// Package control is the control socket the permissions broker adds and removes live rule sets on (--control), and
// the registry of the rules in force and the connections they apply to
package control

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"golang.org/x/sys/unix"
)

// The control socket (--control): the permissions broker adds and removes live rule sets, one per D-Bus grant, by the
// grant's id. One JSON object a line each way, a request then its answer:
//
//	{"op":"add","id":"<grant>","see":[NAME],"talk":[NAME],"own":[NAME],"call":["NAME=RULE"],"broadcast":["NAME=RULE"]}
//	{"op":"remove","id":"<grant>"}
//	{"ok":true,"closed":<connections ended>} or {"error":"..."}
//
// A set applies from the next message the proxy reads; a removal ends the connections that used the set. One broker
// at a time: when its connection closes, every live set goes as by a removal

const (
	MaxLine = 64 << 10
	MaxSets = 32
)

var setID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type request struct {
	Op        string   `json:"op"`
	ID        string   `json:"id"`
	See       []string `json:"see"`
	Talk      []string `json:"talk"`
	Own       []string `json:"own"`
	Call      []string `json:"call"`
	Broadcast []string `json:"broadcast"`
}

type Response struct {
	OK     bool   `json:"ok,omitempty"`
	Closed int    `json:"closed,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Server serves the control socket
type Server struct {
	Registry *Registry
	// The bus and the sandbox's app ID, which live sets are checked against (rules.ParseLive)
	Bus, AppID string
	// The uid the broker must have
	UID int
	Log *slog.Logger
}

// The live sets by id, which only the connected broker changes
type control struct {
	*Server
	mu   sync.Mutex
	busy bool
	sets map[string]*rules.Set
}

// Serve serves the control socket until it's closed
func (s *Server) Serve(l *net.UnixListener) error {
	ctl := &control{Server: s, sets: map[string]*rules.Set{}}
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.Log.Warn("Control accept failed", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if err := s.controlPeer(conn); err != nil {
			s.Log.Warn("Control peer refused", "err", err)
			conn.Close()
			continue
		}
		ctl.mu.Lock()
		busy := ctl.busy
		ctl.busy = true
		ctl.mu.Unlock()
		if busy {
			s.Log.Warn("Control peer refused: the broker is connected already")
			conn.Close()
			continue
		}
		go ctl.serve(conn)
	}
}

// The broker: a peer of the proxy's uid, on a socket only the host reaches. The socket is in a 0700 directory under
// $XDG_RUNTIME_DIR/claude-desktop, which nothing binds into the sandbox (the module refuses binds and host sockets
// there), so a peer is a host process of the user's, which reaches the bus without the proxy anyway. The proxy can't
// tell the sandbox's processes apart by more: they have the user's uid, and the kernel refuses a process in a user
// namespace of its own (nixpak's wrapper and the system-bus bwrap make one) the peer's namespaces from its pidfd
// (PIDFD_GET_*_NAMESPACE need ptrace access, which commoncap refuses across user namespaces), and it has no /proc.
// One connection at a time on top: a second while the broker is connected is closed
func (s *Server) controlPeer(conn *net.UnixConn) error {
	uid, err := PeerUID(conn)
	if err != nil {
		return err
	}
	if uid != s.UID {
		return fmt.Errorf("Peer uid %d is not the proxy's %d", uid, s.UID)
	}
	return nil
}

// PeerUID is the uid of the process at the other end of conn, from SO_PEERCRED
func PeerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	return int(cred.Uid), nil
}

// Answers the broker's requests until its connection ends, then drops every live set
func (ctl *control) serve(conn *net.UnixConn) {
	defer func() {
		conn.Close()
		ctl.mu.Lock()
		defer ctl.mu.Unlock()
		for id, rs := range ctl.sets {
			n := ctl.Registry.Remove(rs)
			ctl.Log.Info("Live rule set dropped with the broker's connection", "id", id, "closed", n)
		}
		clear(ctl.sets)
		ctl.busy = false
	}()
	r := bufio.NewReaderSize(conn, MaxLine)
	enc := json.NewEncoder(conn)
	for {
		line, err := r.ReadSlice('\n')
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				_ = enc.Encode(Response{Error: "Request too long"})
			}
			return
		}
		var req request
		var res Response
		if err := json.Unmarshal(line, &req); err != nil {
			res.Error = "Not a JSON request"
		} else if res.Closed, err = ctl.do(req); err != nil {
			res.Error = err.Error()
		} else {
			res.OK = true
		}
		if err := enc.Encode(res); err != nil {
			return
		}
	}
}

func (ctl *control) do(req request) (int, error) {
	ctl.mu.Lock()
	defer ctl.mu.Unlock()
	if !setID.MatchString(req.ID) {
		return 0, errors.New("An id of 1 to 64 letters, digits, _ and -")
	}
	switch req.Op {
	case "add":
		if ctl.sets[req.ID] != nil {
			return 0, fmt.Errorf("Rule set %s is there already", req.ID)
		}
		if len(ctl.sets) >= MaxSets {
			return 0, fmt.Errorf("%d live rule sets at most", MaxSets)
		}
		rs, err := rules.ParseLive(req.ID, rules.Args{See: req.See, Talk: req.Talk, Own: req.Own, Call: req.Call,
			Broadcast: req.Broadcast}, ctl.Bus, ctl.AppID)
		if err != nil {
			return 0, err
		}
		ctl.sets[req.ID] = rs
		ctl.Registry.Add(rs)
		ctl.Log.Info("Live rule set added", "id", req.ID)
		return 0, nil
	case "remove":
		rs := ctl.sets[req.ID]
		if rs == nil {
			return 0, fmt.Errorf("No rule set %s", req.ID)
		}
		delete(ctl.sets, req.ID)
		n := ctl.Registry.Remove(rs)
		ctl.Log.Info("Live rule set removed", "id", req.ID, "closed", n)
		return n, nil
	}
	return 0, fmt.Errorf("Unknown op %q", req.Op)
}
