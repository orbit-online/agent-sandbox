package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
	"golang.org/x/sys/unix"
)

// Listens for clients of one bus and applies one set of rules
type Proxy struct {
	bus      []*net.UnixAddr
	rules    *rules.Rules
	log      *slog.Logger
	refusals *refusals
	budget   *wire.Budget
	uid      int // The uid a client must have

	mu      sync.Mutex
	clients int
}

// Clients connected at once; the app opens a handful
const maxClients = 256

func NewProxy(address string, r *rules.Rules) (*Proxy, error) {
	addrs, err := parseAddress(address)
	if err != nil {
		return nil, err
	}
	log := slog.Default()
	return &Proxy{bus: addrs, rules: r, log: log, refusals: newRefusals(log), budget: wire.NewBudget(),
		uid: os.Getuid()}, nil
}

// Accepts clients until the listener closes. Out of file descriptors or memory, it waits and tries again, as
// net/http does: clients ending free them
func (p *Proxy) Serve(l *net.UnixListener) error {
	var backoff time.Duration
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if errors.Is(err, unix.EMFILE) || errors.Is(err, unix.ENFILE) || errors.Is(err, unix.ENOBUFS) ||
				errors.Is(err, unix.ENOMEM) || errors.Is(err, unix.ECONNABORTED) {
				backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
				p.log.Warn("Accept failed, trying again", "err", err, "in", backoff)
				time.Sleep(backoff)
				continue
			}
			return err
		}
		backoff = 0
		p.mu.Lock()
		full := p.clients >= maxClients
		if !full {
			p.clients++
		}
		p.mu.Unlock()
		if full {
			p.log.Warn("Client refused: too many clients")
			conn.Close()
			continue
		}
		go func() {
			defer func() {
				p.mu.Lock()
				p.clients--
				p.mu.Unlock()
			}()
			p.handle(conn)
		}()
	}
}

// Listens at path, replacing what's there, as xdg-dbus-proxy does
func listen(path string) (*net.UnixListener, error) {
	os.Remove(path)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("Listen on %s: %w", path, err)
	}
	l.SetUnlinkOnClose(true)
	return l, nil
}

// The uid of the process at the other end of conn, from SO_PEERCRED
func peerUID(conn *net.UnixConn) (int, error) {
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
