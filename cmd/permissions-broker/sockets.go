package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/orbit-online/agent-sandbox/internal/proc"
)

func listen(path string) (*net.UnixListener, error) {
	_ = os.Remove(path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("Listen on %s: %w", path, err)
	}
	return ln, nil
}

// serveOn serves a socket until it's closed. Each socket has its own connection budget, so the sandbox filling
// request.sock leaves control.sock to the window; accept errors (out of fds) are waited out, not fatal
func (b *broker) serveOn(ln *net.UnixListener, handle func(*net.UnixConn, peer, request) response) {
	slots := make(chan struct{}, maxConns)
	backoff := 10 * time.Millisecond
	for {
		conn, err := ln.AcceptUnix()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			slog.Warn("Accept", "err", err)
			time.Sleep(backoff)
			backoff = min(2*backoff, time.Second)
			continue
		}
		backoff = 10 * time.Millisecond
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			defer conn.Close()
			p, err := peerOf(conn)
			if err != nil {
				return
			}
			defer unix.Close(p.pidfd)
			_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
			var req request
			if err := json.NewDecoder(io.LimitReader(conn, maxRequest)).Decode(&req); err != nil {
				_ = json.NewEncoder(conn).Encode(response{Error: "Not a JSON request"})
				return
			}
			_ = conn.SetReadDeadline(time.Time{})
			// A peer gone by now gets nothing. The checks below read its /proc entries by pid and check again after
			// each read, since the pid could be another process's by then
			if p.gone() {
				return
			}
			if req.Op == "watch" {
				b.streamEvents(conn)
				return
			}
			_ = json.NewEncoder(conn).Encode(handle(conn, p, req))
		}()
	}
}

// A client: its pid in our pid namespace and a pidfd for it (SO_PEERPIDFD), which tells whether the pid still names
// that process. What is read from /proc/<pid> counts only if the process is still alive after the read
type peer struct{ pid, pidfd int }

func (p peer) gone() bool { return !proc.Alive(p.pidfd) }

func peerOf(conn *net.UnixConn) (peer, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return peer{}, err
	}
	pidfd := -1
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		pidfd, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	}); err != nil {
		return peer{}, err
	}
	if sockErr != nil {
		return peer{}, sockErr
	}
	pid, err := proc.PidOf(pidfd)
	if err != nil {
		unix.Close(pidfd)
		return peer{}, err
	}
	return peer{pid: pid, pidfd: pidfd}, nil
}

func (b *broker) handleRequest(_ *net.UnixConn, p peer, req request) response {
	var res response
	var err error
	switch req.Op {
	case "list":
		res.Capabilities = b.listCapabilities()
		res.Grants = b.grantViews("")
	case "request":
		var g *grant
		g, res.Credential, err = b.request(p, req)
		res.Grant = b.view(g)
	case "release":
		err = b.release(req.Grant, "released from inside")
	case "status":
		sess, _ := b.sb.sessionOf(p.pid)
		id := ""
		if sess != nil {
			id = sess.id
			unix.Close(sess.pidfd)
		}
		if p.gone() {
			return response{Error: "Gone"}
		}
		res.Grants = b.grantViews(id)
	case "share":
		err = b.shareFrom(p)
	default:
		err = fmt.Errorf("Unknown operation %q", req.Op)
	}
	if err != nil {
		res.Error = err.Error()
	}
	return res
}

// handleControl serves the Permissions window and the launcher, which run on the host: a peer in another user
// namespace (anything in the sandbox, whatever path it reaches the socket by) gets nothing
func (b *broker) handleControl(_ *net.UnixConn, p peer, req request) response {
	if !sameNs(p.pid, "user") || p.gone() {
		return response{Error: "Only from the host"}
	}
	var res response
	var err error
	switch req.Op {
	case "state":
		b.mu.Lock()
		for _, p := range b.pending {
			res.Pending = append(res.Pending, p)
		}
		res.Always = append([]alwaysGrant(nil), b.store.Always...)
		res.Log = append([]logEntry(nil), b.store.Log...)
		b.mu.Unlock()
		res.Grants = b.grantViews("")
		res.Capabilities = b.listCapabilities()
	case "options":
		err = b.markOptions(req.Pending)
	case "answer":
		err = b.answer(req)
	case "revoke":
		res.Holders, err = b.revoke(req.Grant)
	case "end":
		err = b.endHolders(req.Pids)
	case "forget":
		err = b.forget(req.Capability, req.Params)
	default:
		err = fmt.Errorf("Unknown operation %q", req.Op)
	}
	if err != nil {
		res.Error = err.Error()
	}
	return res
}

// shareFrom makes the sandbox's grant directory shared in M1, asked by the FHS env's launcher script in M1 before the
// FHS env's bwrap copies it. Once per sandbox: a later share (udhcpc's, after the FHS env's failed) would come after
// the copy, and type C grants would never reach the app
func (b *broker) shareFrom(p peer) error {
	if b.sb.mnt == nil || !sameFile(b.sb.mnt, fmt.Sprintf("/proc/%d/ns/mnt", p.pid)) || p.gone() {
		return errors.New("Only from the sandbox's outer mount namespace")
	}
	b.mu.Lock()
	if b.shareAsked {
		b.mu.Unlock()
		return errors.New("Asked to share once already")
	}
	b.shareAsked = true
	b.mu.Unlock()
	// Too late once a process of the sandbox is in a copy of M1: what's mounted would never reach it
	if copied, err := b.sb.copied(); err != nil || copied {
		return errors.New("Too late to share: the sandbox's mount namespace was copied already")
	}
	if err := b.sb.share(b.cfg.SandboxGrantDir); err != nil {
		return err
	}
	b.mu.Lock()
	b.shared = true
	b.mu.Unlock()
	go b.replay("C")
	return nil
}

// adoptShared takes over a grant directory an earlier daemon shared, and replays the type C always grants into it
func (b *broker) adoptShared() {
	if !b.sb.isShared(b.cfg.SandboxGrantDir) {
		return
	}
	b.mu.Lock()
	b.shared, b.shareAsked = true, true
	b.mu.Unlock()
	go b.replay("C")
}

// event tells watch streams (the MCP servers, the window) that something changed; they ask for the state
func (b *broker) event(kind, id string) {
	line, _ := json.Marshal(map[string]string{"event": kind, "id": id})
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.watches {
		select {
		case ch <- line:
		default:
		}
	}
}

func (b *broker) streamEvents(conn *net.UnixConn) {
	ch := make(chan []byte, 16)
	b.mu.Lock()
	b.watches[ch] = true
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.watches, ch)
		b.mu.Unlock()
	}()
	closed := make(chan struct{})
	go func() {
		_, _ = bufio.NewReader(conn).ReadByte()
		close(closed)
	}()
	for {
		select {
		case line := <-ch:
			if _, err := conn.Write(append(line, '\n')); err != nil {
				return
			}
		case <-closed:
			return
		}
	}
}
