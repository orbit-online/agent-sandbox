package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Guards of host sockets that the end-to-end tests don't reach

// A revoke while splice connects to the host: the host's end is closed whole once it connects, not left half-open
// with nothing to end it
func TestRevokeWhileDialing(t *testing.T) {
	b, _ := testBroker(t, "allow")
	dir := t.TempDir()
	ln, err := listenIn(dir, "host.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c := &capability{Name: "agent", Type: "socket", Description: "an agent", Path: filepath.Join(dir, "host.sock")}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	b.caps[c.id()] = c
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	dialing, revoked := make(chan struct{}), make(chan struct{})
	beforeDial = func() { close(dialing); <-revoked }
	t.Cleanup(func() { beforeDial = func() {} })
	client, err := dialPath(filepath.Join(b.cfg.GrantDir, socketsDir, "agent"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	<-dialing
	if _, err := b.revoke(g.ID); err != nil {
		t.Fatal(err)
	}
	close(revoked)
	up, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	if !hungUp(up, 3*time.Second) {
		t.Error("The host's end stayed open after a revoke during the dial")
	}
}

// hungUp reports whether conn's peer closed it whole within d: POLLHUP, which a shutdown of its writing alone doesn't
// raise
func hungUp(conn *net.UnixConn, d time.Duration) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	hup := false
	_ = raw.Control(func(fd uintptr) {
		for deadline := time.Now().Add(d); !hup && time.Now().Before(deadline); {
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if n, _ := unix.Poll(fds, 100); n > 0 {
				hup = fds[0].Revents&unix.POLLHUP != 0
				if !hup {
					time.Sleep(50 * time.Millisecond)
				}
			}
		}
	})
	return hup
}

// A grant of a host socket whose address the broker can't listen at is refused, not handed out without an address
func TestGrantWithoutAddress(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testSocket(t, b, "a")
	if err := os.MkdirAll(b.cfg.GrantDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// sockets/ a file: nothing can be made beneath it
	if err := os.WriteFile(filepath.Join(b.cfg.GrantDir, socketsDir), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"vm": "a"}`, "PT1H")); err == nil {
		t.Errorf("Granted without an address: %+v", g)
	}
}

// The broker makes an address only in a directory of its own, not through a link put where the directory goes
func TestListenNoFollow(t *testing.T) {
	dir, elsewhere := t.TempDir(), t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(dir, socketsDir)); err != nil {
		t.Fatal(err)
	}
	if ln, err := listenIn(dir, filepath.Join(socketsDir, "agent")); err == nil {
		ln.Close()
		t.Error("Listened through a link")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Errorf("Made %v where the link leads", entries)
	}
}

// An address a daemon before left behind, a socket nobody listens at, is taken over
func TestListenStale(t *testing.T) {
	dir := t.TempDir()
	old, err := listenIn(dir, filepath.Join(socketsDir, "agent"))
	if err != nil {
		t.Fatal(err)
	}
	old.Close()
	ln, err := listenIn(dir, filepath.Join(socketsDir, "agent"))
	if err != nil {
		t.Fatalf("A stale address: %v", err)
	}
	ln.Close()
}

// The daemon stops listening at the host sockets' addresses when the sandbox ends: nothing connects there after
func TestRunClosesSockets(t *testing.T) {
	b, stdin, _ := sandboxC(t)
	dir := t.TempDir()
	e := startEcho(t, dir, "agent.sock")
	t.Cleanup(e.stop)
	b.cfg.Sockets = []socketConfig{{Name: "agent", Description: "an agent", Path: e.path}}
	if err := loadSockets(b.cfg.Sockets, b.caps); err != nil {
		t.Fatal(err)
	}
	b.cfg.ControlSocket = filepath.Join(t.TempDir(), "control.sock")
	ran := make(chan error, 1)
	go func() { ran <- b.run() }()
	addr := filepath.Join(b.cfg.GrantDir, socketsDir, "agent")
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if conn, err := dialPath(addr, time.Second); err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Never listened")
		}
	}
	stdin.Close()
	select {
	case err := <-ran:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run didn't end with the sandbox")
	}
	if conn, err := dialPath(addr, time.Second); err == nil {
		conn.Close()
		t.Error("Still listening after the daemon ended")
	}
}
