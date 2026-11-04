package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/control"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
	"golang.org/x/sys/unix"
)

// Listens for clients of one bus and applies one set of rules
type Proxy struct {
	bus    []*net.UnixAddr
	reg    *control.Registry // The rules in force and the clients past authentication
	log    *slog.Logger
	budget *wire.Budget
	uid    int // The uid a client and the broker must have

	mu      sync.Mutex
	clients int
}

// Clients connected at once; the app opens a handful
const maxClients = 256

func NewProxy(address string, rules *rules.Rules) (*Proxy, error) {
	addrs, err := parseAddress(address)
	if err != nil {
		return nil, err
	}
	return &Proxy{bus: addrs, reg: control.NewRegistry(rules), log: slog.Default(), budget: wire.NewBudget(),
		uid: os.Getuid()}, nil
}

// The control socket's server, for live sets checked against bus's policy and the sandbox's app ID
func (p *Proxy) control(bus, appID string) *control.Server {
	return &control.Server{Registry: p.reg, Bus: bus, AppID: appID, UID: p.uid, Log: p.log}
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

// Listens on the control socket at rel beneath $XDG_RUNTIME_DIR, as nixpak passes dbus.args unexpanded: a clean
// relative path, its directory made 0700 and the socket bound under umask 077, then made 0600, the mode the doc names
func listenControl(rel string) (*net.UnixListener, error) {
	run := os.Getenv("XDG_RUNTIME_DIR")
	if !filepath.IsAbs(run) {
		return nil, errors.New("--control needs $XDG_RUNTIME_DIR")
	}
	if rel == "" || filepath.IsAbs(rel) || filepath.Clean(rel) != rel || strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("--control %q: a clean path relative to $XDG_RUNTIME_DIR", rel)
	}
	path := filepath.Join(run, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	old := unix.Umask(0o077)
	l, err := listen(path)
	unix.Umask(old)
	if err != nil {
		return nil, err
	}
	// Bound 0700; connecting takes write permission only
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}
