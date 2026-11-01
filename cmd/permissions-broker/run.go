package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func newBroker(cfg config, caps map[string]*capability, sb *sandbox, ask asker) (*broker, error) {
	return &broker{cfg: cfg, caps: caps, sb: sb, ask: ask, grants: map[string]*grant{}, pending: map[string]*pending{},
		gates: map[string]*gate{}, watches: map[chan []byte]bool{}, clock: realClock{}}, nil
}

// run starts the daemon and serves until the sandbox ends
func (b *broker) run() error {
	reqLn, ctlLn, err := b.start()
	if err != nil {
		return err
	}
	go b.serveOn(reqLn, b.handleRequest)
	go b.serveOn(ctlLn, b.handleControl)
	slog.Info("Serving", "launcher", b.cfg.Launcher, "sandbox", b.sb.pid)
	fds := []unix.PollFd{{Fd: int32(b.sb.pidfd), Events: unix.POLLIN}}
	for {
		if _, err := unix.Poll(fds, -1); err == nil || !errors.Is(err, unix.EINTR) {
			break
		}
	}
	slog.Info("Sandbox ended")
	b.endAll("the sandbox ended")
	reqLn.Close()
	ctlLn.Close()
	return nil
}

// start reconciles what a previous daemon left and listens on both sockets
func (b *broker) start() (reqLn, ctlLn *net.UnixListener, err error) {
	// What an earlier daemon left, if its ExecStopPost didn't get to it
	cleanup(b.cfg, b.sb)
	if err := os.MkdirAll(b.cfg.GrantDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("Create the grant directory: %w", err)
	}
	// claude-desktop.sh creates it; nothing in the sandbox can write there (it's bound read-only), but it must be
	// ours and a directory, not a link to elsewhere
	if fi, err := os.Lstat(b.cfg.GrantDir); err != nil || !fi.IsDir() || fi.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return nil, nil, fmt.Errorf("The grant directory %s isn't a directory of ours", b.cfg.GrantDir)
	}
	if reqLn, err = listen(filepath.Join(b.cfg.GrantDir, "request.sock")); err != nil {
		return nil, nil, err
	}
	if ctlLn, err = listen(b.cfg.ControlSocket); err != nil {
		reqLn.Close()
		return nil, nil, err
	}
	b.adoptShared()
	return reqLn, ctlLn, nil
}
