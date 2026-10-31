package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func newBroker(cfg config, caps map[string]*capability, sb *sandbox, ask asker) (*broker, error) {
	b := &broker{cfg: cfg, caps: caps, sb: sb, ask: ask, grants: map[string]*grant{}, pending: map[string]*pending{},
		gates: map[string]*gate{}, watches: map[chan []byte]bool{}}
	data, err := os.ReadFile(cfg.Store)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("Read the grant store: %w", err)
	default:
		// A broken store mustn't keep the daemon from starting: it's set aside, and always grants are asked again
		if err := json.Unmarshal(data, &b.store); err != nil {
			slog.Warn("Broken grant store, set aside", "store", cfg.Store, "err", err)
			b.store = storeData{}
			_ = os.Rename(cfg.Store, cfg.Store+".broken")
		}
	}
	return b, nil
}

// run reconciles what a previous daemon left, listens on both sockets, replays the always grants, and serves until
// the sandbox ends
func (b *broker) run() error {
	// What an earlier daemon left, if its ExecStopPost didn't get to it
	cleanup(b.cfg, b.sb)
	if err := os.MkdirAll(b.cfg.GrantDir, 0o700); err != nil {
		return fmt.Errorf("Create the grant directory: %w", err)
	}
	// claude-desktop.sh creates it; nothing in the sandbox can write there (it's bound read-only), but it must be
	// ours and a directory, not a link to elsewhere
	if fi, err := os.Lstat(b.cfg.GrantDir); err != nil || !fi.IsDir() || fi.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return fmt.Errorf("The grant directory %s isn't a directory of ours", b.cfg.GrantDir)
	}
	reqLn, err := listen(filepath.Join(b.cfg.GrantDir, "request.sock"))
	if err != nil {
		return err
	}
	ctlLn, err := listen(b.cfg.ControlSocket)
	if err != nil {
		return err
	}
	b.replay("A")
	b.adoptShared()
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
