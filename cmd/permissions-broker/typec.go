package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Type C: binding host paths into the running sandbox and detaching them, as scripts/ns-inject-spike.py verified.
// The daemon checks the source against the ceiling, creates the mountpoint in the grant directory on the host, and
// runs helpers of its own binary through nsenter for what a multithreaded Go process can't do (enter a user
// namespace):
//   clone-tree, in the owner of the sandbox's mount namespace, unshares a mount namespace of its own, opens the
//     source beneath its ceiling root without following any link, checks it against the denied directories by
//     identity, clones it (open_tree, without its submounts) and passes the tree's fd back;
//   move-tree, in the sandbox's mount namespace, attaches that tree at the mountpoint (move_mount);
//   detach unmounts mount points there.
// The sandbox can't write the grant directory, but it can plant links and rename directories in its rw binds, which
// may lie under a ceiling root: hence no links followed at all, and identities rather than paths for what's denied.

// resolved is what a type C plugin's resolve command prints
type resolved struct {
	Source string `json:"source"`
	RO     bool   `json:"ro"`
}

// makeMountpoint creates a grant's mountpoint in the grant directory on the host, through a dirfd that doesn't
// follow links: a directory for a directory, an empty file for anything else
func makeMountpoint(grantDir, name string, dir bool) error {
	dfd, err := unix.Open(grantDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("Open the grant directory: %w", err)
	}
	defer unix.Close(dfd)
	if dir {
		return unix.Mkdirat(dfd, name, 0o700)
	}
	fd, err := unix.Openat(dfd, name, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

// removeMountpoint removes a mountpoint makeMountpoint made
func removeMountpoint(grantDir, name string) {
	dfd, err := unix.Open(grantDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer unix.Close(dfd)
	if unix.Unlinkat(dfd, name, unix.AT_REMOVEDIR) != nil {
		_ = unix.Unlinkat(dfd, name, 0)
	}
}

// isDir reports whether path is a directory, following links: what clone-tree will resolve it to beneath its root
// may still differ, which only makes the mount fail
func isDir(path string) bool {
	var st unix.Stat_t
	return unix.Stat(path, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR
}

// A type C request's source, resolved by its plugin and checked against its ceiling
type sourceC struct {
	root, rel string
	ro        bool
}

func (s sourceC) path() string { return filepath.Join(s.root, s.rel) }

// resolveC runs a type C plugin's resolve command and checks what it names against the ceiling
func (b *broker) resolveC(c *capability, params json.RawMessage) (sourceC, error) {
	in, _ := json.Marshal(pluginInput{Params: params, Ceiling: c.Ceiling.Raw})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Resolve[0], c.Resolve[1:]...)
	cmd.Stdin = bytes.NewReader(in)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := runPlugin(cmd); err != nil {
		return sourceC{}, fmt.Errorf("%s couldn't resolve: %s", c.id(), strings.TrimSpace(errOut.String()))
	}
	var r resolved
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		return sourceC{}, fmt.Errorf("%s resolved to something other than JSON: %w", c.id(), err)
	}
	var ceil ceilingC
	if len(c.Ceiling.Raw) > 0 {
		if err := json.Unmarshal(c.Ceiling.Raw, &ceil); err != nil {
			return sourceC{}, fmt.Errorf("The ceiling of %s: %w", c.id(), err)
		}
	}
	root, rel, err := checkSource(ceil, b.cfg.Denied, r.Source, r.RO)
	if err != nil {
		return sourceC{}, err
	}
	return sourceC{root: root, rel: rel, ro: r.RO}, nil
}

// describeC adds what a type C grant attaches to its summary, as the daemon checked it
func describeC(summary string, src sourceC) string {
	access := "read-write"
	if src.ro {
		access = "read-only"
	}
	return fmt.Sprintf("%s: %q, %s", summary, src.path(), access)
}

// mountC attaches a type C grant at its mountpoint in the sandbox
func (b *broker) mountC(g *grant) error {
	src, err := b.resolveC(g.cap, g.Params)
	if err != nil {
		return err
	}
	if err := makeMountpoint(b.cfg.GrantDir, g.ID, isDir(src.path())); err != nil {
		return fmt.Errorf("Create the mountpoint: %w", err)
	}
	g.Path = filepath.Join(b.cfg.SandboxGrantDir, g.ID)
	if g.Source, err = b.sb.attach(src.root, src.rel, src.ro, g.shown, b.cfg.Denied, g.Path); err != nil {
		removeMountpoint(b.cfg.GrantDir, g.ID)
		return err
	}
	// Without them, a copy of the mount in a nested namespace isn't found as a holder; the grant stands
	if lines, err := b.sb.mountinfo(); err == nil {
		g.dev, g.root = mountOf(lines, g.Path)
	}
	return nil
}

// unmountC detaches a type C grant and removes its mountpoint, which ends its mounts in every namespace it
// propagated to, then lists what still holds it. Its mount ids are taken first, while its mount points resolve
func (b *broker) unmountC(g *grant) {
	if !b.sb.alive() {
		// Its mounts went with the sandbox
		removeMountpoint(b.cfg.GrantDir, g.ID)
		return
	}
	ids := b.sb.grantMounts(g.Path)
	if err := b.sb.detach(g.Path); err != nil {
		slog.Warn("Detach", "grant", g.ID, "err", err)
	}
	removeMountpoint(b.cfg.GrantDir, g.ID)
	g.Holders = b.sb.holdersAfter(ids, g.dev, g.root)
	if len(g.Holders) > 0 {
		slog.Info("Still held", "grant", g.ID, "holders", g.Holders)
	}
}

// cleanup ends the grants a daemon leaves when it stops, a crash included (the unit's ExecStopPost runs it, and a
// daemon starting runs it too): its type A units stopped, its locks removed, its folder grants detached in the sandbox
// if it got as far as sharing the grant directory, and their mountpoints removed. sb is nil when the sandbox is gone,
// and with it their mounts
func cleanup(cfg config, sb *sandbox) {
	stopAllServes(cfg.Launcher)
	removeLocks(cfg.Launcher)
	// Removing the mountpoints below ends their mounts in every namespace as well; this is in case that fails
	if sb != nil && sb.isShared(cfg.SandboxGrantDir) {
		if err := sb.detachBelow(cfg.SandboxGrantDir); err != nil {
			slog.Warn("Detach leftover grants", "err", err)
		}
	}
	entries, _ := os.ReadDir(cfg.GrantDir)
	for _, e := range entries {
		if e.Name() != "request.sock" {
			removeMountpoint(cfg.GrantDir, e.Name())
		}
	}
}
