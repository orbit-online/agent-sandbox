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

// The attach type: binding host paths into the running sandbox and detaching them, as scripts/ns-inject-spike.py
// verified. The daemon checks the source against the ceiling, creates the mountpoint in the grant directory on the
// host, and runs helpers of its own binary through nsenter for what a multithreaded Go process can't do (enter a user
// namespace), each exec'd on the host's mounts (see helpers.go):
//   clone-tree, in the owner of the sandbox's mount namespace, unshares a mount namespace of its own, opens the
//     source beneath its ceiling root without following any link, checks it against the denied directories by
//     identity, clones it (open_tree, without its submounts) and passes the tree's fd back;
//   move-tree joins the sandbox's mount namespace and attaches that tree at the mountpoint (move_mount);
//   detach joins it and unmounts mountpoints there.
// The sandbox can't write the grant directory, but it can plant links in its rw binds, which may lie under a ceiling
// root, and a link can point anywhere: hence no links followed at all. The host has other paths to a directory too
// (bind mounts, its own links): hence identities rather than paths for what's denied.

// resolved is what an attach plugin's resolve command prints
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

// An attach request's source, resolved by its plugin and checked against its ceiling
type attachSource struct {
	root, rel string
	ro        bool
}

func (s attachSource) path() string { return filepath.Join(s.root, s.rel) }

// resolveAttach runs an attach plugin's resolve command and checks what it names against the ceiling
func (b *broker) resolveAttach(c *capability, params json.RawMessage) (attachSource, error) {
	in, _ := json.Marshal(pluginInput{Params: params, Ceiling: c.Ceiling.Raw})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Resolve[0], c.Resolve[1:]...)
	cmd.Stdin = bytes.NewReader(in)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := c.runPlugin(cmd); err != nil {
		return attachSource{}, fmt.Errorf("%s couldn't resolve: %s", c.id(), strings.TrimSpace(errOut.String()))
	}
	var r resolved
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		return attachSource{}, fmt.Errorf("%s resolved to something other than JSON: %w", c.id(), err)
	}
	var ceil attachCeiling
	if len(c.Ceiling.Raw) > 0 {
		if err := json.Unmarshal(c.Ceiling.Raw, &ceil); err != nil {
			return attachSource{}, fmt.Errorf("The ceiling of %s: %w", c.id(), err)
		}
	}
	root, rel, err := checkSource(ceil, b.cfg.Denied, r.Source, r.RO)
	if err != nil {
		return attachSource{}, err
	}
	return attachSource{root: root, rel: rel, ro: r.RO}, nil
}

// describeAttach adds what an attach grant attaches to its summary, as the daemon checked it
func describeAttach(summary string, src attachSource) string {
	access := "read-write"
	if src.ro {
		access = "read-only"
	}
	return fmt.Sprintf("%s: %q, %s", summary, src.path(), access)
}

// attachGrant attaches an attach grant at its mountpoint in the sandbox
func (b *broker) attachGrant(g *grant) error {
	src, err := b.resolveAttach(g.cap, g.Params)
	if err != nil {
		return err
	}
	if err := makeMountpoint(b.cfg.GrantDir, g.ID, isDir(src.path())); err != nil {
		return fmt.Errorf("Create the mountpoint: %w", err)
	}
	dir, err := grantDirOf(b.cfg)
	if err != nil {
		removeMountpoint(b.cfg.GrantDir, g.ID)
		return err
	}
	g.Path = filepath.Join(b.cfg.SandboxGrantDir, g.ID)
	tree, source, err := b.sb.attach(src.root, src.rel, src.ro, b.cfg.Denied, dir, g.ID)
	if err != nil {
		removeMountpoint(b.cfg.GrantDir, g.ID)
		return err
	}
	g.Source = source
	// Without it, neither the grant's mounts nor copies of them are found as holders: no grant then
	if g.mnt, err = b.sb.grantMountOf(tree); err != nil {
		tree.Close()
		if err := b.sb.detach(dir, g.ID); err != nil {
			slog.Warn("Detach", "grant", g.ID, "err", err)
		}
		removeMountpoint(b.cfg.GrantDir, g.ID)
		return err
	}
	return nil
}

// detachGrant detaches an attach grant and removes its mountpoint, which ends its mounts in every namespace it
// propagated to, then lists what still holds it. Nothing comes before the detach: the scan's cost is the sandbox's to
// choose (its processes, namespaces and mounts), so it mustn't hold the detach up
func (b *broker) detachGrant(g *grant) {
	if g.mnt == nil {
		// Never attached
		return
	}
	defer g.mnt.tree.Close()
	if !b.sb.alive() {
		// Its mounts went with the sandbox
		removeMountpoint(b.cfg.GrantDir, g.ID)
		return
	}
	dir, err := grantDirOf(b.cfg)
	if err == nil {
		err = b.sb.detach(dir, g.ID)
	}
	if err != nil {
		slog.Warn("Detach", "grant", g.ID, "err", err)
	}
	removeMountpoint(b.cfg.GrantDir, g.ID)
	g.Holders = b.sb.holdersAfter(g.mnt)
	if len(g.Holders) > 0 {
		slog.Info("Still held", "grant", g.ID, "holders", g.Holders)
	}
}

// cleanup ends the grants a daemon leaves when it stops, a crash included (the unit's ExecStopPost runs it, and a
// daemon starting runs it too): its service units stopped, its locks removed, its folder grants detached in the sandbox
// if it got as far as sharing the grant directory, and their mountpoints removed. sb is nil when the sandbox is gone,
// and with it their mounts
func cleanup(cfg config, sb *sandbox) {
	stopAllServes(cfg.Launcher)
	removeLocks(cfg.Launcher)
	// Removing the mountpoints below ends their mounts in every namespace as well; this is in case that fails
	if dir, err := grantDirOf(cfg); err == nil && sb != nil && sb.isShared(cfg.SandboxGrantDir) {
		if err := sb.detachBelow(dir); err != nil {
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
