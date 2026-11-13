package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mounts"
	"golang.org/x/sys/unix"
)

// The attach type: binding host paths into the running sandbox and detaching them, as scripts/ns-inject-spike.py
// verified. The daemon checks the source against the ceiling, creates the mountpoint in the grant directory on the
// host, and runs helpers of its own binary through nsenter for what a multithreaded Go process can't do (enter a user
// namespace), each exec'd on the host's mounts (see internal/mounts/helpers.go):
//   clone-tree, in the owner of the sandbox's mount namespace, unshares a mount namespace of its own, opens the
//     source beneath its ceiling root without following any link or crossing a mount, clones it (open_tree,
//     without its submounts) and passes the tree's fd back;
//   move-tree joins the sandbox's mount namespace and attaches that tree at the mountpoint (move_mount);
//   detach joins it and unmounts mountpoints there.
// The daemon acts with the host user's rights, the sandbox doesn't: a link it plants in its rw binds, which may lie
// under a ceiling root, can point at what only the daemon can read. Hence no links followed at all. The denied
// directories are a check on the path (checkSource), which then holds for what's opened; a ceiling root on a host
// mount that aliases a denied directory is the user's own configuration.

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

// An attach request's source, checked against the ceiling
type attachSource struct {
	root, rel string
	ro        bool
}

func (s attachSource) path() string { return filepath.Join(s.root, s.rel) }

// resolveAttach checks the folder a request names against the ceiling
func (b *broker) resolveAttach(c *capability, params json.RawMessage) (attachSource, error) {
	path, ro := folderOf(params)
	root, rel, err := mounts.CheckSource(c.Sources, b.cfg.Denied, path, ro)
	if err != nil {
		return attachSource{}, err
	}
	return attachSource{root: root, rel: rel, ro: ro}, nil
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
	tree, source, err := mounts.Attach(b.sb, src.root, src.rel, src.ro, dir, g.ID)
	if err != nil {
		removeMountpoint(b.cfg.GrantDir, g.ID)
		return err
	}
	g.Source = source
	// Without it, neither the grant's mounts nor copies of them are found as holders: no grant then
	if g.mnt, err = mounts.GrantMountOf(b.sb, tree); err != nil {
		tree.Close()
		if err := mounts.Detach(b.sb, dir, g.ID); err != nil {
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
	defer g.mnt.Close()
	if !b.sb.alive() {
		// Its mounts went with the sandbox
		removeMountpoint(b.cfg.GrantDir, g.ID)
		return
	}
	dir, err := grantDirOf(b.cfg)
	if err == nil {
		err = mounts.Detach(b.sb, dir, g.ID)
	}
	if err != nil {
		slog.Warn("Detach", "grant", g.ID, "err", err)
	}
	removeMountpoint(b.cfg.GrantDir, g.ID)
	g.Holders = mounts.HoldersAfter(b.sb, g.mnt)
	if len(g.Holders) > 0 {
		slog.Info("Still held", "grant", g.ID, "holders", g.Holders)
	}
}

// cleanup ends the grants a daemon leaves when it stops, a crash included (the unit's ExecStopPost runs it, and a
// daemon starting runs it too): its call units stopped, its locks removed, its folder grants detached in the sandbox
// if it got as far as sharing the grant directory, their mountpoints removed, its host sockets, and last its ports,
// which it tries until they're off. sb is nil when the sandbox wasn't found: its mounts went with it, and its ports
// are revoked all the same
func cleanup(cfg config, sb *sandbox, clk clock) {
	stopAllCalls(cfg.Launcher)
	removeLocks(cfg.Launcher)
	// Removing the mountpoints below ends their mounts in every namespace as well; this is in case that fails
	if dir, err := grantDirOf(cfg); err == nil && sb != nil && mounts.IsShared(sb, cfg.SandboxGrantDir) {
		if err := mounts.DetachBelow(sb, dir); err != nil {
			slog.Warn("Detach leftover grants", "err", err)
		}
	}
	_ = os.RemoveAll(filepath.Join(cfg.GrantDir, socketsDir))
	entries, _ := os.ReadDir(cfg.GrantDir)
	for _, e := range entries {
		if e.Name() != "request.sock" {
			removeMountpoint(cfg.GrantDir, e.Name())
		}
	}
	revokePorts(cfg, sb, clk)
}

// attachKind is the kind of folder capabilities: a grant mounts the folder in the sandbox's grant directory, its end
// detaches it and records what still held it
type attachKind struct{ baseKind }

func (attachKind) usable(b *broker) error {
	b.mu.Lock()
	shared := b.shared
	b.mu.Unlock()
	if !shared {
		return errors.New("Folder and device grants need the sandbox's grant directory shared, which " +
			"failed when it started: restart the app")
	}
	return nil
}

// describe checks the folder against the ceiling before asking: what's outside is refused without bothering the user.
// What's mounted is what's at the path then, checked again
func (attachKind) describe(b *broker, c *capability, params json.RawMessage) (string, error) {
	src, err := b.resolveAttach(c, params)
	if err != nil {
		return "", err
	}
	return describeAttach(c.describe(params), src), nil
}

func (attachKind) live(b *broker, g *grant) error { return b.attachGrant(g) }

func (attachKind) end(b *broker, g *grant, why string) {
	b.detachGrant(g)
	b.recordHeld(g, why)
}

// grantDirOf is the config's grant directory, as the helpers check it in the sandbox
func grantDirOf(cfg config) (mounts.GrantDir, error) {
	return mounts.GrantDirOf(cfg.GrantDir, cfg.SandboxGrantDir)
}
