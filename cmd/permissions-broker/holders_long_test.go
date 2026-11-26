package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mounts"
	"golang.org/x/sys/unix"
)

// Lines of /proc/<pid>/mountinfo and maps past a megabyte: a path may be any length (a process walks into it,
// relative to its working directory), so the sandbox picks how long the line of a mount or a mapping of its is

// goDeep mounts a tmpfs at at, in the calling thread's own mount namespace, and walks 4200 directories of 255
// characters into it: a path of more than a megabyte, where the thread's working directory then is
func goDeep(at string) error {
	if err := unix.Mount("tmpfs", at, "tmpfs", 0, ""); err != nil {
		return err
	}
	if err := unix.Mkdir(filepath.Join(at, "bind"), 0o700); err != nil {
		return err
	}
	if err := unix.Chdir(at); err != nil {
		return err
	}
	name := strings.Repeat("d", 255)
	for range 4200 {
		if err := unix.Mkdir(name, 0o700); err != nil {
			return err
		}
		if err := unix.Chdir(name); err != nil {
			return err
		}
	}
	return nil
}

// holdBindLong is threadHoldMain's bindlong: a bind of path in a mount namespace of the thread's own, made after a
// mount whose line in mountinfo is past a megabyte, so listed after it
func holdBindLong(path, at string) error {
	if err := unix.Unshare(unix.CLONE_FS | unix.CLONE_NEWNS); err != nil {
		return err
	}
	if err := goDeep(at); err != nil {
		return err
	}
	if err := unix.Mount(".", ".", "", unix.MS_BIND, ""); err != nil {
		return err
	}
	return unix.Mount(path, filepath.Join(at, "bind"), "", unix.MS_BIND, "")
}

// holdMapLong is threadHoldMain's maplong: a shared mapping of path with its fd closed, between two mappings of a
// file whose path is past a megabyte, one of which maps lists ahead of it whichever way the addresses go
func holdMapLong(path, at string) error {
	if err := unix.Unshare(unix.CLONE_FS | unix.CLONE_NEWNS); err != nil {
		return err
	}
	if err := goDeep(at); err != nil {
		return err
	}
	if err := os.WriteFile("f", []byte("x"), 0o600); err != nil {
		return err
	}
	for _, p := range []string{"f", path, "f"} {
		fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		_, err = unix.Mmap(fd, 0, 1, unix.PROT_READ, unix.MAP_SHARED)
		unix.Close(fd)
		if err != nil {
			return err
		}
	}
	return nil
}

// P5: a re-bind of the grant in a mount namespace whose mountinfo has a line past a megabyte ahead of it makes its
// process a holder; the scan read up to that line and no further
func TestHoldersLongMountLine(t *testing.T) {
	src := t.TempDir()
	b, stdin, out := sandboxC(t, "allow")
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	pid := threadHold(t, stdin, out, g.Path, g.Path, "bindlong")
	holders, err := b.revoke(g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(holders, func(h mounts.Holder) bool { return h.Pid == pid && !h.Possible }) {
		t.Errorf("%d, with a re-bind of the grant listed after a long line, isn't among the holders %+v", pid, holders)
	}
}

// P5: a mapping of one of the grant's files that maps lists after a line past a megabyte makes its process a holder
func TestHoldersLongMapsLine(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "file"), []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, stdin, out := sandboxC(t, "allow")
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	pid := threadHold(t, stdin, out, g.Path, g.Path+"/file", "maplong")
	holders, err := b.revoke(g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(holders, func(h mounts.Holder) bool { return h.Pid == pid && !h.Possible }) {
		t.Errorf("%d, mapping a file of the grant after a long line, isn't among the holders %+v", pid, holders)
	}
}

// P5: a mount of the grant's filesystem whose own line is past a megabyte (a bind of a directory that deep in a
// read-write grant) is cut short, its root with it: its process is a possible holder
func TestHoldersLongGrantLine(t *testing.T) {
	src := t.TempDir()
	b, stdin, out := sandboxC(t, "allow")
	c := folders(t, `{"path": "`+src+`", "rw": true}`)
	b.caps[c.id()] = c
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`", "ro": false}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	pid := threadHold(t, stdin, out, g.Path, g.Path, "binddeep")
	holders, err := b.revoke(g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(holders, func(h mounts.Holder) bool { return h.Pid == pid }) {
		t.Errorf("%d, with a bind from deep in the grant, isn't among the holders %+v", pid, holders)
	}
}

// holdBindDeep is threadHoldMain's binddeep: in a mount namespace of the thread's own, a private bind at at of a
// directory past a megabyte deep in path, the grant; the namespace's copy of the grant unmounted
func holdBindDeep(path, at string) error {
	if err := unix.Unshare(unix.CLONE_FS | unix.CLONE_NEWNS); err != nil {
		return err
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	if err := unix.Chdir(path); err != nil {
		return err
	}
	name := strings.Repeat("d", 255)
	for range 4200 {
		if err := unix.Mkdir(name, 0o700); err != nil {
			return err
		}
		if err := unix.Chdir(name); err != nil {
			return err
		}
	}
	if err := unix.Mount(".", at, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	// Out of the grant, so the thread holds it by its mount alone
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	return unix.Unmount(path, unix.MNT_DETACH)
}
