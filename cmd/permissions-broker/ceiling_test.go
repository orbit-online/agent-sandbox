package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckDenied(t *testing.T) {
	for _, bad := range []string{"", "relative", "./x"} {
		if _, err := checkDenied([]string{bad}); err == nil {
			t.Errorf("checkDenied accepted %q", bad)
		}
	}
	dir := t.TempDir()
	if err := os.Symlink(dir, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if got, err := checkDenied([]string{filepath.Join(dir, "link")}); err != nil || got[0] != dir {
		t.Errorf("checkDenied = %v, %v; want the link resolved", got, err)
	}
}

func TestCheckSource(t *testing.T) {
	ceil := attachCeiling{Sources: []source{{Path: "/srv/notes"}, {Path: "/srv/work", RW: true}, {Path: "/srv/work/keep-ro"},
		{Path: "/dev/kvm"}}}
	denied := []string{"/srv/work/state"}
	for _, ok := range []struct {
		src       string
		ro        bool
		root, rel string
	}{
		{"/srv/notes", true, "/srv/notes", "."},
		{"/srv/notes/a/../b", true, "/srv/notes", "b"},
		{"/srv/work/x", false, "/srv/work", "x"},
		{"/srv/work/keep-ro/x", true, "/srv/work/keep-ro", "x"},
		{"/dev/kvm", true, "/dev/kvm", "."},
	} {
		root, rel, err := checkSource(ceil, denied, ok.src, ok.ro)
		if err != nil || root != ok.root || rel != ok.rel {
			t.Errorf("checkSource(%s) = %s, %s, %v", ok.src, root, rel, err)
		}
	}
	for _, bad := range []struct {
		src string
		ro  bool
	}{
		{"/srv/notes", false},       // read-only only
		{"/srv/notesx", true},       // not beneath, only a prefix of the name
		{"/srv/notes/../etc", true}, // out by ..
		{"srv/notes", true},         // relative
		{"/srv/work/state/x", true}, // denied
		{"/srv/work", true},         // holds a denied directory
		{"/srv", true},
		{"/srv/work/keep-ro/x", false}, // the longest source decides, and it's read-only
	} {
		if _, _, err := checkSource(ceil, denied, bad.src, bad.ro); err == nil {
			t.Errorf("checkSource(%s, ro=%v) accepted", bad.src, bad.ro)
		}
	}
}

// The sandbox's attacks on attach grants, from its rw binds, which may lie under a ceiling root

// A ceiling root swapped for a link to elsewhere
func TestAttackRootSwap(t *testing.T) {
	ws, secret := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(secret, "key"), []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(ws, "proj")
	b, _, _ := sandboxC(t, "allow")
	c := folders(t, `{"path": "`+root+`"}`)
	b.caps[c.id()] = c
	if err := os.Symlink(secret, root); err != nil {
		t.Fatal(err)
	}
	if g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+root+`"}`, "PT1H")); err == nil {
		t.Errorf("Mounted %s through a link in place of the ceiling root", g.Source)
	}
}

// A link beneath the root to a denied directory
func TestAttackDeniedLink(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	for _, d := range []string{filepath.Join(root, "ws"), state} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../state", filepath.Join(root, "ws", "x")); err != nil {
		t.Fatal(err)
	}
	b, _, _ := sandboxC(t, "allow")
	b.cfg.Denied = []string{state}
	c := folders(t, `{"path": "`+root+`", "rw": true}`)
	b.caps[c.id()] = c
	if g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+root+`/ws/x", "ro": false}`, "PT1H")); err == nil {
		t.Errorf("Mounted %s, a denied directory, through a link", g.Source)
	}
}

// A denied directory configured through a link: checkDenied resolves it, so the path check catches the source
// whether it is the denied directory or holds it
func TestDeniedThroughLink(t *testing.T) {
	root, elsewhere := t.TempDir(), t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.MkdirAll(filepath.Join(state, "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(state, filepath.Join(elsewhere, "state")); err != nil {
		t.Fatal(err)
	}
	b, _, _ := sandboxC(t, "allow", "allow")
	denied, err := checkDenied([]string{filepath.Join(elsewhere, "state")}) // lexically unrelated to root
	if err != nil {
		t.Fatal(err)
	}
	b.cfg.Denied = denied
	c := folders(t, `{"path": "`+root+`"}`)
	b.caps[c.id()] = c
	for _, p := range []string{state + "/inner", root} {
		if g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+p+`"}`, "PT1H")); err == nil {
			t.Errorf("Mounted %s, which is or holds a denied directory", g.Source)
		}
	}
}
