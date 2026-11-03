package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mounts"
)

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
	denied, err := mounts.CheckDenied([]string{filepath.Join(elsewhere, "state")}) // lexically unrelated to root
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
