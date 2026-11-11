package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A missing record deletes nix/ and copies the paths the store lacks, telling the progress up to 1 at most
func TestSyncStoreFresh(t *testing.T) {
	w := newWorld(t)
	planted := filepath.Join(w.cfg.StateDir, "nix/store/planted")
	if err := os.MkdirAll(planted, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.dir, "missing"), []byte("stale\n/nix/store/b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var seen []float64
	if err := syncStore(w.cfg, func(f float64) { seen = append(seen, f) }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(planted); err == nil {
		t.Error("nix/ kept without a record")
	}
	c := w.calls()
	if !strings.Contains(c, "nix-store --export /nix/store/b\n") || !strings.Contains(c, "store-import /nix/store/roots\n") {
		t.Errorf("Calls:\n%s", c)
	}
	imported, _ := os.ReadFile(filepath.Join(w.dir, "imported"))
	if len(imported) != 2000 {
		t.Errorf("Imported %d bytes", len(imported))
	}
	if len(seen) == 0 || seen[len(seen)-1] > 0.99 || seen[len(seen)-1] < 0.9 {
		t.Errorf("Progress %v", seen)
	}
	// Recorded: the next sync leaves nix/ alone and finds the store current
	if err := os.MkdirAll(planted, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(w.dir, "missing"))
	if err := syncStore(w.cfg, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(planted); err != nil {
		t.Error("nix/ deleted though recorded")
	}
}

// A store directory that is a link is refused before anything else, and one swapped for another deletes nix/
func TestSyncStoreSwapped(t *testing.T) {
	w := newWorld(t)
	if err := syncStore(w.cfg, nil); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(w.cfg.StateDir, "nix/store")
	if err := os.Rename(store, store+".orig"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(w.dir, store); err != nil {
		t.Fatal(err)
	}
	if err := syncStore(w.cfg, nil); err == nil || !strings.Contains(err.Error(), "is a link") {
		t.Errorf("A link: %v", err)
	}
	os.Remove(store)
	if err := os.Mkdir(store, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syncStore(w.cfg, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store + ".orig"); err == nil {
		t.Error("nix/ kept with a store directory not the one recorded")
	}
}
