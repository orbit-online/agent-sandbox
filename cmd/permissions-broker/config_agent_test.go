package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A config without an agent says "The agent", one with names it
func TestConfigAgent(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct{ json, want string }{{`{}`, "The agent"}, {`{"agent": "Claude"}`, "Claude"}} {
		p := filepath.Join(dir, "config.json")
		if err := os.WriteFile(p, []byte(c.json), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg, err := readConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Agent != c.want {
			t.Errorf("%s: agent %q, want %q", c.json, cfg.Agent, c.want)
		}
	}
}
