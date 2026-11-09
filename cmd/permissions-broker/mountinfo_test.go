package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mounts"
)

// A re-bind of a grant in a nested mount namespace outlives the revoke: reported as a holder
func TestAttackKeepBind(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "file"), []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	keep := t.TempDir()
	b, run, out := sandboxC(t, "allow")
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(run, "run exec unshare -Urm sh -c 'mount --rbind %s %s && exec sleep 60'\n", g.Path, keep)
	var pid int
	if _, err := fmt.Fscan(out, &pid); err != nil || pid <= 0 {
		t.Fatal(pid, err)
	}
	waitUntil(t, "the re-bind", func() bool {
		data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
		return strings.Contains(string(data), " "+keep+" ")
	})
	holders, err := b.revoke(g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(holders, func(h mounts.Holder) bool { return h.Pid == pid }) {
		t.Errorf("The re-bind's process %d isn't among the holders %+v", pid, holders)
	}
}
