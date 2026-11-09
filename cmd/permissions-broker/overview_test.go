package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mountinfo"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
	"golang.org/x/sys/unix"
)

func absentOf(t *testing.T, overview json.RawMessage) []string {
	t.Helper()
	var o struct {
		Absent []string `json:"absent"`
	}
	if err := json.Unmarshal(overview, &o); err != nil {
		t.Fatalf("Overview %s: %v", overview, err)
	}
	return o.Absent
}

// An optional bind or a device without a mount at its path is absent; a bind that isn't optional never is, and the
// rest of the overview stays as it was
func TestWithAbsent(t *testing.T) {
	overview := json.RawMessage(`{"network":"its own","binds":[{"path":"/etc/group","optional":true},` +
		`{"path":"/etc/passwd","optional":true},{"path":"/home/alice","rw":true}],"devices":["/dev/kvm","/dev/null"]}`)
	lines := []mountinfo.Line{{Point: "/"}, {Point: "/etc/passwd"}, {Point: "/dev/null"}}
	got := withAbsent(overview, lines)
	if a := absentOf(t, got); !reflect.DeepEqual(a, []string{"/etc/group", "/dev/kvm"}) {
		t.Errorf("Absent %q", a)
	}
	var o map[string]json.RawMessage
	_ = json.Unmarshal(got, &o)
	if string(o["network"]) != `"its own"` || len(o) != 4 {
		t.Errorf("Overview %s", got)
	}
	all := []mountinfo.Line{{Point: "/etc/group"}, {Point: "/etc/passwd"}, {Point: "/dev/kvm"}, {Point: "/dev/null"}}
	if a := absentOf(t, withAbsent(overview, all)); a == nil || len(a) != 0 {
		t.Errorf("Absent with everything mounted %q", a)
	}
	if got := withAbsent(json.RawMessage(`[1]`), lines); string(got) != `[1]` {
		t.Errorf("Not an object: %s", got)
	}
}

// control.sock's state marks what the sandbox's mount namespace lacks, read from a stand-in with a mount of its own
func TestStateOverviewAbsent(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	sb := ownNs(t, dir)
	sbfd, err := unix.PidfdOpen(sb.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	b.sb = pinned(t, sb.Process.Pid, sbfd)
	missing := filepath.Join(dir, "missing")
	overview, _ := json.Marshal(map[string]any{
		"binds":   []map[string]any{{"path": dir, "optional": true}, {"path": missing, "optional": true}},
		"devices": []string{filepath.Join(dir, "kvm")},
	})
	b.cfg.Overview = overview
	res := b.handleControl(nil, peerAt(t, os.Getpid()), wire.Request{Op: "state"})
	if a := absentOf(t, res.Overview); !reflect.DeepEqual(a, []string{missing, filepath.Join(dir, "kvm")}) {
		t.Errorf("Absent %q", a)
	}
}
