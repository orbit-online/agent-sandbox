package main

import (
	"strings"
	"testing"
)

// The start hooks: their arguments, and a warning for a hook that failed (exit 3) or for sandbox-hooks refusing
func TestSandboxHooksStart(t *testing.T) {
	w := newWorld(t)
	for _, tc := range []struct {
		exit int
		want string
	}{
		{0, ""},
		{3, "A start hook on the host failed"},
		{1, "The start hooks on the host didn't run"},
	} {
		exe := w.script("sandbox-hooks", "exit "+itoa(tc.exit))
		got := strings.Join((&sandboxHooks{Exe: exe, Name: "work"}).start(42), "")
		if tc.want == "" && got != "" || !strings.Contains(got, tc.want) {
			t.Errorf("exit %d: %q, want %q", tc.exit, got, tc.want)
		}
	}
	if !strings.Contains(w.calls(), "sandbox-hooks start 42 --name=work") {
		t.Errorf("calls %q", w.calls())
	}
	(&sandboxHooks{Exe: w.script("sandbox-hooks", "")}).start(7)
	if !strings.Contains(w.calls(), "sandbox-hooks start 7\n") {
		t.Errorf("default launcher: calls %q", w.calls())
	}
}

func itoa(i int) string { return string(rune('0' + i)) }
