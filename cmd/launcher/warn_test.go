package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A warning holds the helper until the user chooses Continue on the splash, which shows it and then clears it
func TestWarningHeld(t *testing.T) {
	w := newWorld(t)
	w.cfg.Splash = []string{w.script("splash", `while read -r l; do echo "line $l" >>`+w.log+`
case $l in *'"warning":"'[!\"]*) sleep 0.3; echo continue;; esac; done`)}
	sp := showSplash(w.cfg)
	defer sp.close()
	ws := listenWarnings(w.cfg, sp)
	defer ws.close()
	start := time.Now()
	acknowledge(w.cfg.Unit, []string{"A hook failed", "Another"})
	if took := time.Since(start); took < 300*time.Millisecond {
		t.Errorf("Went on after %v, before Continue", took)
	}
	for i := 0; !strings.Contains(w.calls(), `"warning":""`) && i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	calls := w.calls()
	if !strings.Contains(calls, `"warning":"A hook failed\n\nAnother"`) || !strings.Contains(calls, `"warning":""`) {
		t.Errorf("Splash got %q", calls)
	}
}

// Without a splash, or without supervise listening, the start goes on at once
func TestWarningUnheld(t *testing.T) {
	w := newWorld(t)
	start := time.Now()
	acknowledge(w.cfg.Unit, []string{"Nobody listens"})
	w.cfg.Splash = nil
	sp := showSplash(w.cfg)
	ws := listenWarnings(w.cfg, sp)
	defer ws.close()
	acknowledge(w.cfg.Unit, []string{"No splash"})
	if took := time.Since(start); took > time.Second {
		t.Errorf("Held %v", took)
	}
}

// The longest launcher name the module takes (launcherNameMax in nix/home/claude-desktop/lib.nix). The eval tests
// read it from here too
const launcherNameMax = 39

// supervise binds the warning socket by path, $XDG_RUNTIME_DIR/claude-desktop/<the app's unit>.warn, at most 107
// bytes and its NUL: of the sockets a launcher's name goes into, the longest. With the longest runtime dir,
// /run/user/4294967294, it binds for a launcher name at the cap and not for one a byte longer
func TestWarningSocketAtLauncherNameCap(t *testing.T) {
	w := newWorld(t)
	t.Chdir(t.TempDir())
	// A relative path as long as the longest runtime dir
	t.Setenv("XDG_RUNTIME_DIR", strings.Repeat("r", len("/run/user/4294967294")))
	w.cfg.Splash = nil
	sp := showSplash(w.cfg)
	for _, n := range []int{launcherNameMax, launcherNameMax + 1} {
		// As the module names the app's unit (appUnit in its lib.nix)
		w.cfg.Unit = "claude-desktop-" + strings.Repeat("a", n) + "-app.service"
		path := filepath.Join(strings.Repeat("r", len("/run/user/4294967294")), "claude-desktop", w.cfg.Unit+".warn")
		if n == launcherNameMax && len(path) != 107 {
			t.Errorf("%s is %d bytes at the cap, want 107", path, len(path))
		}
		ws := listenWarnings(w.cfg, sp)
		if ws.path != path || (ws.ln != nil) != (n == launcherNameMax) {
			t.Errorf("Listening at %s (%d bytes), for a launcher name of %d: %v", ws.path, len(ws.path), n, ws.ln != nil)
		}
		ws.close()
	}
}
