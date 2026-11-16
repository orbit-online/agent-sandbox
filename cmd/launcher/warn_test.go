package main

import (
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
