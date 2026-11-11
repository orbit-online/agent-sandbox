package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// tree starts sh as the init of a pid namespace of its own (the sandbox's), running script, and returns its pid as we
// see it once script wrote its ready file
func tree(t *testing.T, script string) int {
	t.Helper()
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	cmd := exec.Command("unshare", "--user", "--map-root-user", "--pid", "--fork", "--kill-child", "sh", "-c",
		script+"; touch "+ready+"; exec sleep 100")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	for range 100 {
		if _, err := os.Stat(ready); err == nil {
			// unshare's child, the namespace's init
			data, _ := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/task/" + strconv.Itoa(cmd.Process.Pid) + "/children")
			pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err != nil {
				t.Fatalf("The namespace's init: %q", data)
			}
			return pid
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("The process tree didn't start")
	return 0
}

// The app is the process at the app's pid one pid namespace below the sandbox's init, not one further down
func TestAppPid(t *testing.T) {
	// A pid namespace below the init, its first process at pid 1, and one more below that, at pid 1 too
	init := tree(t, "unshare --pid --fork sh -c 'unshare --pid --fork sleep 100 & sleep 100' & sleep 0.5")
	app, err := AppPid(init, 1)
	if err != nil {
		t.Fatal(err)
	}
	ns, _ := nsPids(app)
	top, _ := nsPids(init)
	if len(ns) != len(top)+1 || ns[len(ns)-1] != 1 {
		t.Errorf("Took %d at %v, below the init at %v", app, ns, top)
	}
	if _, err := AppPid(init, 999); err == nil {
		t.Error("Found an app at a pid nothing sits at")
	}
}

// Two pid namespaces next to each other below the init each have a pid 1: which is the app isn't known
func TestAppPidAmbiguous(t *testing.T) {
	init := tree(t, "unshare --pid --fork sleep 100 & unshare --pid --fork sleep 100 & sleep 0.5")
	if _, err := AppPid(init, 1); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("Two at the app's pid: %v", err)
	}
}
