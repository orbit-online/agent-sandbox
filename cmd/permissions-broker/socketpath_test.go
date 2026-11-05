package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The longest launcher name the module takes (launcherNameMax in nix/home/claude-desktop/default.nix). The eval tests
// read it from here, so the module's cap and this test can't drift apart
const launcherNameMax = 46

// The broker binds control.sock and request.sock by path, in $XDG_RUNTIME_DIR/claude-desktop/ (the module's
// controlSocket and grantDir), a pathname socket's path at most 107 bytes and its NUL. With the longest runtime dir,
// /run/user/4294967294, both bind for a launcher name at the cap, and neither for one a byte longer
func TestSocketPathsAtLauncherNameCap(t *testing.T) {
	t.Chdir(t.TempDir())
	// A relative path as long as the longest runtime dir
	runtime := strings.Repeat("r", len("/run/user/4294967294"))
	for _, n := range []int{launcherNameMax, launcherNameMax + 1} {
		dir := filepath.Join(runtime, "claude-desktop", "permissions-"+strings.Repeat("a", n))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{dir + "-control.sock", filepath.Join(dir, "request.sock")} {
			if n == launcherNameMax && len(path) != 107 {
				t.Errorf("%s is %d bytes at the cap, want 107", path, len(path))
			}
			ln, err := listen(path)
			if (err == nil) != (n == launcherNameMax) {
				t.Errorf("Listen on %d bytes, for a launcher name of %d: %v", len(path), n, err)
			}
			if err == nil {
				ln.Close()
			}
		}
	}
}
