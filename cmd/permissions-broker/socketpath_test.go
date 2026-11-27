package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The longest sandbox name, <app>[-<launcher>], the module takes (sandboxNameMax in nix/home/sandbox/lib.nix), which
// these sockets set. The eval tests read it from here, so the module's cap and this test can't drift apart
const sandboxNameMax = 47

// The broker binds control.sock and request.sock by path, in $XDG_RUNTIME_DIR/agent-sandbox/ (the module's
// controlSocket and grantDir, <sandbox>-permissions), a pathname socket's path at most 107 bytes and its NUL. With the
// longest runtime dir, /run/user/4294967294, both bind for a sandbox name at the module's cap, and neither for one a
// byte longer
func TestSocketPathsAtSandboxNameCap(t *testing.T) {
	t.Chdir(t.TempDir())
	// A relative path as long as the longest runtime dir
	runtime := strings.Repeat("r", len("/run/user/4294967294"))
	for _, n := range []int{sandboxNameMax, sandboxNameMax + 1} {
		dir := filepath.Join(runtime, "agent-sandbox", strings.Repeat("a", n)+"-permissions")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{dir + "-control.sock", filepath.Join(dir, "request.sock")} {
			if n == sandboxNameMax && len(path) != 107 {
				t.Errorf("%s is %d bytes for a name of %d, want 107", path, len(path), n)
			}
			ln, err := listen(path)
			if (err == nil) != (n <= sandboxNameMax) {
				t.Errorf("Listen on %d bytes, for a sandbox name of %d: %v", len(path), n, err)
			}
			if err == nil {
				ln.Close()
			}
		}
	}
}
