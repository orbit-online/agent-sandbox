package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Started as nixpak starts it (--fd=3 first, the module's --config, --filter last), the proxy writes a byte to the fd
// once it listens and exits when the other end closes, removing its socket
func TestSyncFD(t *testing.T) {
	bus := startBus(t)
	startService(t, bus)
	sock := filepath.Join(t.TempDir(), "proxy")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cfg := configFile(t, policy(svcName, "talk"), ruled("org.test.X", "call", "*"))
	cmd := exec.Command(os.Args[0], "--fd=3", bus, sock, "--config="+cfg, "--filter")
	cmd.Env = append(os.Environ(), "DBUS_PROXY_MAIN=1")
	cmd.ExtraFiles = []*os.File{w}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	w.Close()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { cmd.Process.Kill() })

	r.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 1)
	if n, err := r.Read(b); n != 1 || b[0] != 'x' {
		t.Fatalf("Read the ready byte: %q %v", b[:n], err)
	}
	c := connect(t, "unix:path="+sock)
	if _, err := call(c, svcName, "/org/test", svcIface+".Echo", "x"); err != nil {
		t.Errorf("Call through the proxy: %v", err)
	}
	r.Close()
	select {
	case err := <-exited:
		if err != nil {
			t.Errorf("Proxy exited with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Proxy still runs after its fd closed")
	}
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Socket left behind: %v", err)
	}
}

// Arguments the proxy doesn't take are refused, xdg-dbus-proxy's rule flags among them, as are a config missing or
// invalid (the rules package's tests have the rest)
func TestBadArguments(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "proxy")
	cfg := "--config=" + configFile(t, policy("org.test.X", "talk"))
	bad := func(entries ...string) string { return "--config=" + configFile(t, entries...) }
	for _, args := range [][]string{
		{"unix:path=/x", sock, cfg, "--filter", "--sloppy-names"},
		{"unix:path=/x", sock, cfg, "--filter", "--talk=org.test.X"},
		{"unix:path=/x", sock, cfg, "--filter", "--call=org.test.X=*"},
		{"unix:path=/x", sock, "--filter"},
		{"unix:path=/x", sock, "--config=" + filepath.Join(t.TempDir(), "none.json"), "--filter"},
		{"unix:path=/x", sock, bad(policy(":1.2", "talk")), "--filter"},
		{"unix:path=/x", sock, bad(policy("org.test.X.*", "talk")), "--filter"},
		{"unix:path=/x", sock, bad(policy("org.test.X", "all")), "--filter"},
		{"unix:path=/x", sock, bad(ruled("org.test.X", "call", "*@bad")), "--filter"},
		{"unix:path=/x", sock, bad(`"org.test.X": {"policy": "talk", "own": true}`), "--filter"},
		{"tcp:host=localhost", sock, cfg, "--filter"},
		// Without --filter xdg-dbus-proxy passes everything; this proxy always filters
		{"unix:path=/x", sock, cfg},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], args...)
		cmd.Env = append(os.Environ(), "DBUS_PROXY_MAIN=1")
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if ctx.Err() != nil || !errors.As(err, &ee) || ee.ExitCode() <= 0 {
			t.Errorf("%v accepted: %v %s", args, err, out)
		}
	}
}
