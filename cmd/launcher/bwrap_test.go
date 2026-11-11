package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The test binary runs as the launcher with the arguments in LAUNCHER_TEST_MAIN, and as its helper when the launcher
// starts it so, with its own
func TestMain(m *testing.M) {
	if os.Getenv("LAUNCHER_TEST_MAIN") != "" {
		if len(os.Args) < 2 || os.Args[1] != "bwrap-helper" {
			os.Args = append([]string{os.Args[0]}, strings.Fields(os.Getenv("LAUNCHER_TEST_MAIN"))...)
		}
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// A bwrap of the test's: it reports a child of its own on --info-fd, waits for the user namespace's block, then
// records what it got (the block's line, fds 22 and 23) and its arguments in dir
func fakeBwrap(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "bwrap")
	script := `#!/bin/sh
echo "$@" >` + dir + `/args
sleep 100 20>&- 21<&- & child=$!
printf '{"child-pid": %d, "mnt-namespace": 1, "pid-namespace": 1}' "$child" >&20
exec 20>&-
read -r line <&21 && echo unblocked >` + dir + `/blocked
cat <&22 >` + dir + `/subuid
cat <&23 >` + dir + `/subgid
kill "$child"
`
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// recorder writes a tool that records its arguments in dir/name and exits with status
func recorder(t *testing.T, dir, name, status string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho \"$@\" >>"+dir+"/"+name+".log\nexit "+status+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func launch(t *testing.T, dir, newuidmap string) error {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), "LAUNCHER_TEST_MAIN=bwrap --mode=parent --bwrap="+fakeBwrap(t, dir)+
		" --newuidmap="+newuidmap+" --newgidmap="+recorder(t, dir, "newgidmap", "0")+
		" --permissions-broker="+recorder(t, dir, "broker", "0")+" -- --die-with-parent -- app")
	cmd.Stderr = os.Stderr
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(20 * time.Second):
		cmd.Process.Kill()
		t.Fatal("bwrap didn't end")
	}
	return nil
}

// Mode parent: the helper writes the parent's ids as themselves once bwrap reported its child, then unblocks it, which
// gets the subuid and subgid lines on fds 22 and 23 and its own arguments after the launcher's
func TestBwrapParent(t *testing.T) {
	dir := t.TempDir()
	if err := launch(t, dir, recorder(t, dir, "newuidmap", "0")); err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		data, _ := os.ReadFile(filepath.Join(dir, name))
		return strings.TrimSpace(string(data))
	}
	if got := read("args"); got != "--unshare-user --info-fd 20 --userns-block-fd 21 --die-with-parent -- app" {
		t.Errorf("bwrap's arguments: %q", got)
	}
	uidMap, _ := os.ReadFile("/proc/self/uid_map")
	m, _ := identityMap(strings.NewReader(string(uidMap)))
	if got := read("newuidmap.log"); !strings.HasSuffix(got, " "+strings.Join(mapArgs(m), " ")) {
		t.Errorf("newuidmap got %q for the map %v", got, m)
	}
	if read("blocked") != "unblocked" || read("newgidmap.log") == "" {
		t.Error("Not unblocked after both maps")
	}
	if got, want := read("subuid"), strings.TrimSpace(subidLines(m, currentUser(t), os.Getuid())); got != want {
		t.Errorf("subuid on fd 22: %q, want %q", got, want)
	}
}

// A map that fails takes bwrap down before its child runs unmapped
func TestBwrapMapFails(t *testing.T) {
	dir := t.TempDir()
	err := launch(t, dir, recorder(t, dir, "newuidmap", "1"))
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != -1 {
		t.Errorf("bwrap ended with %v, not killed", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "blocked")); err == nil {
		t.Error("Unblocked without maps")
	}
}

func currentUser(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("id", "-un").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}
