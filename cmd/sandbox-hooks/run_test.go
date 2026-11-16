package main

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/orbit-online/agent-sandbox/internal/caller"
)

// Absolute paths of the tools the hooks use: they get no PATH
func tools(t *testing.T, names ...string) map[string]string {
	t.Helper()
	tool := map[string]string{}
	for _, name := range names {
		p, err := exec.LookPath(name)
		if err != nil {
			t.Fatal(err)
		}
		tool[name] = p
	}
	return tool
}

// A hook gets its arguments, the files on fd 3 on, an empty environment, / and stdin from /dev/null, its stdout on
// stderr; every hook runs, and one failing or running past the timeout makes errHooks
func TestRunHooks(t *testing.T) {
	timeout := hookTimeout
	hookTimeout = time.Second
	t.Cleanup(func() { hookTimeout = timeout })
	t.Setenv("LEAK", "1")
	dir := t.TempDir()
	out := dir + "/out"
	tool := tools(t, "env", "grep", "tr", "readlink", "sleep")
	write(t, dir+"/ok", `#!/bin/sh
{ echo "args=$*"; echo "env=$(`+tool["env"]+` | `+tool["grep"]+` -v '^PWD=\|^SHLVL=\|^_=' | `+tool["tr"]+` '\n' ' ')"
  echo "pwd=$(pwd)"; echo "fd3=$(`+tool["readlink"]+` /proc/self/fd/3)"; read -r line; echo "stdin=$?"; } > `+out+`
echo to-stdout
`, 0o755)
	write(t, dir+"/fail", "#!/bin/sh\nexit 1\n", 0o755)
	write(t, dir+"/slow", "#!/bin/sh\n"+tool["sleep"]+" 30\n", 0o755)
	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer netns.Close()
	want, _ := os.Readlink("/proc/self/ns/net")
	r, w, _ := os.Pipe()
	stderr := os.Stderr
	os.Stderr = w
	err = runHooks([]hook{{Path: dir + "/ok"}}, "start", 1000, "work", []*os.File{netns})
	os.Stderr = stderr
	w.Close()
	buf := make([]byte, 64)
	n, _ := r.Read(buf)
	if err != nil {
		t.Fatalf("runHooks: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "to-stdout") {
		t.Errorf("stdout of the hook not on stderr: %q", buf[:n])
	}
	got, _ := os.ReadFile(out)
	for _, line := range []string{"args=start 1000 work\n", "env=\n", "pwd=/\n", "fd3=" + want, "stdin=1"} {
		if !strings.Contains(string(got), line) {
			t.Errorf("hook saw %q, want %q", got, line)
		}
	}
	os.Remove(out)
	if err := runHook(hook{Path: dir + "/slow"}, "stop", 1000, "", nil); err == nil || !strings.Contains(err.Error(), "Killed after") {
		t.Errorf("slow hook: err = %v, want killed", err)
	}
	began := time.Now()
	err = runHooks([]hook{{Path: dir + "/fail"}, {Path: dir + "/slow"}, {Path: dir + "/ok"}}, "stop", 1000, "", nil)
	if !errors.Is(err, errHooks) {
		t.Errorf("failing hooks: err = %v, want errHooks", err)
	}
	if d := time.Since(began); d > 5*time.Second {
		t.Errorf("slow hook ran %s, past its timeout", d)
	}
	if got, _ := os.ReadFile(out); !strings.Contains(string(got), "args=stop 1000 \n") {
		t.Errorf("hook after the failing ones didn't run: %q", got)
	}
	// A capability the process doesn't hold: the hook doesn't run
	err = runHooks([]hook{{Path: dir + "/ok", caps: []uintptr{capNames["CAP_SYS_ADMIN"]}}}, "stop", 1000, "", nil)
	if !errors.Is(err, errHooks) {
		t.Errorf("hook with a capability not held: err = %v", err)
	}
}

// run checks what the caller names before any hook runs, and runs only the hooks of the phase
func TestRun(t *testing.T) {
	dir := t.TempDir()
	me := uint32(os.Getuid())
	t.Cleanup(func() { human = caller.Human })
	human = func() error { return errors.New("Only members of group users") }
	write(t, dir+"/hooks.json", "{}", 0o644)
	if err := run(docopt.Opts{"--name": "", "start": false}, dir+"/hooks.json", me); err == nil {
		t.Error("a caller outside group users ran")
	}
	human = func() error { return nil }
	tool := tools(t, "touch")
	write(t, dir+"/hook", "#!/bin/sh\n"+tool["touch"]+" "+dir+"/ran-$1\n", 0o755)
	write(t, dir+"/hooks.json", `{"start": [{"path": "`+dir+`/hook"}], "stop": [{"path": "`+dir+`/hook"}]}`, 0o644)
	parse := func(args ...string) docopt.Opts {
		opts, err := docopt.ParseArgs(usage, args, "")
		if err != nil {
			t.Fatal(err)
		}
		return opts
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"stop", "--name=Work"}, "is not [a-z]"},
		{[]string{"start", "0"}, "is not a process"},
		{[]string{"start", "x"}, "is not a process"},
		{[]string{"start", strconv.Itoa(os.Getpid())}, "shares the caller's network namespace"},
	} {
		if err := run(parse(tc.args...), dir+"/hooks.json", me); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: err = %v, want %q", tc.args, err, tc.want)
		}
	}
	if _, err := os.Stat(dir + "/ran-start"); err == nil {
		t.Error("a start hook ran though the checks refused")
	}
	if err := run(parse("stop", "--name=work"), dir+"/hooks.json", me); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := os.Stat(dir + "/ran-stop"); err != nil {
		t.Error("the stop hook didn't run")
	}
	if _, err := os.Stat(dir + "/ran-start"); err == nil {
		t.Error("a start hook ran for stop")
	}
}
