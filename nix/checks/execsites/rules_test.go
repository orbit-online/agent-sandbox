package execsites

import (
	"strings"
	"testing"
)

// The rules on sources that break them, one way each: what a later helper could look like
func TestRulesCatch(t *testing.T) {
	const head = "package p\nimport (\"os/exec\"; \"golang.org/x/sys/unix\")\nvar nsenter = \"nsenter\"\n"
	sites := map[string]site{
		"p/a.go:host":  {class: hostMounts, extra: []string{"-batch"}},
		"p/a.go:enter": {class: reentry},
		"p/a.go:pass":  {class: passes},
	}
	joins := map[string][]string{"p/a.go:join": {"Helper"}}
	const (
		host  = `func host() { exec.Command(nsenter, "--user=/proc/self/fd/3", "--net=/proc/self/fd/4", "--preserve-credentials", "--keep-caps", "ip", "-batch") }`
		enter = `func enter(t string) { _ = []string{"setpriv", "--no-new-privs", nsenter, "-U", "-m", "--preserve-credentials", "-t", t} }`
		pass  = `func pass() { run(nsenter) }; func run(string) {}`
		join  = `func join() { unix.Setns(4, unix.CLONE_NEWNS) }; func Helper() { join(); step() }; func step() {}`
	)
	for _, c := range []struct {
		name string
		src  []string // The functions of p/a.go
		want string   // Part of the one complaint, none when empty
	}{
		{"as the module does it", []string{host, enter, pass, join}, ""},
		{"an unlisted function running nsenter",
			[]string{host, enter, pass, join, `func later() { exec.Command(nsenter, "--user=/proc/self/fd/3") }`},
			"p/a.go:later names nsenter and isn't listed"},
		{"nsenter by a path of its own",
			[]string{host, enter, pass, join, `func later() { exec.Command("/usr/bin/nsenter", "-a") }`},
			"p/a.go:later names nsenter and isn't listed"},
		{"capabilities and the mount namespace",
			[]string{strings.Replace(host, `"--keep-caps"`, `"--keep-caps", "--mount=/proc/self/fd/5"`, 1), enter, pass, join},
			"p/a.go:host runs nsenter with capabilities and --mount=/proc/self/fd/5"},
		{"capabilities and a target's namespaces",
			[]string{strings.Replace(host, `"--keep-caps"`, `"--keep-caps", "-a"`, 1), enter, pass, join},
			"p/a.go:host runs nsenter with capabilities and -a"},
		{"capabilities and the root of the sandbox",
			[]string{strings.Replace(host, `"--keep-caps"`, `"--keep-caps", "--root=/proc/1/root"`, 1), enter, pass, join},
			"p/a.go:host runs nsenter with capabilities and --root=/proc/1/root"},
		{"a namespace by pid instead of a pinned fd",
			[]string{strings.Replace(host, "--net=/proc/self/fd/4", "--net=/proc/1/ns/net", 1), enter, pass, join},
			"p/a.go:host runs nsenter with capabilities and --net=/proc/1/ns/net"},
		{"the re-entry keeping capabilities",
			[]string{host, strings.Replace(enter, `"-U"`, `"-U", "--keep-caps"`, 1), pass, join},
			"p/a.go:enter execs a path of the sandbox's with --keep-caps"},
		{"the re-entry as root of the user namespace",
			[]string{host, strings.Replace(enter, `"-U"`, `"-U", "-S", "0"`, 1), pass, join},
			"p/a.go:enter execs a path of the sandbox's with -S"},
		{"the re-entry without no_new_privs",
			[]string{host, strings.Replace(enter, `"--no-new-privs", `, "", 1), pass, join},
			"p/a.go:enter joins the app's mount namespace without --no-new-privs"},
		{"the re-entry with the caller's ids replaced",
			[]string{host, strings.Replace(enter, `"--preserve-credentials", `, "", 1), pass, join},
			"p/a.go:enter joins the app's mount namespace without --preserve-credentials"},
		{"a function that passes nsenter on running it",
			[]string{host, enter, `func pass() { exec.Command(nsenter, "-a") }`, join},
			"p/a.go:pass runs nsenter itself"},
		{"a function that passes nsenter on building its arguments",
			[]string{host, enter, `func pass() { run([]string{nsenter, "-a"}) }; func run([]string) {}`, join},
			"p/a.go:pass builds nsenter's arguments itself"},
		{"an unlisted setns",
			[]string{host, enter, pass, join, `func other() { unix.Setns(3, 0) }`},
			"p/a.go:other joins a namespace (setns) and isn't listed"},
		{"an exec after joining, through the package",
			[]string{host, enter, pass, strings.Replace(join, "func step() {}", `func step() { exec.Command("true") }`, 1)},
			"p/a.go:Helper joins the sandbox's mount namespace through join and reaches an exec in p/a.go:step"},
		{"an exec in the helper itself",
			[]string{host, enter, pass, strings.Replace(join, "join(); step()", `join(); unix.Exec("/bin/sh", nil, nil)`, 1)},
			"p/a.go:Helper joins the sandbox's mount namespace through join and reaches an exec in p/a.go:Helper"},
		{"another helper joining",
			[]string{host, enter, pass, join, `func Later() { join() }`},
			"p/a.go:join is called by [Helper Later], listed [Helper]"},
		{"a listed function gone",
			[]string{host, enter, join},
			"p/a.go:pass is listed and doesn't name nsenter"},
	} {
		fns, err := parse(map[string]string{"p/a.go": head + strings.Join(c.src, "\n")})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := append(checkSites(fns, sites), checkJoins(fns, joins)...)
		switch {
		case c.want == "" && len(got) > 0:
			t.Errorf("%s: %q", c.name, got)
		case c.want != "" && (len(got) != 1 || !strings.Contains(got[0], c.want)):
			t.Errorf("%s: %q, want one complaint with %q", c.name, got, c.want)
		}
	}
}
