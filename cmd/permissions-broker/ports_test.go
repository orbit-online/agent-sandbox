package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
	"golang.org/x/sys/unix"
)

// fakeNetkit stands in for netns-netkit: a port granted is a file in its ports directory, every run a line of its log,
// and a command fails while a file fail-<command> is there (fail-revoke-all for revoke --all) and takes 300 ms while
// slow-<command> is
type fakeNetkit struct{ dir string }

func newFakeNetkit(t *testing.T) (fakeNetkit, string) {
	t.Helper()
	f := fakeNetkit{dir: t.TempDir()}
	if err := os.Mkdir(filepath.Join(f.dir, "ports"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, "netns-netkit")
	script := `#!/bin/sh
d=` + f.dir + `
echo "$*" >>$d/log
cmd=$1; shift
case $1 in --name=*) shift ;; esac
[ "$cmd $1" = "revoke --all" ] && cmd=revoke-all
if [ -e $d/slow-$cmd ]; then sleep 0.3; fi
if [ -e $d/fail-$cmd ]; then echo "$cmd failed" >&2; exit 1; fi
case $cmd in
grant) touch $d/ports/$1-$2 ;;
revoke) rm -f $d/ports/$1-$2 ;;
revoke-all) rm -f $d/ports/* ;;
addr) echo 169.254.100.7 fd12:3456:789a::7 ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return f, path
}

// ports is what the fake has granted, sorted: tcp-8080 and such
func (f fakeNetkit) ports() []string {
	entries, _ := os.ReadDir(filepath.Join(f.dir, "ports"))
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func (f fakeNetkit) log() string {
	data, _ := os.ReadFile(filepath.Join(f.dir, "log"))
	return string(data)
}

// fail makes cmd fail, or succeed again
func (f fakeNetkit) fail(t *testing.T, cmd string, on bool) { f.set(t, "fail-"+cmd, on) }

func (f fakeNetkit) set(t *testing.T, name string, on bool) {
	t.Helper()
	path := filepath.Join(f.dir, name)
	if on {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	os.Remove(path)
}

// portBroker is a test broker with the port capability over a fake helper, for a sandbox that runs
func portBroker(t *testing.T, answers ...string) (*broker, *fakeAsker, fakeNetkit) {
	t.Helper()
	b, f := testBroker(t, answers...)
	nk, path := newFakeNetkit(t)
	b.cfg.NetnsNetkit = path
	c, err := portCap(b.cfg)
	if err != nil {
		t.Fatal(err)
	}
	b.caps[c.id()] = c
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(pidfd) })
	b.sb.pidfd = pidfd
	return b, f, nk
}

// A grant switches the port on and says where the host reaches it; its release switches it off
func TestPortGrant(t *testing.T) {
	b, f, nk := portBroker(t, "allow")
	g, err := b.request(peerAt(t, os.Getpid()), req(portID, `{"protocol": "tcp", "port": 8080}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"169.254.100.7:8080", "[fd12:3456:789a::7]:8080"}; !slices.Equal(g.Addresses, want) {
		t.Errorf("Addresses %v, want %v", g.Addresses, want)
	}
	if want := []string{"tcp-8080"}; !slices.Equal(nk.ports(), want) {
		t.Errorf("Ports %v, want %v", nk.ports(), want)
	}
	if got := f.asked[0].Summary; got != "TCP port 8080 of the sandbox, reachable from the host" {
		t.Errorf("Asked %q", got)
	}
	if err := b.release(g.ID, "released"); err != nil {
		t.Fatal(err)
	}
	if len(nk.ports()) != 0 {
		t.Errorf("Ports after the release: %v", nk.ports())
	}
	if want := "grant --name=test tcp 8080\naddr --name=test\nrevoke --name=test tcp 8080\n"; nk.log() != want {
		t.Errorf("Helper runs:\n%s\nwant\n%s", nk.log(), want)
	}
}

// A grant ends on its lease, on revoke and with the daemon: each switches its port off
func TestPortEnds(t *testing.T) {
	b, _, nk := portBroker(t, "allow", "allow", "allow")
	clk := newFakeClock()
	b.clock = clk
	p := peerAt(t, os.Getpid())
	if _, err := b.request(p, req(portID, `{"protocol": "udp", "port": 53}`, "PT10M")); err != nil {
		t.Fatal(err)
	}
	clk.advance(10 * time.Minute)
	waitUntil(t, "the lease to end", func() bool { return len(b.liveGrants()) == 0 && len(nk.ports()) == 0 })

	g, err := b.request(p, req(portID, `{"protocol": "udp", "port": 53}`, "PT10M"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.revoke(g.ID); err != nil || len(nk.ports()) != 0 {
		t.Errorf("Revoke: %v, ports %v", err, nk.ports())
	}

	if _, err := b.request(p, req(portID, `{"protocol": "tcp", "port": 22}`, "PT10M")); err != nil {
		t.Fatal(err)
	}
	b.endAll("the sandbox ended")
	if len(nk.ports()) != 0 {
		t.Errorf("Ports after the daemon ended: %v", nk.ports())
	}
}

// The helper failing: no grant, and no port left on
func TestPortHelperFails(t *testing.T) {
	b, _, nk := portBroker(t, "allow", "allow")
	p := peerAt(t, os.Getpid())
	nk.fail(t, "grant", true)
	_, err := b.request(p, req(portID, `{"protocol": "tcp", "port": 8080}`, "PT1H"))
	if refusalOf(err) != refFailed || len(b.liveGrants()) != 0 || !strings.Contains(err.Error(), "grant failed") {
		t.Errorf("Grant failing: %v, grants %v", err, b.liveGrants())
	}
	nk.fail(t, "grant", false)
	nk.fail(t, "addr", true)
	_, err = b.request(p, req(portID, `{"protocol": "tcp", "port": 8080}`, "PT1H"))
	if refusalOf(err) != refFailed || len(b.liveGrants()) != 0 || len(nk.ports()) != 0 {
		t.Errorf("No address: %v, grants %v, ports %v", err, b.liveGrants(), nk.ports())
	}
}

// What's refused before the user is asked, and a window answer for another port
func TestPortRefused(t *testing.T) {
	b, f, nk := portBroker(t)
	p := peerAt(t, os.Getpid())
	for _, params := range []string{`{"protocol": "tcp"}`, `{"port": 80}`, `{"protocol": "sctp", "port": 80}`,
		`{"protocol": "tcp", "port": 0}`, `{"protocol": "tcp", "port": 65536}`, `{"protocol": "tcp", "port": 1.5}`,
		`{"protocol": "tcp", "port": 80, "host": "x"}`} {
		if _, err := b.request(p, req(portID, params, "PT1H")); refusalOf(err) != refParams {
			t.Errorf("%s: %v", params, err)
		}
	}
	if f.count() != 0 {
		t.Errorf("Asked %d times", f.count())
	}

	f.answers = []string{"options"}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			b.mu.Lock()
			var id string
			for _, p := range b.pending {
				if p.Options {
					id = p.ID
				}
			}
			b.mu.Unlock()
			if id != "" {
				_ = b.answer(wire.Request{Pending: id, Allow: true, Params: json.RawMessage(`{"protocol": "tcp", "port": 22}`)})
				return
			}
		}
	}()
	if _, err := b.request(p, req(portID, `{"protocol": "tcp", "port": 8080}`, "PT1H")); refusalOf(err) != refParams {
		t.Errorf("Another port from the window: %v", err)
	}
	if len(nk.ports()) != 0 {
		t.Errorf("Ports %v", nk.ports())
	}
}

// Standing grants of ports at start, and the cleanup a daemon stopping runs
func TestPortStandingAndCleanup(t *testing.T) {
	b, f, nk := portBroker(t)
	b.cfg.Grants = []standingConfig{{Capability: portID, Params: json.RawMessage(`{"port": 3000, "protocol": "tcp"}`)}}
	again, err := newBroker(b.cfg, b.caps, b.sb, f.ask)
	if err != nil {
		t.Fatal(err)
	}
	again.grantStanding()
	if gs := again.liveGrants(); len(gs) != 1 || gs[0].Lease != "standing" || len(gs[0].Addresses) != 2 ||
		!slices.Equal(nk.ports(), []string{"tcp-3000"}) {
		t.Fatalf("Standing: %+v, ports %v", gs, nk.ports())
	}
	cleanup(again.cfg, again.sb, realClock{})
	if len(nk.ports()) != 0 || !strings.HasSuffix(nk.log(), "revoke --name=test --all\n") {
		t.Errorf("Cleanup: ports %v, runs\n%s", nk.ports(), nk.log())
	}
	// Without the sandbox found, its ports are revoked all the same: that needs only the name of the launcher
	nk.set(t, "ports/tcp-3000", true)
	cleanup(again.cfg, nil, realClock{})
	if len(nk.ports()) != 0 || strings.Count(nk.log(), "revoke --name=test --all\n") != 2 {
		t.Errorf("Cleanup without the sandbox: ports %v, runs\n%s", nk.ports(), nk.log())
	}
}

// A cleanup whose revoke of the ports fails tries again while the sandbox runs, and stops once it ended
func TestPortCleanupUntilSandboxEnds(t *testing.T) {
	b, _, nk := portBroker(t)
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	pidfd, err := unix.PidfdOpen(child.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(pidfd); _ = child.Process.Kill(); _ = child.Wait() })
	nk.set(t, "ports/tcp-3000", true)
	nk.fail(t, "revoke-all", true)
	clk := newFakeClock()
	done := make(chan struct{})
	go func() { cleanup(b.cfg, &sandbox{pidfd: pidfd}, clk); close(done) }()
	waitUntil(t, "a second try", func() bool {
		clk.advance(time.Minute)
		return strings.Count(nk.log(), "--all\n") >= 2
	})
	select {
	case <-done:
		t.Fatal("The cleanup ended while the sandbox runs")
	default:
	}
	_ = child.Process.Kill()
	_ = child.Wait()
	waitUntil(t, "the cleanup to end", func() bool {
		clk.advance(time.Minute)
		select {
		case <-done:
			return true
		default:
			return false
		}
	})
	if !slices.Equal(nk.ports(), []string{"tcp-3000"}) {
		t.Errorf("Ports %v", nk.ports())
	}
}

// A grant of a port while the end of another grant of it revokes it: the revoke goes first, then the grant, and the
// port stays on
func TestPortGrantDuringRevoke(t *testing.T) {
	b, _, nk := portBroker(t, "allow", "allow")
	p := peerAt(t, os.Getpid())
	params := `{"protocol": "tcp", "port": 8080}`
	g, err := b.request(p, req(portID, params, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	nk.set(t, "slow-revoke", true)
	released := make(chan error, 1)
	go func() { released <- b.release(g.ID, "released") }()
	waitUntil(t, "the revoke to start", func() bool { return strings.Contains(nk.log(), "revoke --name=test tcp 8080") })
	again, err := b.request(p, req(portID, params, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	if err := <-released; err != nil {
		t.Fatal(err)
	}
	if gs := b.liveGrants(); len(gs) != 1 || gs[0].ID != again.ID || !slices.Equal(nk.ports(), []string{"tcp-8080"}) {
		t.Errorf("Live %v, ports %v, runs\n%s", gs, nk.ports(), nk.log())
	}
	// And its end switches it off
	nk.set(t, "slow-revoke", false)
	if err := b.release(again.ID, "released"); err != nil || len(nk.ports()) != 0 {
		t.Errorf("Release: %v, ports %v", err, nk.ports())
	}
}
