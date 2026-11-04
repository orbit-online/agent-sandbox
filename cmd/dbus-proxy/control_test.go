package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// The app ID of the tests' sandbox, which live sets may own names below
const testApp = "org.test.App"

// A proxy with a control socket, its clients' address and the control socket's path
func startLive(t *testing.T, bus string, args ...string) (string, string) {
	t.Helper()
	ctlPath := filepath.Join(t.TempDir(), "control")
	var p *Proxy
	addr := startProxyWith(t, bus, func(pp *Proxy) { p = pp; pp.policyBus, pp.appID = "session", testApp }, args...)
	l, err := listen(ctlPath)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { p.serveControl(l); close(done) }()
	t.Cleanup(func() { l.Close(); <-done })
	return addr, ctlPath
}

// The broker's side of the control socket
type ctlConn struct {
	conn *net.UnixConn
	r    *bufio.Reader
}

func dialControl(t *testing.T, path string) *ctlConn {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	return &ctlConn{conn, bufio.NewReader(conn)}
}

// Sends a request and returns the answer, or nil when the proxy closed the connection
func (c *ctlConn) do(t *testing.T, req map[string]any) *controlResponse {
	t.Helper()
	data, _ := json.Marshal(req)
	if _, err := c.conn.Write(append(data, '\n')); err != nil {
		return nil
	}
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		return nil
	}
	var res controlResponse
	if err := json.Unmarshal(line, &res); err != nil {
		t.Fatal(err)
	}
	return &res
}

func (c *ctlConn) must(t *testing.T, req map[string]any) *controlResponse {
	t.Helper()
	res := c.do(t, req)
	if res == nil || !res.OK {
		t.Fatalf("%v: %+v", req, res)
	}
	return res
}

func echo(conn *dbus.Conn, dest string) error {
	_, err := call(conn, dest, "/org/test", svcIface+".Echo", "hi")
	return err
}

// A set added applies to the client's next message, by the owner's unique name too, whose owner the proxy looks up
// before it; a removal refuses the next one
func TestLiveAddRemove(t *testing.T) {
	bus := startBus(t)
	svc := startService(t, bus)
	addr, ctlPath := startLive(t, bus)
	c, c2 := connect(t, addr), connect(t, addr)
	ctl := dialControl(t, ctlPath)
	wantErr(t, "before the grant", echo(c, svcName), errServiceUnknown)
	ctl.must(t, map[string]any{"op": "add", "id": "g1", "talk": []string{svcName}})
	wantErr(t, "after the grant", echo(c, svcName), "")
	wantErr(t, "by unique name, right after a grant", echo(c2, svc.Names()[0]), "")
	ctl.must(t, map[string]any{"op": "add", "id": "g2", "talk": []string{"org.test.Other"}})
	res := ctl.must(t, map[string]any{"op": "remove", "id": "g2"})
	if res.Closed != 0 {
		t.Errorf("Removing a set no client used closed %d connections", res.Closed)
	}
	ctl.must(t, map[string]any{"op": "remove", "id": "g1"})
	c3 := connect(t, addr)
	wantErr(t, "after the revoke", echo(c3, svcName), errServiceUnknown)
}

// A removal ends the connections that used the set, dropping the names they owned under it, and leaves the others,
// whose next message is refused
func TestLiveRemoveCloses(t *testing.T) {
	bus := startBus(t)
	startService(t, bus)
	addr, ctlPath := startLive(t, bus)
	used, other := connect(t, addr), connect(t, addr)
	ctl := dialControl(t, ctlPath)
	ctl.must(t, map[string]any{"op": "add", "id": "g1", "talk": []string{svcName}, "own": []string{testApp + ".Live"}})
	wantErr(t, "the grant", echo(used, svcName), "")
	if r, err := used.RequestName(testApp+".Live", dbus.NameFlagDoNotQueue); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("RequestName under the grant: %v %v", r, err)
	}
	if err := busCallOn(other, "GetId"); err != nil {
		t.Fatal(err)
	}
	res := ctl.must(t, map[string]any{"op": "remove", "id": "g1"})
	if res.Closed != 1 {
		t.Errorf("Closed %d connections, want 1", res.Closed)
	}
	if err := echo(used, svcName); err == nil {
		t.Error("A connection that used the set still calls")
	}
	watcher := connect(t, bus)
	waitFor(t, func() bool { return !hasOwner(t, watcher, testApp+".Live") })
	wantErr(t, "another client after the revoke", echo(other, svcName), errServiceUnknown)
	if err := busCallOn(other, "GetId"); err != nil {
		t.Errorf("A client that didn't use the set lost its connection: %v", err)
	}
}

// The broker's connection closing drops every live set and ends the connections that used them
func TestLiveBrokerGone(t *testing.T) {
	bus := startBus(t)
	startService(t, bus)
	addr, ctlPath := startLive(t, bus)
	c := connect(t, addr)
	ctl := dialControl(t, ctlPath)
	ctl.must(t, map[string]any{"op": "add", "id": "g1", "talk": []string{svcName}})
	wantErr(t, "the grant", echo(c, svcName), "")
	ctl.conn.Close()
	waitFor(t, func() bool { return echo(c, svcName) != nil })
	c2 := connect(t, addr)
	wantErr(t, "after the broker left", echo(c2, svcName), errServiceUnknown)
	// Another broker may connect then, and its sets apply
	ctl2 := dialControl(t, ctlPath)
	ctl2.must(t, map[string]any{"op": "add", "id": "g1", "talk": []string{svcName}})
	wantErr(t, "the next broker's grant", echo(c2, svcName), "")
}

// Live call and broadcast rules don't pass the name's every broadcast, as static ones do
func TestLiveBroadcastStrict(t *testing.T) {
	bus := startBus(t)
	svc := startService(t, bus)
	addr, ctlPath := startLive(t, bus)
	c := connect(t, addr)
	ctl := dialControl(t, ctlPath)
	ctl.must(t, map[string]any{"op": "add", "id": "g1",
		"call": []string{svcName + "=" + svcIface + ".Echo"}, "broadcast": []string{svcName + "=" + svcIface + ".Wanted"}})
	got := signals(c, 500*time.Millisecond)
	if err := c.AddMatchSignal(dbus.WithMatchInterface(svcIface)); err != nil {
		t.Fatal(err)
	}
	wantErr(t, "the call rule", echo(c, svcName), "")
	for _, m := range []string{"Wanted", "Other"} {
		if err := svc.Emit("/org/test", svcIface+"."+m); err != nil {
			t.Fatal(err)
		}
	}
	var names []string
	for _, s := range got() {
		names = append(names, s.Name)
	}
	if strings.Join(names, " ") != svcIface+".Wanted" {
		t.Errorf("Broadcasts under live rules: %v, want only Wanted", names)
	}
}

// What a set may not hold, and the bounds
func TestLiveSetRefused(t *testing.T) {
	bus := startBus(t)
	_, ctlPath := startLive(t, bus)
	ctl := dialControl(t, ctlPath)
	many := make([]string, maxSetEntries+1)
	for i := range many {
		many[i] = "org.test.N" + string(rune('a'+i%26)) + strings.Repeat("x", i/26)
	}
	for _, req := range []map[string]any{
		{"op": "add", "id": "a", "talk": []string{busName}},
		{"op": "add", "id": "a", "talk": []string{"org.freedesktop.*"}},
		{"op": "add", "id": "a", "call": []string{"org.*=*"}},
		{"op": "add", "id": "a", "talk": []string{"org.freedesktop.DBus.*"}},
		{"op": "add", "id": "a"},
		{"op": "add", "id": "a", "see": many},
		{"op": "add", "id": "bad id", "talk": []string{svcName}},
		{"op": "add", "id": "a", "talk": []string{"notaname"}},
		{"op": "remove", "id": "nosuch"},
		{"op": "eavesdrop", "id": "a"},
		// The bus's policy (internal/dbuspolicy), as the module and the broker check it
		{"op": "add", "id": "a", "call": []string{"ca.desrt.dconf=ca.desrt.dconf.Writer.Change"}},
		{"op": "add", "id": "a", "own": []string{"org.freedesktop.StatusNotifierWatcher"}},
		{"op": "add", "id": "a", "call": []string{"org.freedesktop.portal.Desktop=org.freedesktop.portal.RemoteDesktop.Start"}},
		{"op": "add", "id": "a", "talk": []string{"org.example.*"}},
	} {
		if res := ctl.do(t, req); res == nil || res.OK || res.Error == "" {
			t.Errorf("%v: %+v", req, res)
		}
	}
	ctl.must(t, map[string]any{"op": "add", "id": "a", "talk": []string{svcName}})
	if res := ctl.do(t, map[string]any{"op": "add", "id": "a", "talk": []string{svcName}}); res == nil || res.OK {
		t.Errorf("The same id twice: %+v", res)
	}
	for i := 1; i < maxLiveSets; i++ {
		ctl.must(t, map[string]any{"op": "add", "id": "s" + string(rune('a'+i%26)) + strings.Repeat("x", i/26), "talk": []string{svcName}})
	}
	if res := ctl.do(t, map[string]any{"op": "add", "id": "over", "talk": []string{svcName}}); res == nil || res.OK {
		t.Errorf("Past %d sets: %+v", maxLiveSets, res)
	}
	// A line past the cap ends the connection
	if _, err := ctl.conn.Write([]byte(strings.Repeat("x", maxControlLine+1) + "\n")); err == nil {
		if line, _ := ctl.r.ReadBytes('\n'); !strings.Contains(string(line), "too long") {
			t.Errorf("An overlong line: %q", line)
		}
	}
}

// A peer of another uid, and a second broker while one is connected, are refused
func TestLiveControlPeer(t *testing.T) {
	bus := startBus(t)
	_, ctlPath := startLive(t, bus)
	other := filepath.Join(t.TempDir(), "other")
	var p *Proxy
	startProxyWith(t, bus, func(pp *Proxy) { p = pp; pp.uid = os.Getuid() + 1 })
	l, err := listen(other)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { p.serveControl(l); close(done) }()
	t.Cleanup(func() { l.Close(); <-done })
	if res := dialControl(t, other).do(t, map[string]any{"op": "add", "id": "a", "talk": []string{svcName}}); res != nil {
		t.Errorf("A peer of another uid got %+v", res)
	}
	ctl := dialControl(t, ctlPath)
	ctl.must(t, map[string]any{"op": "add", "id": "a", "talk": []string{svcName}})
	second := dialControl(t, ctlPath)
	if res := second.do(t, map[string]any{"op": "remove", "id": "a"}); res != nil {
		t.Errorf("A second broker got %+v", res)
	}
	ctl.must(t, map[string]any{"op": "remove", "id": "a"})
}
