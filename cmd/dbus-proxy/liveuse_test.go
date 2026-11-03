package main

import (
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// Which connections a removal ends: each way a message can be judged under a live set marks the client, alone. And
// each direction takes the rules as they are when its message is judged

// ends adds set, runs use on a fresh client, removes the set and reports whether the client's connection ended
func ends(t *testing.T, set map[string]any, use func(c *dbus.Conn, svc *dbus.Conn)) bool {
	t.Helper()
	bus := startBus(t)
	svc := startService(t, bus)
	addr, ctlPath := startLive(t, bus, "--filter")
	c := connect(t, addr)
	ctl := dialControl(t, ctlPath)
	set["op"], set["id"] = "add", "g"
	ctl.must(t, set)
	use(c, svc)
	res := ctl.must(t, map[string]any{"op": "remove", "id": "g"})
	return res.Closed == 1
}

// A client that only received a broadcast under the set
func TestLiveUseReceived(t *testing.T) {
	if !ends(t, map[string]any{"broadcast": []string{svcName + "=" + svcIface + ".*"}}, func(c, svc *dbus.Conn) {
		got := signals(c, 500*time.Millisecond)
		if err := c.AddMatchSignal(dbus.WithMatchInterface(svcIface)); err != nil {
			t.Fatal(err)
		}
		if err := svc.Emit("/org/test", svcIface+".Wanted"); err != nil {
			t.Fatal(err)
		}
		if len(got()) != 1 {
			t.Fatal("The broadcast didn't reach the client")
		}
	}) {
		t.Error("A client that got a broadcast under the set kept its connection")
	}
}

// A client that only took a name under a live own: the revoke ends it, and the name with it. (The proxy's own match
// on the name's owner brings the client its NameOwnerChanged too, so TestLiveUseArgument has the first argument alone)
func TestLiveUseOwned(t *testing.T) {
	var watcher *dbus.Conn
	if !ends(t, map[string]any{"own": []string{testApp + ".Owned"}}, func(c, svc *dbus.Conn) {
		if r, err := c.RequestName(testApp+".Owned", dbus.NameFlagDoNotQueue); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
			t.Fatalf("RequestName under the set: %v %v", r, err)
		}
		watcher = svc
	}) {
		t.Error("A client that took a name under the set kept its connection")
	}
	waitFor(t, func() bool { return !hasOwner(t, watcher, testApp+".Owned") })
}

// A client that only asked who owns a name it sees under the set: the bus call's first argument is judged by it
func TestLiveUseArgument(t *testing.T) {
	if !ends(t, map[string]any{"see": []string{svcName}}, func(c, svc *dbus.Conn) {
		var owner string
		res, err := call(c, busName, busPath, busIface+".GetNameOwner", svcName)
		if err != nil {
			t.Fatal(err)
		}
		if res.Store(&owner); owner != svc.Names()[0] {
			t.Fatalf("GetNameOwner under the set: %q", owner)
		}
	}) {
		t.Error("A client that asked for a name's owner under the set kept its connection")
	}
}

// A client that only listed names, one of them visible under the set
func TestLiveUseListed(t *testing.T) {
	if !ends(t, map[string]any{"see": []string{svcName}}, func(c, _ *dbus.Conn) {
		if err := busCallOn(c, "GetId"); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(listNames(t, c), " "+svcName+" ") {
			t.Fatal("The name isn't listed under the set")
		}
	}) {
		t.Error("A client that listed a name under the set kept its connection")
	}
}

// A client that only got a NameOwnerChanged under the set, with no message of its own after the set was added: the
// bus's message takes the rules there are as it's judged
func TestLiveUseNameOwnerChanged(t *testing.T) {
	bus := startBus(t)
	addr, ctlPath := startLive(t, bus, "--filter")
	c := connect(t, addr)
	got := signals(c, 500*time.Millisecond)
	if err := c.AddMatchSignal(dbus.WithMatchSender(busName), dbus.WithMatchMember("NameOwnerChanged")); err != nil {
		t.Fatal(err)
	}
	ctl := dialControl(t, ctlPath)
	ctl.must(t, map[string]any{"op": "add", "id": "g", "see": []string{"org.test.Later"}})
	peer := connect(t, bus)
	if _, err := peer.RequestName("org.test.Later", dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, s := range got() {
		seen = seen || len(s.Body) == 3 && s.Body[0] == "org.test.Later"
	}
	if !seen {
		t.Fatal("NameOwnerChanged of a name the set lets the client see didn't reach it")
	}
	if res := ctl.must(t, map[string]any{"op": "remove", "id": "g"}); res.Closed != 1 {
		t.Error("A client that got NameOwnerChanged under the set kept its connection")
	}
}

// The client's own message takes the rules there are as it's judged: a set removed while the client's last judged
// message (a bus's, which didn't use it) still had it refuses the next call
func TestLiveClientRefresh(t *testing.T) {
	bus := startBus(t)
	startService(t, bus)
	addr, ctlPath := startLive(t, bus, "--filter", "--see=org.test.Seen")
	c := connect(t, addr)
	got := signals(c, 500*time.Millisecond)
	if err := c.AddMatchSignal(dbus.WithMatchSender(busName), dbus.WithMatchMember("NameOwnerChanged")); err != nil {
		t.Fatal(err)
	}
	ctl := dialControl(t, ctlPath)
	ctl.must(t, map[string]any{"op": "add", "id": "g", "talk": []string{svcName}})
	// A bus message judged with the set there, which doesn't use it
	peer := connect(t, bus)
	if _, err := peer.RequestName("org.test.Seen", dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	if len(got()) == 0 {
		t.Fatal("No NameOwnerChanged of the seen name")
	}
	ctl.must(t, map[string]any{"op": "remove", "id": "g"})
	wantErr(t, "a call after the removal", echo(c, svcName), errServiceUnknown)
}

// A set removed from a client that looked up its names but didn't use it: the client's next message stops the proxy
// watching them
func TestLiveRemoveMatch(t *testing.T) {
	bus := startBus(t)
	addr, ctlPath := startLive(t, bus, "--filter")
	c := connect(t, addr)
	monitor := connect(t, bus)
	if _, err := call(monitor, busName, busPath, "org.freedesktop.DBus.Monitoring.BecomeMonitor",
		[]string{"type='method_call',member='RemoveMatch'"}, uint32(0)); err != nil {
		t.Fatal(err)
	}
	removed := make(chan *dbus.Message, 16)
	monitor.Eavesdrop(removed)
	ctl := dialControl(t, ctlPath)
	ctl.must(t, map[string]any{"op": "add", "id": "g", "see": []string{"org.test.Watched"}})
	if err := busCallOn(c, "GetId"); err != nil {
		t.Fatal(err)
	}
	ctl.must(t, map[string]any{"op": "remove", "id": "g"})
	if err := busCallOn(c, "GetId"); err != nil {
		t.Fatal(err)
	}
	want := ownerMatch("org.test.Watched", false)
	for deadline := time.After(3 * time.Second); ; {
		select {
		case m := <-removed:
			if len(m.Body) == 1 && m.Body[0] == want {
				return
			}
		case <-deadline:
			t.Fatal("The proxy didn't remove its match rule for the removed set's name")
		}
	}
}
