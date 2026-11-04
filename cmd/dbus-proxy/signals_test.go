package main

import (
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// NameOwnerChanged reaches the client for names it may see, and for their owner's unique name when it leaves
func TestNameOwnerChanged(t *testing.T) {
	bus := startBus(t)
	c := connect(t, startProxy(t, bus, "--see=org.test.Seen"))
	got := signals(c, 500*time.Millisecond)
	if err := c.AddMatchSignal(dbus.WithMatchSender(busName), dbus.WithMatchMember("NameOwnerChanged")); err != nil {
		t.Fatal(err)
	}
	peer, err := dbus.Dial(bus)
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Auth(nil); err != nil {
		t.Fatal(err)
	}
	if err := peer.Hello(); err != nil {
		t.Fatal(err)
	}
	unique := peer.Names()[0]
	for _, n := range []string{"org.test.Hidden", "org.test.Seen"} {
		if _, err := peer.RequestName(n, dbus.NameFlagDoNotQueue); err != nil {
			t.Fatal(err)
		}
	}
	peer.Close()
	seen := map[string]int{}
	for _, s := range got() {
		if s.Name == busIface+".NameOwnerChanged" && len(s.Body) == 3 {
			seen[s.Body[0].(string)]++
		}
	}
	if seen["org.test.Hidden"] != 0 {
		t.Errorf("NameOwnerChanged of a hidden name reached the client")
	}
	if seen["org.test.Seen"] != 2 {
		t.Errorf("Got %d NameOwnerChanged of the seen name, want 2 (taken and left)", seen["org.test.Seen"])
	}
	if seen[unique] != 1 {
		t.Errorf("Got %d NameOwnerChanged of the seen name's owner leaving, want 1", seen[unique])
	}
}
