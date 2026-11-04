package main

import (
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

// A name without a rule is hidden: not listed, no owner, a call to it unknown
func TestHidden(t *testing.T) {
	bus := startBus(t)
	svc := startService(t, bus)
	c := connect(t, startProxy(t, bus))
	if hasOwner(t, c, svcName) {
		t.Error("NameHasOwner true for a hidden name")
	}
	if strings.Contains(listNames(t, c), " "+svcName+" ") {
		t.Error("ListNames lists a hidden name")
	}
	_, err := call(c, svcName, "/org/test", svcIface+".Echo", "x")
	wantErr(t, "call to a hidden name", err, errServiceUnknown)
	_, err = call(c, svc.Names()[0], "/org/test", svcIface+".Echo", "x")
	wantErr(t, "call to a hidden unique name", err, errNameHasNoOwner)
	err = busCallOn(c, "GetNameOwner", svcName)
	wantErr(t, "GetNameOwner of a hidden name", err, errNameHasNoOwner)
}

// --see makes a name visible but no more: a call to it is denied rather than unknown
func TestSee(t *testing.T) {
	bus := startBus(t)
	startService(t, bus)
	c := connect(t, startProxy(t, bus, "--see="+svcName))
	if !hasOwner(t, c, svcName) {
		t.Error("NameHasOwner false for a name the client may see")
	}
	if !strings.Contains(listNames(t, c), " "+svcName+" ") {
		t.Error("ListNames doesn't list a name the client may see")
	}
	if err := busCallOn(c, "GetNameOwner", svcName); err != nil {
		t.Errorf("GetNameOwner: %v", err)
	}
	_, err := call(c, svcName, "/org/test", svcIface+".Echo", "x")
	wantErr(t, "call to a seen name", err, errAccessDenied)
}

// --talk lets any call through, and its reply back; by the owner's unique name too
func TestTalk(t *testing.T) {
	bus := startBus(t)
	svc := startService(t, bus)
	c := connect(t, startProxy(t, bus, "--talk="+svcName))
	var s string
	for _, dest := range []string{svcName, svc.Names()[0]} {
		for _, p := range []dbus.ObjectPath{"/org/test", "/other"} {
			r, err := call(c, dest, p, svcIface+".Echo", "hi")
			if err != nil {
				t.Fatalf("Call %s %s: %v", dest, p, err)
			}
			if r.Store(&s); s != "hi" {
				t.Errorf("Reply %q", s)
			}
		}
	}
	// TALK isn't OWN
	err := busCallOn(c, "RequestName", svcName+".Mine", uint32(0))
	wantErr(t, "RequestName without own", err, errServiceUnknown)
}

// A name under a wildcard, owned before the client connects: the proxy finds its owner through ListNames
func TestTalkWildcard(t *testing.T) {
	bus := startBus(t)
	svc := startService(t, bus, "org.test.Svc.Sub")
	c := connect(t, startProxy(t, bus, "--talk=org.test.Svc.*"))
	for _, dest := range []string{"org.test.Svc.Sub", svc.Names()[0]} {
		if _, err := call(c, dest, "/org/test", svcIface+".Echo", "hi"); err != nil {
			t.Errorf("Call %s: %v", dest, err)
		}
	}
	_, err := call(c, "org.test.Other", "/org/test", svcIface+".Echo", "hi")
	wantErr(t, "call outside the wildcard", err, errServiceUnknown)
}

// --own lets the client take a name, and only that one
func TestOwn(t *testing.T) {
	bus := startBus(t)
	c := connect(t, startProxy(t, bus, "--own=org.test.Mine", "--see=org.test.Seen"))
	r, err := c.RequestName("org.test.Mine", dbus.NameFlagDoNotQueue)
	if err != nil || r != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("RequestName of an owned name: %v %v", r, err)
	}
	_, err = c.RequestName("org.test.Seen", dbus.NameFlagDoNotQueue)
	wantErr(t, "RequestName of a seen name", err, errAccessDenied)
	_, err = c.RequestName("org.test.Other", dbus.NameFlagDoNotQueue)
	wantErr(t, "RequestName of a hidden name", err, errServiceUnknown)
	// Another client on the bus reaches it there
	other := connect(t, bus)
	if _, err := call(other, "org.test.Mine", "/", "org.freedesktop.DBus.Peer.Ping"); err != nil {
		t.Errorf("Ping the owned name from the bus: %v", err)
	}
}
