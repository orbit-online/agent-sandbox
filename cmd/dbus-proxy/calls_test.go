package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// Call rules: a method on a path, an interface's methods on a subtree, anything anywhere
func TestCallRules(t *testing.T) {
	bus := startBus(t)
	startService(t, bus)
	const unknownIface = "org.freedesktop.DBus.Error.UnknownInterface"
	for _, tc := range []struct {
		rule   string
		path   dbus.ObjectPath
		method string
		want   string
	}{
		{"org.test.Iface.Echo@/org/test", "/org/test", "Echo", ""},
		{"org.test.Iface.Echo@/org/test", "/org/test", "Other", errAccessDenied},
		{"org.test.Iface.Echo@/org/test", "/other", "Echo", errAccessDenied},
		{"org.test.Iface.Echo@/org/test", "/org/test/sub/obj", "Echo", errAccessDenied},
		{"org.test.Iface.*@/org/test/sub/*", "/org/test/sub/obj", "Other", ""},
		{"org.test.Iface.*@/org/test/sub/*", "/org/test/sub", "Other", unknownIface},
		{"org.test.Iface.*@/org/test/sub/*", "/org/test/subway", "Other", errAccessDenied},
		{"org.test.Iface.*@/org/test/sub/*", "/org/test", "Other", errAccessDenied},
		{"org.test.Iface.*@/*", "/other", "Other", ""},
		{"*", "/other", "Echo", ""},
		{"org.test.Other.*", "/org/test", "Echo", errAccessDenied},
	} {
		c := connect(t, startProxy(t, bus, ruled(svcName, "call", tc.rule)))
		_, err := call(c, svcName, tc.path, svcIface+"."+tc.method, "x")
		wantErr(t, tc.rule+" "+string(tc.path)+" "+tc.method, err, tc.want)
	}
}

// A broadcast rule lets the broadcasts it matches reach a client that asked, talk and own all of them; without a rule,
// with see or with a call rule alone, none (xdg-dbus-proxy 0.1.9, CVE-2026-93676)
func TestBroadcast(t *testing.T) {
	bus := startBus(t)
	svc := startService(t, bus)
	for _, tc := range []struct {
		args []string
		path dbus.ObjectPath
		want bool
	}{
		{nil, "/org/test", false},
		{[]string{policy(svcName, "see")}, "/org/test", false},
		{[]string{ruled(svcName, "broadcast", "org.test.Iface.Sig@/org/test")}, "/org/test", true},
		{[]string{ruled(svcName, "broadcast", "org.test.Iface.Sig@/org/test")}, "/other", false},
		{[]string{ruled(svcName, "call", "*")}, "/org/test", false},
		{[]string{policy(svcName, "talk")}, "/other", true},
		{[]string{policy(svcName, "own")}, "/other", true},
	} {
		c := connect(t, startProxy(t, bus, tc.args...))
		got := signals(c, 300*time.Millisecond)
		if err := c.AddMatchSignal(dbus.WithMatchInterface(svcIface)); err != nil {
			t.Fatal(err)
		}
		if err := svc.Emit(tc.path, svcIface+".Sig", "v"); err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, s := range got() {
			if s.Name == svcIface+".Sig" {
				n++
			}
		}
		if (n > 0) != tc.want {
			t.Errorf("%v on %s: got %d signals, want them: %v", tc.args, tc.path, n, tc.want)
		}
	}
}

// A version the config gives is answered by the proxy, whose service exports no properties; another interface's goes
// on to the service by the call rule, another path's is refused
func TestVersion(t *testing.T) {
	bus := startBus(t)
	startService(t, bus)
	c := connect(t, startProxy(t, bus, fmt.Sprintf(`%q: {"call": ["org.freedesktop.DBus.Properties.Get@/org/test"],
		"versions": {"org.test.Iface@/org/test": 7}}`, svcName)))
	const get = "org.freedesktop.DBus.Properties.Get"
	r, err := call(c, svcName, "/org/test", get, svcIface, "version")
	var v dbus.Variant
	if err != nil || r.Store(&v) != nil || v.Value() != uint32(7) {
		t.Errorf("The version: %v %v", v, err)
	}
	if _, err := call(c, svcName, "/org/test", get, "org.test.Other", "version"); err == nil || errName(err) == errAccessDenied {
		t.Errorf("Another interface's version: %v", err)
	}
	_, err = call(c, svcName, "/other", get, svcIface, "version")
	wantErr(t, "Another path's version", err, errAccessDenied)
}
