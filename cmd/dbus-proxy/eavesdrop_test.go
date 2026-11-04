package main

import (
	"testing"
)

// BecomeMonitor and eavesdropping match rules are refused; the bus itself allows them
func TestEavesdropRefused(t *testing.T) {
	bus := startBus(t)
	const rule = "type='method_call',eavesdrop=true"
	direct := connect(t, bus)
	if err := busCallOn(direct, "AddMatch", rule); err != nil {
		t.Fatalf("Control: the bus refused an eavesdropping match rule: %v", err)
	}
	c := connect(t, startProxy(t, bus))
	wantErr(t, "eavesdropping AddMatch", busCallOn(c, "AddMatch", rule), errAccessDenied)
	wantErr(t, "spaced eavesdropping AddMatch", busCallOn(c, "AddMatch", "eavesdrop \t= 'true'"), errAccessDenied)
	if err := busCallOn(c, "AddMatch", "type='signal'"); err != nil {
		t.Errorf("Plain AddMatch refused: %v", err)
	}
	_, err := call(c, busName, busPath, "org.freedesktop.DBus.Monitoring.BecomeMonitor", []string{}, uint32(0))
	wantErr(t, "BecomeMonitor", err, errAccessDenied)
	// The control for BecomeMonitor last: the connection becomes a monitor
	_, err = call(direct, busName, busPath, "org.freedesktop.DBus.Monitoring.BecomeMonitor", []string{}, uint32(0))
	if err != nil {
		t.Errorf("Control: the bus refused BecomeMonitor: %v", err)
	}
}
