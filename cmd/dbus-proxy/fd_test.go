package main

import (
	"os"
	"testing"

	"github.com/godbus/dbus/v5"
)

// File descriptors pass both ways: one the client sends, one in the service's reply
func TestFDPassing(t *testing.T) {
	bus := startBus(t)
	startService(t, bus)
	c := connect(t, startProxy(t, bus, policy(svcName, "talk")))
	if !c.SupportsUnixFDs() {
		t.Fatal("The proxy didn't agree to pass file descriptors")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("from client"))
	w.Close()
	reply, err := call(c, svcName, "/org/test", svcIface+".ReadFD", dbus.UnixFD(r.Fd()))
	r.Close()
	var s string
	if err != nil || reply.Store(&s) != nil || s != "from client" {
		t.Errorf("Service read %q from the client's fd: %v", s, err)
	}

	reply, err = call(c, svcName, "/org/test", svcIface+".GiveFD")
	var fd dbus.UnixFD
	if err != nil || reply.Store(&fd) != nil {
		t.Fatalf("GiveFD: %v", err)
	}
	f := os.NewFile(uintptr(fd), "given")
	defer f.Close()
	b := make([]byte, 64)
	n, _ := f.Read(b)
	if string(b[:n]) != "from service" {
		t.Errorf("Client read %q from the service's fd", b[:n])
	}
}
