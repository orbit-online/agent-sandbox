package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
)

// libdbus's client (dbus-send) through the proxy
func TestLibdbusClient(t *testing.T) {
	bus := startBus(t)
	startService(t, bus)
	addr := startProxy(t, bus, "--talk="+svcName)
	out, err := exec.Command("dbus-send", "--bus="+addr, "--print-reply", "--dest="+svcName, "/org/test",
		svcIface+".Echo", "string:from-libdbus").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "from-libdbus") {
		t.Errorf("dbus-send: %v %s", err, out)
	}
}

func hexUID(uid int) string { return hex.EncodeToString([]byte(strconv.Itoa(uid))) }

// sd-bus's way: EXTERNAL without an initial response, everything up to the first message in one write
func TestPipelinedSASL(t *testing.T) {
	bus := startBus(t)
	conn := dialRaw(t, startProxy(t, bus))
	hello, err := wire.Encode(busCall("Hello"), 1)
	if err != nil {
		t.Fatal(err)
	}
	conn.Write(append([]byte("\x00AUTH EXTERNAL\r\nDATA\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n"), hello...))
	r := wire.NewReader(conn, nil)
	for _, want := range []string{"DATA", "OK ", "AGREE_UNIX_FD"} {
		line, err := r.ReadLine()
		if err != nil || !strings.HasPrefix(line, want) {
			t.Fatalf("Got %q (%v), want %q", line, err, want)
		}
	}
	m, err := r.ReadMessage()
	if err != nil {
		t.Fatalf("Hello reply: %v", err)
	}
	if id, _ := arg0(m); !strings.HasPrefix(id, ":") {
		t.Errorf("Hello reply %v", m.Message)
	}
}

// After authenticating, a message longer than the limit ends the connection before the proxy reads it
func TestMessageBounds(t *testing.T) {
	bus := startBus(t)
	addr := startProxy(t, bus)
	auth := "\x00AUTH EXTERNAL " + hexUID(os.Getuid()) + "\r\nBEGIN\r\n"
	long := make([]byte, 16)
	copy(long, "l\x01\x00\x01")
	binary.LittleEndian.PutUint32(long[4:], wire.MaxMessageSize)
	binary.LittleEndian.PutUint32(long[8:], 1)
	binary.LittleEndian.PutUint32(long[12:], 8)

	for name, msg := range map[string][]byte{"too long": long} {
		conn := dialRaw(t, addr)
		conn.Write([]byte(auth))
		conn.Write(msg)
		r := wire.NewReader(conn, nil)
		if line, _ := r.ReadLine(); !strings.HasPrefix(line, "OK ") {
			t.Fatalf("%s: auth: %q", name, line)
		}
		_, err := r.ReadMessage()
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("%s: the connection is still open: %v", name, err)
		}
	}
}
