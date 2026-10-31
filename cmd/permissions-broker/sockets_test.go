package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestShare(t *testing.T) {
	dir := t.TempDir()
	cmd := ownNs(t, dir)
	pid := cmd.Process.Pid
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := testBroker(t)
	b.sb = &sandbox{pid: pid, pidfd: fd}
	b.cfg.SandboxGrantDir = dir

	if err := b.shareFrom(os.Getpid()); err == nil {
		t.Error("Shared for a client outside the sandbox's mount namespace")
	}
	if err := b.shareFrom(pid); err != nil {
		t.Fatal(err)
	}
	info, _ := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	for _, line := range strings.Split(string(info), "\n") {
		f := strings.Fields(line)
		if len(f) > 6 && f[4] == dir {
			if !strings.Contains(line, " shared:") {
				t.Errorf("Not shared: %s", line)
			}
			return
		}
	}
	t.Errorf("No mount at %s:\n%s", dir, info)
}

func TestControlFromHostOnly(t *testing.T) {
	b, _ := testBroker(t)
	cmd := ownNs(t, t.TempDir())
	if res := b.handleControl(nil, cmd.Process.Pid, request{Op: "state"}); res.Error == "" {
		t.Error("control.sock answered a peer in another user namespace")
	}
	if res := b.handleControl(nil, os.Getpid(), request{Op: "state"}); res.Error != "" {
		t.Errorf("control.sock refused the host: %s", res.Error)
	}
}

// Through the sockets, as the MCP server and the window talk to the broker
func TestSockets(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "B")
	b.caps[c.id()] = c
	if err := os.MkdirAll(b.cfg.GrantDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(b.cfg.GrantDir, "request.sock")
	ln, err := listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go b.serveOn(ln, b.handleRequest)

	watch, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer watch.Close()
	_ = json.NewEncoder(watch).Encode(request{Op: "watch"})
	time.Sleep(50 * time.Millisecond)

	res, err := callBroker(sock, req(c.id(), `{"path": "/a"}`, "PT1H"))
	if err != nil || res.Grant == nil || res.Credential == "" {
		t.Fatalf("request: %+v, %v", res, err)
	}
	list, err := callBroker(sock, request{Op: "list"})
	if err != nil || len(list.Capabilities) != 1 || len(list.Grants) != 1 {
		t.Errorf("list: %+v, %v", list, err)
	}
	if _, err := callBroker(sock, request{Op: "release", Grant: res.Grant.ID}); err != nil {
		t.Error(err)
	}
	_ = watch.SetReadDeadline(time.Now().Add(time.Second))
	events, _ := io.ReadAll(watch)
	for _, want := range []string{`"pending"`, `"granted"`, `"ended"`} {
		if !strings.Contains(string(events), want) {
			t.Errorf("No %s event in:\n%s", want, events)
		}
	}
}

// The sandbox holding every connection it can get leaves control.sock to the host, and request.sock frees up as idle
// clients time out
func TestServeLimits(t *testing.T) {
	old := readTimeout
	readTimeout = 500 * time.Millisecond
	t.Cleanup(func() { readTimeout = old })
	b, _ := testBroker(t)
	dir := t.TempDir()
	reqSock, ctlSock := filepath.Join(dir, "request.sock"), filepath.Join(dir, "control.sock")
	reqLn, err := listen(reqSock)
	if err != nil {
		t.Fatal(err)
	}
	defer reqLn.Close()
	ctlLn, err := listen(ctlSock)
	if err != nil {
		t.Fatal(err)
	}
	defer ctlLn.Close()
	go b.serveOn(reqLn, b.handleRequest)
	go b.serveOn(ctlLn, b.handleControl)

	var idle []net.Conn
	for range maxConns + 10 {
		c, err := net.Dial("unix", reqSock)
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, c)
	}
	defer func() {
		for _, c := range idle {
			c.Close()
		}
	}()
	if _, err := callBroker(ctlSock, request{Op: "state"}); err != nil {
		t.Errorf("control.sock with request.sock full: %v", err)
	}
	time.Sleep(readTimeout + 200*time.Millisecond)
	if _, err := callBroker(reqSock, request{Op: "list"}); err != nil {
		t.Errorf("request.sock after the idle clients timed out: %v", err)
	}
	// An oversized request is cut off, not read whole
	c, err := net.Dial("unix", reqSock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go func() {
		_, _ = c.Write([]byte(`{"op": "list", "reason": "` + strings.Repeat("x", 2*maxRequest) + `"}`))
	}()
	var res response
	if err := json.NewDecoder(c).Decode(&res); err != nil || res.Error == "" {
		t.Errorf("Oversized request answered %+v, %v", res, err)
	}
}
