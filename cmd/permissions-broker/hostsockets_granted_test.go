package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/hostcmd"
)

// Host sockets with grantedBy: no grant of their own, opened by a grant of a host command capability for the same
// bounding values (docs/permissions.md, Host sockets)

// vmCommands is a host command capability vmctl bounded by vm, as nixos-windows-vm's windows-vm is
func vmCommands(t *testing.T, extra ...string) *capability {
	t.Helper()
	params := map[string]json.RawMessage{"vm": json.RawMessage(`{"type": "string", "description": "the VM"}`)}
	for _, k := range extra {
		params[k] = json.RawMessage(`{"type": "string", "description": "d"}`)
	}
	c := &capability{Name: "vmctl", Type: "command", Description: "control a VM", Title: "control the VM",
		Exclusive: true, Params: params,
		Commands: map[string]*hostcmd.Command{"run": {Description: "run it", Consent: "Run it", Run: []string{"true"}}}}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSocketGrantedByDeclarations(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	glob := json.RawMessage(`{"type": "string", "description": "the VM", "instances": "/srv/vms/*.sock"}`)
	byVM := map[string]json.RawMessage{"vm": glob}
	for name, tc := range map[string]struct {
		sc     socketConfig
		extra  []string
		refuse string
	}{
		"its commands' bounding": {sc: socketConfig{Bounding: byVM, GrantedBy: "vmctl"}},
		"no such capability":     {sc: socketConfig{Bounding: byVM, GrantedBy: "nothing"}, refuse: "no host command capability"},
		"another socket":         {sc: socketConfig{Bounding: byVM, GrantedBy: "agent"}, refuse: "no host command capability"},
		"more bounding there":    {sc: socketConfig{Bounding: byVM, GrantedBy: "vmctl"}, extra: []string{"mode"}, refuse: "aren't the socket's"},
		"another name":           {sc: socketConfig{Bounding: map[string]json.RawMessage{"name": glob}, GrantedBy: "vmctl"}, refuse: "aren't the socket's"},
		"a path, bounded there":  {sc: socketConfig{Path: "/srv/one.sock", GrantedBy: "vmctl"}, refuse: "aren't the socket's"},
	} {
		caps := map[string]*capability{"vmctl": vmCommands(t, tc.extra...)}
		if err := loadSockets([]socketConfig{{Name: "agent", Description: "d", Path: "/srv/agent.sock"}}, caps); err != nil {
			t.Fatal(err)
		}
		tc.sc.Name, tc.sc.Description = "console", "a VM's console"
		err := loadSockets([]socketConfig{tc.sc}, caps)
		switch {
		case tc.refuse == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case tc.refuse == "" && caps["console"].grantor != caps["vmctl"]:
			t.Errorf("%s: no grantor", name)
		case tc.refuse != "" && (err == nil || !strings.Contains(err.Error(), tc.refuse)):
			t.Errorf("%s: %v, want refused for %q", name, err, tc.refuse)
		}
	}
}

// grantedSocket gives b vmctl and a host socket vm opened by its grants, whose instances are echo servers
func grantedSocket(t *testing.T, b *broker, names ...string) (sock, cmds *capability) {
	t.Helper()
	cmds = vmCommands(t)
	b.caps[cmds.id()] = cmds
	sock = testSocket(t, b, names...)
	sock.GrantedBy = cmds.id()
	if err := sock.resolveGrantor(b.caps); err != nil {
		t.Fatal(err)
	}
	b.syncSockets(sock)
	return sock, cmds
}

// A connection is spliced under a grant of the commands for its instance alone, and closed with that grant's end
func TestSocketGrantedBySplice(t *testing.T) {
	b, f := testBroker(t, "allow", "allow")
	_, cmds := grantedSocket(t, b, "a", "b")
	a, bAddr := filepath.Join(socketsDir, "vm", "a"), filepath.Join(socketsDir, "vm", "b")
	if _, line := echoes(t, b, a); line != "" {
		t.Fatalf("Spliced without a grant: %q", line)
	}
	p := peerAt(t, os.Getpid())
	gb, err := b.request(p, req(cmds.id(), `{"vm": "b"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	if _, line := echoes(t, b, a); line != "" {
		t.Errorf("Spliced under the grant of another instance: %q", line)
	}
	held, line := echoes(t, b, bAddr)
	if line != "ping\n" {
		t.Fatalf("Under the commands' grant: %q", line)
	}
	if f.count() != 1 {
		t.Errorf("Asked %d times", f.count())
	}
	if _, err := b.revoke(gb.ID); err != nil {
		t.Fatal(err)
	}
	if !closed(held) {
		t.Error("The commands' revoke left the socket's connection open")
	}
	if _, line := echoes(t, b, bAddr); line != "" {
		t.Errorf("Spliced after the revoke: %q", line)
	}
}

// Asking for the socket asks for the commands, for the same instance: the answer is their grant, with the socket's
// address, and a second request is covered by it
func TestSocketGrantedByRequest(t *testing.T) {
	b, f := testBroker(t, "allow")
	sock, cmds := grantedSocket(t, b, "a")
	p := peerAt(t, os.Getpid())
	res := b.handleRequest(nil, p, req(sock.id(), `{"vm": "a"}`, "PT1H"))
	if res.Error != "" || res.Grant == nil {
		t.Fatalf("Request of the socket: %+v", res)
	}
	if res.Grant.Capability != cmds.id() || res.Grant.Socket != "/run/permissions/sockets/vm/a" {
		t.Errorf("Grant %+v, want vmctl's with the socket's address", res.Grant)
	}
	if len(f.asked) != 1 || f.asked[0].Title != cmds.Title {
		t.Errorf("Asked %+v, want the consent of vmctl", f.asked)
	}
	if _, line := echoes(t, b, filepath.Join(socketsDir, "vm", "a")); line != "ping\n" {
		t.Errorf("Under the grant the request got: %q", line)
	}
	again := b.handleRequest(nil, p, req(sock.id(), `{"vm": "a"}`, "PT1H"))
	if again.Grant == nil || again.Grant.ID != res.Grant.ID || f.count() != 1 {
		t.Errorf("Asked again: %+v, asked %d times", again, f.count())
	}
	// The socket's own parameters are the commands': another key is refused before asking
	bad := b.handleRequest(nil, p, req(sock.id(), `{"vm": "a", "mode": "x"}`, "PT1H"))
	if bad.Refused != refParams || f.count() != 1 {
		t.Errorf("Another key: %+v, asked %d times", bad, f.count())
	}
}

// A standing grant of such a socket would open nothing: the config is refused, naming the commands
func TestSocketGrantedByStanding(t *testing.T) {
	b, _ := testBroker(t)
	sock, cmds := grantedSocket(t, b, "a")
	_, err := checkStanding([]standingConfig{{Capability: sock.id(), Params: json.RawMessage(`{"vm": "a"}`)}}, b.caps)
	if err == nil || !strings.Contains(err.Error(), cmds.id()) {
		t.Errorf("Standing grant of the socket: %v", err)
	}
	if _, err := checkStanding([]standingConfig{{Capability: cmds.id(), Params: json.RawMessage(`{"vm": "a"}`)}}, b.caps); err != nil {
		t.Errorf("Standing grant of the commands: %v", err)
	}
}

// list says which grant opens the socket
func TestSocketGrantedByList(t *testing.T) {
	b, _ := testBroker(t)
	sock, cmds := grantedSocket(t, b, "a")
	for _, i := range b.listCapabilities() {
		if i.ID == sock.id() && i.GrantedBy != cmds.id() {
			t.Errorf("list: %+v", i)
		}
		if i.ID == cmds.id() && i.GrantedBy != "" {
			t.Errorf("list: %+v", i)
		}
	}
}
