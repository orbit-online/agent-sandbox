package main

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/hostcmd"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/notify"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
)

// The consent for a declaration shaped like agent-sandbox-plugins' windows-vm: the notification's summary and body,
// word for word, and the lines the window gets in state, keys and type sharing theirs
func TestConsentText(t *testing.T) {
	b, f := testBroker(t, "deny")
	arg := func(decl string) map[string]json.RawMessage {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(decl), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	run := []string{"/bin/true"}
	c := &capability{Name: "windows-vm", Type: "command", Description: "Control a running Windows VM",
		Title: "control the Windows VM", Exclusive: true,
		Params: map[string]json.RawMessage{"vm": json.RawMessage(`{"type": "string", "enum": ["windows-vm"],
			"description": "the VM, by its launcher's name"}`)},
		Commands: map[string]*hostcmd.Command{
			"screenshot": {Description: "Take a PNG screenshot", Consent: "Take screenshots", Run: run,
				Result: "image/png", Arguments: arg(`{"screen": {"type": "integer", "minimum": 0, "maximum": 15,
					"description": "the screen"}}`)},
			"click": {Description: "Click with the mouse", Consent: "Click on the screen", Run: run,
				Arguments: arg(`{"x": {"type": "integer", "minimum": 0, "maximum": 7679, "description": "pixels"}}`)},
			"keys": {Description: "Press keys together", Consent: "Use the keyboard and type any text", Run: run,
				Arguments: arg(`{"keys": {"type": "array", "maxItems": 8, "description": "QEMU key names",
					"items": {"type": "string", "enum": ["ctrl", "alt"], "description": "a QEMU key name"}}}`)},
			"type": {Description: "Type text", Consent: "Use the keyboard and type any text", Run: run,
				Arguments: arg(`{"text": {"type": "string", "multiline": true, "maxLength": 4096,
					"description": "any text"}}`)},
			"exec": {Description: "Run PowerShell", Consent: "Run any PowerShell, up to system level",
				Run: run, Arguments: arg(`{"script": {"type": "string", "multiline": true, "maxLength": 65536,
					"description": "any PowerShell"}}`)},
		}}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	b.caps[c.id()] = c
	r := req(c.id(), `{"vm": "windows-vm"}`, "PT10M")
	r.Reason = "To check the installer"
	_, _ = b.request(peerAt(t, os.Getpid()), r)
	if f.count() != 1 {
		t.Fatalf("Asked %d times", f.count())
	}
	summary, body := notify.Text(f.asked[0], "")
	if want := `Claude wants to control the Windows VM "windows-vm" for 10 min`; summary != want {
		t.Errorf("summary = %q\nwant      %q", summary, want)
	}
	if want := "On \"windows-vm\" for 10 min: ⚠ Run any PowerShell, up to system level; ⚠ Use the keyboard and type any text; " +
		"Click on the screen; Take screenshots\nClaude's reason, in its own words: \"To check the installer\""; body != want {
		t.Errorf("body = %q\nwant   %q", body, want)
	}
	info := b.listCapabilities()[0]
	want := []hostcmd.ConsentItem{
		{Consent: "Run any PowerShell, up to system level", Commands: []string{"exec"}, Unrestricted: true},
		{Consent: "Use the keyboard and type any text", Commands: []string{"keys", "type"}, Unrestricted: true},
		{Consent: "Click on the screen", Commands: []string{"click"}},
		{Consent: "Take screenshots", Commands: []string{"screenshot"}},
	}
	if info.Title != "control the Windows VM" || !reflect.DeepEqual(info.Consent, want) {
		t.Errorf("state: %q %+v", info.Title, info.Consent)
	}
}

// A bounding value the sandbox chose as long as a parameter may be pushes the lease out of a summary a server cuts:
// the body's first line has the value whole and the lease ahead of what the grant covers
func TestConsentTextLongValue(t *testing.T) {
	b, f := testBroker(t, "deny")
	c := testCap(t, "command")
	b.caps[c.id()] = c
	long := strings.Repeat("a", maxParam-1) + "z"
	r := req(c.id(), `{"path": "`+long+`"}`, "PT10M")
	_, _ = b.request(peerAt(t, os.Getpid()), r)
	if f.count() != 1 {
		t.Fatalf("Asked %d times", f.count())
	}
	_, body := notify.Text(f.asked[0], "")
	if want := `On "` + long + `" for 10 min: Print what it gets` + "\n"; !strings.HasPrefix(body, want) {
		t.Errorf("body = %q", body)
	}
}

// A bounding value the sandbox chose with a line separator, a right-to-left override and a zero-width space: escaped
// wherever the consent shows it, the summary, the body and the window's heading in state, so it can't start a line of
// its own, turn the text around or hide a character
func TestConsentTextInvisibleRunes(t *testing.T) {
	b, f := testBroker(t, "options")
	c := testCap(t, "command")
	b.caps[c.id()] = c
	seen := make(chan *pending, 1)
	go func() {
		for {
			var asked *pending
			b.mu.Lock()
			for _, p := range b.pending {
				if p.Options {
					asked = p
				}
			}
			b.mu.Unlock()
			if asked != nil {
				seen <- asked
				_ = b.answer(wire.Request{Pending: asked.ID})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	_, _ = b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "x\u2028, for this call only:\u202e\u200by", "ro": true}`,
		"PT10M"))
	p := <-seen
	quoted := `path "x\u2028, for this call only:\u202e\u200by", ro true`
	summary, body := notify.Text(f.asked[0], "")
	if want := "Claude wants to use the test thing " + quoted + " for 10 min"; summary != want {
		t.Errorf("summary = %q", summary)
	}
	if want := "On " + quoted + " for 10 min: Print what it gets\n"; !strings.HasPrefix(body, want) {
		t.Errorf("body = %q", body)
	}
	if p.Bounds != quoted {
		t.Errorf("state's bounds = %q", p.Bounds)
	}
	for _, s := range []string{summary, body, p.Summary, p.Bounds} {
		if strings.ContainsAny(s, "\u2028\u202e\u200b") {
			t.Errorf("Raw in %q", s)
		}
	}
}
