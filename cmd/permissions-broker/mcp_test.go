package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestNudge(t *testing.T) {
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
	if _, err := callBroker(sock, req(c.id(), `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	n := &nudger{socket: sock, now: func() time.Time { return now }}
	if note := n.note(); note != "" {
		t.Errorf("Nudged about a fresh grant: %s", note)
	}
	now = now.Add(nudgeAfter + time.Minute)
	if note := n.note(); !strings.Contains(note, "the test thing") {
		t.Errorf("No nudge after %s: %q", nudgeAfter, note)
	}
	if note := n.note(); note != "" {
		t.Errorf("Nudged again right away: %s", note)
	}
}

// The nudge reaches tool results
func TestNudgeAdds(t *testing.T) {
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
	if _, err := callBroker(sock, req(c.id(), `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	n := &nudger{socket: sock, now: func() time.Time { return time.Now().Add(nudgeAfter + time.Minute) }}
	res, _, _ := n.add(&mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "result"}}}, nil, nil)
	if len(res.Content) != 2 || !strings.Contains(res.Content[1].(*mcp.TextContent).Text, "release") {
		t.Errorf("No nudge in the result: %+v", res.Content)
	}
	var none *nudger
	if res, _, _ := none.add(&mcp.CallToolResult{}, nil, nil); res == nil {
		t.Error("A nil nudger dropped the result")
	}
}
