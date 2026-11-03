package mcpserver

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
)

// fakeBroker answers status on a socket of its own with a grant of the test thing, granted at granted. The broker's
// own answers reach the nudge in TestNudgeLive, in the broker's tests
func fakeBroker(t *testing.T, granted time.Time) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "request.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req wire.Request
			if err := json.NewDecoder(conn).Decode(&req); err == nil && req.Op == "status" {
				_ = json.NewEncoder(conn).Encode(map[string]any{"grants": []heldGrant{
					{ID: "0123456789abcdef", Summary: "the test thing", Granted: granted}}})
			} else {
				_ = json.NewEncoder(conn).Encode(map[string]any{"error": "not status"})
			}
			conn.Close()
		}
	}()
	return sock
}

func TestNudge(t *testing.T) {
	now := time.Now()
	sock := fakeBroker(t, now)
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
	sock := fakeBroker(t, time.Now())
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
