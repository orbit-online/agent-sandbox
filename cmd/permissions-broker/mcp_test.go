package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mcpserver"
)

// The MCP server, internal/mcpserver, against the broker

// mcpSession is a client of the MCP server for the broker at sock, with the host commands of cfgs as the module
// declares them
func mcpSession(t *testing.T, sock string, cfgs ...commandConfig) *mcp.ClientSession {
	t.Helper()
	data, err := json.Marshal(cfgs)
	if err != nil {
		t.Fatal(err)
	}
	var decls []mcpserver.Commands
	if err := json.Unmarshal(data, &decls); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	if _, err := mcpserver.NewServer(sock, decls).Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// The MCP server lists every host command from its start, and a call runs it
func TestCommandTools(t *testing.T) {
	b, c, _ := commandBroker(t, "cat", "allow")
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
	ctx := context.Background()
	cs := mcpSession(t, sock, commandConfig{Name: c.Name, Description: c.Description, Bounding: c.Params,
		Commands: c.Commands})
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var tool *mcp.Tool
	for _, tl := range tools.Tools {
		if tl.Name == "thing_run" {
			tool = tl
		}
	}
	schema, _ := json.Marshal(tool.InputSchema)
	if tool == nil || !strings.Contains(string(schema), `"required":["path","reason","ro"]`) ||
		!strings.Contains(string(schema), `"lease"`) {
		t.Fatalf("Tool %+v, schema %s", tool, schema)
	}
	out, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "thing_run",
		Arguments: map[string]any{"path": "/a", "ro": true, "reason": "testing"}})
	if err != nil || out.IsError {
		t.Fatalf("Call: %+v, %v", out, err)
	}
	var in callInput
	if err := json.Unmarshal([]byte(out.Content[0].(*mcp.TextContent).Text), &in); err != nil ||
		string(in.Bounding) != `{"path":"/a","ro":true}` || string(in.Arguments) != `{}` {
		t.Errorf("Ran with %+v, %v", in, err)
	}
	out, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "thing_run", Arguments: map[string]any{"reason": "x",
		"path": "/b", "lease": "forever"}})
	if err != nil || !out.IsError {
		t.Errorf("A bad lease: %+v, %v", out, err)
	}
}

// A call made before the daemon listens waits for it
func TestCallWaitsForBroker(t *testing.T) {
	b, c, _ := commandBroker(t, "cat", "allow")
	if err := os.MkdirAll(b.cfg.GrantDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(b.cfg.GrantDir, "request.sock")
	go func() {
		time.Sleep(time.Second)
		ln, err := listen(sock)
		if err != nil {
			t.Error(err)
			return
		}
		t.Cleanup(func() { ln.Close() })
		b.serveOn(ln, b.handleRequest)
	}()
	cs := mcpSession(t, sock, commandConfig{Name: c.Name, Bounding: c.Params, Commands: c.Commands})
	out, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "thing_run",
		Arguments: map[string]any{"reason": "testing"}})
	if err != nil || out.IsError {
		t.Errorf("Call before the daemon listened: %+v, %v", out, err)
	}
}

// A grant held a while brings the nudge into the MCP server's tool results, from the broker's status
func TestNudgeLive(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "command")
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
	res, err := callBroker(sock, req(c.id(), `{}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.grants[res.Grant.ID].Granted = time.Now().Add(-time.Hour)
	b.mu.Unlock()
	out, err := mcpSession(t, sock).CallTool(context.Background(), &mcp.CallToolParams{Name: "status"})
	if err != nil || len(out.Content) != 2 || !strings.Contains(out.Content[1].(*mcp.TextContent).Text, "the test thing") {
		t.Errorf("No nudge in status: %+v, %v", out, err)
	}
}
