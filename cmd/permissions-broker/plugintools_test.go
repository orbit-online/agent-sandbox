package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestPluginToolsRaw(t *testing.T) {
	fakeSystemd(t)
	b, _ := testBroker(t, "allow")
	c := testCap(t, "A")
	c.Plugin, c.Tools = "vm", true
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
	plugin := rawPlugin(t)
	server := newMCPServer(sock, nil, func() {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tools := newPluginTools(sock, func(string) (net.Conn, error) { return net.Dial("unix", plugin) }, nil)
	tools.server = server
	go tools.follow(ctx)
	if _, err := callBroker(sock, req(c.id(), `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	st, ct := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	for range 50 {
		out, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "vm_echo", Arguments: map[string]any{"text": "hi"}})
		if err == nil && !out.IsError && len(out.Content) > 0 && out.Content[0].(*mcp.TextContent).Text == "echo: hi" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Error("No echo through a plugin speaking bare MCP")
}

// A type A plugin's tools appear in the MCP server while its grant lives, calls reach the plugin, and they go with
// the grant, each change announced with list_changed
func TestPluginTools(t *testing.T) {
	fakeSystemd(t)
	b, _ := testBroker(t, "allow", "allow")
	c := testCap(t, "A")
	c.Plugin, c.Tools = "vm", true
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

	plugin := fakePlugin(t)
	server := newMCPServer(sock, nil, func() {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The grant's socket is wherever systemd would have put it; the fake plugin stands in for it
	tools := newPluginTools(sock, func(string) (net.Conn, error) { return net.Dial("unix", plugin) }, nil)
	tools.server = server
	go tools.follow(ctx)

	changed := make(chan struct{}, 8)
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, &mcp.ClientOptions{
		ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) { changed <- struct{}{} },
	})
	st, ct := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	has := func() bool {
		res, err := cs.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(res.Tools, func(t *mcp.Tool) bool { return t.Name == "vm_echo" })
	}
	waitChanged := func(what string) {
		select {
		case <-changed:
		case <-time.After(5 * time.Second):
			t.Fatalf("No list_changed %s", what)
		}
	}

	if has() {
		t.Fatal("A plugin tool before its grant")
	}
	res, err := callBroker(sock, req(c.id(), `{}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	waitChanged("for the grant")
	if !has() {
		t.Fatal("No plugin tool while its grant lives")
	}
	out, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "vm_echo", Arguments: map[string]any{"text": "hi"}})
	if err != nil || len(out.Content) == 0 || out.Content[0].(*mcp.TextContent).Text != "echo: hi" {
		t.Fatalf("Forwarded call: %+v, %v", out, err)
	}
	for len(changed) > 0 {
		<-changed
	}
	// A second grant of it (another VM) offers its tools under names of their own
	res2, err := callBroker(sock, req(c.id(), `{"path": "/other"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	waitChanged("for the second grant")
	second := "vm_echo_" + res2.Grant.ID[:7]
	list, _ := cs.ListTools(ctx, nil)
	if !slices.ContainsFunc(list.Tools, func(t *mcp.Tool) bool { return t.Name == second }) || !has() {
		t.Errorf("Tools with two grants: %v", list.Tools)
	}
	for len(changed) > 0 {
		<-changed
	}
	if _, err := callBroker(sock, request{Op: "release", Grant: res.Grant.ID}); err != nil {
		t.Fatal(err)
	}
	waitChanged("for the release")
	if has() {
		t.Error("The plugin tool outlived its grant")
	}
	list, _ = cs.ListTools(ctx, nil)
	if !slices.ContainsFunc(list.Tools, func(t *mcp.Tool) bool { return t.Name == second }) {
		t.Error("Releasing one grant took the other's tools")
	}
}

func TestObjectSchema(t *testing.T) {
	if !objectSchema(map[string]any{"type": "object"}) || objectSchema(map[string]any{"type": "string"}) || objectSchema(nil) ||
		objectSchema(map[string]any{"type": []string{"object"}}) || objectSchema(map[string]any{"properties": map[string]any{}}) {
		t.Error("objectSchema")
	}
}

// A plugin that accepts and never answers holds up only its own grant's tools, and its grant is tried again once
// the offer times out: when the plugin answers, its tools come
func TestPluginHangs(t *testing.T) {
	oldOffer, oldSync := offerTimeout, syncEvery
	offerTimeout, syncEvery = 300*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { offerTimeout, syncEvery = oldOffer, oldSync })
	hung, healthy := rawPluginWith(t, true), rawPluginWith(t, false, "echo")
	var first string
	recovered := false
	var mu sync.Mutex
	dial := func(path string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if first == "" {
			first = path
		}
		if path == first && !recovered {
			return net.Dial("unix", hung)
		}
		return net.Dial("unix", healthy)
	}
	_, sock, cs := pluginHarness(t, dial, "allow", "allow")
	if _, err := callBroker(sock, req("vm/thing", `{"path": "/hung"}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := callBroker(sock, req("vm/thing", `{"path": "/healthy"}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	names := waitTools(t, cs, func(n []string) bool {
		return slices.ContainsFunc(n, func(s string) bool { return strings.HasPrefix(s, "vm_echo") })
	})
	if !slices.ContainsFunc(names, func(s string) bool { return strings.HasPrefix(s, "vm_echo") }) {
		t.Errorf("A hanging plugin held up another grant's tools: %v", names)
	}
	mu.Lock()
	recovered = true
	mu.Unlock()
	echoes := func(n []string) bool {
		return len(slices.DeleteFunc(slices.Clone(n), func(s string) bool { return !strings.HasPrefix(s, "vm_echo") })) == 2
	}
	if names := waitTools(t, cs, echoes); !echoes(names) {
		t.Errorf("The plugin that hung isn't tried again: %v", names)
	}
}

// An offer that failed is tried again, without a grant event
func TestPluginRetry(t *testing.T) {
	oldSync := syncEvery
	syncEvery = 200 * time.Millisecond
	t.Cleanup(func() { syncEvery = oldSync })
	plugin := rawPlugin(t)
	var mu sync.Mutex
	failed := false
	dial := func(string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if !failed {
			failed = true
			return nil, errors.New("not up yet")
		}
		return net.Dial("unix", plugin)
	}
	_, sock, cs := pluginHarness(t, dial, "allow")
	if _, err := callBroker(sock, req("vm/thing", `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	if names := waitTools(t, cs, func(n []string) bool { return slices.Contains(n, "vm_echo") }); !slices.Contains(names, "vm_echo") {
		t.Errorf("A failed offer wasn't tried again: %v", names)
	}
}

// Two of a grant's tools that come out under one name: the second gets the grant's id, and neither replaces the other
func TestPluginNameCollision(t *testing.T) {
	plugin := rawPluginWith(t, false, "a.b", "a_b")
	_, sock, cs := pluginHarness(t, func(string) (net.Conn, error) { return net.Dial("unix", plugin) }, "allow")
	res, err := callBroker(sock, req("vm/thing", `{}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	second := "vm_a_b_" + res.Grant.ID[:7]
	names := waitTools(t, cs, func(n []string) bool { return slices.Contains(n, second) })
	for name, want := range map[string]string{"vm_a_b": "a.b: x", second: "a_b: x"} {
		out, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: map[string]any{"text": "x"}})
		if err != nil || out.IsError || out.Content[0].(*mcp.TextContent).Text != want {
			t.Errorf("%s calls %+v, %v; want %q (tools %v)", name, out, err, want, names)
		}
	}
}
