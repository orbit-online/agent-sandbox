package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type echoIn struct {
	Text string `json:"text"`
}

// fakePlugin serves MCP on a unix socket, as a service plugin with tools does on its grant socket: one tool, echo
func fakePlugin(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plugin.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	server := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "Echoes."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo: " + in.Text}}}, nil, nil
		})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				ss, err := server.Connect(context.Background(), &mcp.IOTransport{Reader: conn, Writer: conn}, nil)
				if err == nil {
					_ = ss.Wait()
				}
			}()
		}
	}()
	return path
}

// rawPlugin answers MCP by hand, as the VM test's plugin does: the bare minimum of the protocol, one tool, echo
func rawPlugin(t *testing.T) string {
	t.Helper()
	return rawPluginWith(t, false, "echo")
}

// rawPluginWith is rawPlugin with tools of the given names, all echoing, or with hang one that accepts connections
// and never answers, as a plugin socket systemd accepts on while the plugin is stuck
func rawPluginWith(t *testing.T, hang bool, names ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "raw.sock")
	ln, err := net.Listen("unix", path)
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
			go func() {
				defer conn.Close()
				if hang {
					io.Copy(io.Discard, conn)
					return
				}
				sc := bufio.NewScanner(conn)
				for sc.Scan() {
					var msg struct {
						ID     json.RawMessage `json:"id"`
						Method string          `json:"method"`
						Params struct {
							ProtocolVersion string         `json:"protocolVersion"`
							Name            string         `json:"name"`
							Arguments       map[string]any `json:"arguments"`
						} `json:"params"`
					}
					if json.Unmarshal(sc.Bytes(), &msg) != nil || msg.ID == nil {
						continue
					}
					var result any
					switch msg.Method {
					case "initialize":
						result = map[string]any{"protocolVersion": msg.Params.ProtocolVersion,
							"capabilities": map[string]any{"tools": map[string]any{}},
							"serverInfo":   map[string]any{"name": "raw", "version": "0"}}
					case "tools/list":
						var tools []any
						for _, name := range names {
							tools = append(tools, map[string]any{"name": name, "description": "Echoes " + name + ".",
								"inputSchema": map[string]any{"type": "object",
									"properties": map[string]any{"text": map[string]any{"type": "string"}}}})
						}
						result = map[string]any{"tools": tools}
					case "tools/call":
						result = map[string]any{"content": []any{map[string]any{"type": "text",
							"text": fmt.Sprint(msg.Params.Name, ": ", msg.Params.Arguments["text"])}}}
					default:
						out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": msg.ID,
							"error": map[string]any{"code": -32601, "message": msg.Method}})
						conn.Write(append(out, '\n'))
						continue
					}
					out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": result})
					conn.Write(append(out, '\n'))
				}
			}()
		}
	}()
	return path
}

// pluginHarness is a broker serving request.sock with a service capability with tools, and the MCP server following
// it, its plugin connections dialled by dial. Returns a client session of the MCP server and the broker's socket
func pluginHarness(t *testing.T, dial func(string) (net.Conn, error), answers ...string) (*broker, string, *mcp.ClientSession) {
	t.Helper()
	fakeSystemd(t)
	b, _ := testBroker(t, answers...)
	c := testCap(t, "service")
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
	t.Cleanup(func() { ln.Close() })
	go b.serveOn(ln, b.handleRequest)
	server := newMCPServer(sock, nil, func() {})
	tools := newPluginTools(sock, dial, nil)
	tools.server = server
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go tools.follow(ctx)
	st, ct := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return b, sock, cs
}

// toolNames polls the MCP server's tools until want holds, for up to three seconds
func waitTools(t *testing.T, cs *mcp.ClientSession, want func([]string) bool) []string {
	t.Helper()
	var names []string
	for range 60 {
		res, err := cs.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		names = names[:0]
		for _, tool := range res.Tools {
			names = append(names, tool.Name)
		}
		if want(names) {
			return names
		}
		time.Sleep(50 * time.Millisecond)
	}
	return names
}
