package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type requestIn struct {
	Capability string         `json:"capability" jsonschema:"the capability's id, as list names it"`
	Params     map[string]any `json:"params,omitempty" jsonschema:"the capability's parameters, as list describes them"`
	Reason     string         `json:"reason" jsonschema:"why you need it, in a sentence: the user sees it next to what you ask for"`
	Lease      string         `json:"lease,omitempty" jsonschema:"how long: session (the default; until this session ends), lock (until the screen locks) or a duration such as PT1H"`
}

type releaseIn struct {
	Grant string `json:"grant" jsonschema:"the grant's id, from request or status"`
}

var implementation = &mcp.Implementation{Name: "permissions", Version: "0.1.0"}

func runMCP(socket, commandsPath string) error {
	cmds, err := readCommands(commandsPath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	n := &nudger{socket: socket, now: time.Now}
	plugins := newPluginTools(socket, dialUnix, n)
	// Plugin tools once the session is initialized: their list_changed mustn't come before
	var once sync.Once
	plugins.server = newMCPServer(socket, n, func() { once.Do(func() { go plugins.follow(ctx) }) })
	addCommandTools(plugins.server, socket, n, cmds)
	return plugins.server.Run(ctx, &mcp.StdioTransport{})
}

// newMCPServer is the MCP server with its own tools; plugin tools come and go with their grants (pluginTools), from
// when the session is initialized
func newMCPServer(socket string, n *nudger, initialized func()) *mcp.Server {
	server := mcp.NewServer(implementation, &mcp.ServerOptions{
		InitializedHandler: func(context.Context, *mcp.InitializedRequest) { initialized() },
		Instructions: "Access outside the sandbox that the user grants while it runs: folders, devices, services, " +
			"and host commands, the tools named <capability>_<command>, which ask the user for a grant of their " +
			"capability unless one covers the call. list shows what can be asked for. request asks the user, who sees what you ask for and your " +
			"reason, and waits for their answer. Ask only for what the task needs, for as short as it needs, and " +
			"release a grant as soon as you're done with it. A grant belongs to the whole sandbox, not to the session " +
			"that asked: every session can use it, and a session lease only ends with the session. Grants with lease " +
			"standing come from the sandbox's configuration and are there from the start. Some grants bring " +
			"tools of their own, named after their plugin, which are listed while the grant lives.",
	})
	call := func(req request) (response, error) { return callBroker(socket, req) }

	mcp.AddTool(server, &mcp.Tool{Name: "list", Description: "What can be granted, with its parameters, and what is."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			res, err := call(request{Op: "list"})
			if err != nil {
				return nil, nil, err
			}
			return n.add(jsonResult(map[string]any{"capabilities": res.Capabilities, "granted": res.Grants}))
		})
	mcp.AddTool(server, &mcp.Tool{Name: "request", Description: "Ask the user for a grant. Waits for their " +
		"answer, up to two minutes, longer if they open the Permissions window on it. Returns the grant: a socket to " +
		"connect to or a path. A host command capability can be asked for ahead of its calls, with the values of its " +
		"bounding arguments as params."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in requestIn) (*mcp.CallToolResult, any, error) {
			params, _ := json.Marshal(in.Params)
			res, err := call(request{Op: "request", Capability: in.Capability, Params: params, Reason: in.Reason,
				Lease: in.Lease})
			if err != nil {
				return nil, nil, err
			}
			return n.add(jsonResult(map[string]any{"grant": res.Grant}))
		})
	mcp.AddTool(server, &mcp.Tool{Name: "release", Description: "Give a grant back once you're done with it. " +
		"It ends once no session that was given it still holds it."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in releaseIn) (*mcp.CallToolResult, any, error) {
			if _, err := call(request{Op: "release", Grant: in.Grant}); err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Released"}}}, nil, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "status", Description: "The grants this session was given and hasn't " +
		"released. Every live grant is usable from the whole sandbox; list shows them all."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			res, err := call(request{Op: "status"})
			if err != nil {
				return nil, nil, err
			}
			return n.add(jsonResult(map[string]any{"granted": res.Grants}))
		})
	return server
}

func jsonResult(v any) (*mcp.CallToolResult, any, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(data)}}}, nil, nil
}

// callBroker sends one request and reads the answer. A request waits for the user: two minutes, or ten with the
// window open
func callBroker(socket string, req request) (response, error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return response{}, fmt.Errorf("%w: %w", errNotRunning, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(askTimeout + optionsTimeout + time.Minute))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return response{}, err
	}
	var res response
	if err := json.NewDecoder(conn).Decode(&res); err != nil {
		return response{}, fmt.Errorf("Read the broker's answer: %w", err)
	}
	if res.Error != "" {
		return response{}, errors.New(strings.TrimSpace(res.Error))
	}
	return res, nil
}

var errNotRunning = errors.New("The permissions broker isn't running")

// How long a session holds grants before its tool results remind it to release them, and how often they do
var (
	nudgeAfter = 15 * time.Minute
	nudgeEvery = 10 * time.Minute
)

// nudger adds a reminder to tool results while the session has held grants a while. By their age: the daemon can't
// tell whether a socket or a folder is still in use. Channels, which could push it instead, need --channels when
// Claude Code starts, which the app doesn't pass
type nudger struct {
	socket string
	now    func() time.Time
	mu     sync.Mutex
	last   time.Time
}

func (n *nudger) add(res *mcp.CallToolResult, out any, err error) (*mcp.CallToolResult, any, error) {
	if n == nil || err != nil || res == nil {
		return res, out, err
	}
	if note := n.note(); note != "" {
		res.Content = append(res.Content, &mcp.TextContent{Text: note})
	}
	return res, out, err
}

func (n *nudger) note() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	if now.Sub(n.last) < nudgeEvery {
		return ""
	}
	status, err := callBroker(n.socket, request{Op: "status"})
	if err != nil {
		return ""
	}
	var held []string
	for _, g := range status.Grants {
		if now.Sub(g.Granted) >= nudgeAfter {
			held = append(held, fmt.Sprintf("%s (grant %s, since %s)", g.Summary, g.ID, g.Granted.Format("15:04")))
		}
	}
	if len(held) == 0 {
		return ""
	}
	n.last = now
	return "This session still holds: " + strings.Join(held, "; ") +
		". Release what you no longer need with the permissions server's release."
}

func dialUnix(path string) (net.Conn, error) { return net.Dial("unix", path) }
