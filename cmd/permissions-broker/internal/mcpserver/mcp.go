// Package mcpserver is the sandbox's permissions MCP server: a client of the broker's request.sock, with tools to list,
// request, release and see grants, and one per host command
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
)

type requestIn struct {
	Capability string         `json:"capability" jsonschema:"the capability's id, as list names it"`
	Params     map[string]any `json:"params,omitempty" jsonschema:"the capability's parameters, as list describes them"`
	Reason     string         `json:"reason" jsonschema:"why you need it, in a sentence: the user sees it next to what you ask for"`
	Lease      string         `json:"lease,omitempty" jsonschema:"how long: a duration such as PT1H (the default) or lock (until the screen locks)"`
}

type releaseIn struct {
	Grant string `json:"grant" jsonschema:"the grant's id, from request or status"`
}

var implementation = &mcp.Implementation{Name: "permissions", Version: "0.1.0"}

// Run serves MCP on stdin and stdout, a client of the broker at socket. commandsPath names the host commands'
// declarations, which it offers as tools
func Run(socket, commandsPath string) error {
	cmds, err := readCommands(commandsPath)
	if err != nil {
		return err
	}
	return NewServer(socket, cmds).Run(context.Background(), &mcp.StdioTransport{})
}

// NewServer is the MCP server, its tools fixed from its start: Claude Code doesn't pick up tools added later. Its own,
// and one per host command
func NewServer(socket string, cmds []Commands) *mcp.Server {
	n := &nudger{socket: socket, now: time.Now}
	server := newServer(socket, n)
	addCommandTools(server, socket, n, cmds)
	return server
}

func newServer(socket string, n *nudger) *mcp.Server {
	server := mcp.NewServer(implementation, &mcp.ServerOptions{
		Instructions: "Access outside the sandbox that the user grants while it runs: folders, host sockets, " +
			"and host commands, the tools named <capability>_<command>, which ask the user for a grant of their " +
			"capability unless one covers the call. list shows what can be asked for. request asks the user, who " +
			"sees what you ask for and your reason, and waits for their answer. A host socket's grant lets anything " +
			"in the sandbox connect at its address under /run/permissions/sockets, which list names; without one " +
			"a connection is closed at once. A grant of port lets the host user reach a port you listen on, at the " +
			"addresses the grant names. Ask only for what the task needs, for as short as it needs, and " +
			"release a grant as soon as you're done with it. A grant belongs to the whole sandbox, not to the " +
			"session that asked: every session can use it, and any can release it. Grants with lease standing " +
			"come from the sandbox's configuration and are there from the start.",
	})
	call := func(req wire.Request) (reply, error) { return callBroker(socket, req) }

	mcp.AddTool(server, &mcp.Tool{Name: "list", Description: "What can be granted, with its parameters, and what is."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			res, err := call(wire.Request{Op: "list"})
			if err != nil {
				return nil, nil, err
			}
			return n.add(jsonResult(map[string]any{"capabilities": res.Capabilities, "granted": res.Grants}))
		})
	mcp.AddTool(server, &mcp.Tool{Name: "request", Description: "Ask the user for a grant. Waits for their " +
		"answer, up to two minutes, longer if they open the Permissions window on it. Returns the grant: for a " +
		"host socket the address to connect to, for a folder where it's mounted, for a port the addresses the host " +
		"reaches it at. A host command capability can be asked for ahead of its calls, with the values of its " +
		"bounding arguments as params."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in requestIn) (*mcp.CallToolResult, any, error) {
			params, _ := json.Marshal(in.Params)
			res, err := call(wire.Request{Op: "request", Capability: in.Capability, Params: params, Reason: in.Reason,
				Lease: in.Lease})
			if err != nil {
				return nil, nil, err
			}
			return n.add(jsonResult(map[string]any{"grant": res.Grant}))
		})
	mcp.AddTool(server, &mcp.Tool{Name: "release", Description: "Give a grant back once you're done with it. " +
		"It ends for the whole sandbox."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in releaseIn) (*mcp.CallToolResult, any, error) {
			if _, err := call(wire.Request{Op: "release", Grant: in.Grant}); err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Released"}}}, nil, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "status", Description: "The sandbox's live grants, usable from the " +
		"whole sandbox."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			res, err := call(wire.Request{Op: "status"})
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

// reply is what the server reads of the broker's answers. What it passes on to Claude it keeps as the broker sent it
type reply struct {
	Capabilities json.RawMessage `json:"capabilities"`
	Grant        json.RawMessage `json:"grant"`
	Grants       json.RawMessage `json:"grants"`
	// What a host command printed: text, or Data of the image type Mime
	Output string `json:"output"`
	Mime   string `json:"mime"`
	Data   []byte `json:"data"`
}

// heldGrant is what the nudge says of a grant
type heldGrant struct {
	ID      string    `json:"id"`
	Summary string    `json:"summary"`
	Granted time.Time `json:"granted"`
}

func callBroker(socket string, req wire.Request) (reply, error) {
	var res reply
	if err := wire.Call(socket, req, &res); err != nil {
		return reply{}, err
	}
	return res, nil
}

// How old grants get before tool results remind Claude to release them, and how often they do
var (
	nudgeAfter = 15 * time.Minute
	nudgeEvery = 10 * time.Minute
)

// nudger adds a reminder to tool results while the sandbox has held grants a while. By their age: the daemon can't
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
	status, err := callBroker(n.socket, wire.Request{Op: "status"})
	if err != nil {
		return ""
	}
	var grants []heldGrant
	if len(status.Grants) > 0 {
		if err := json.Unmarshal(status.Grants, &grants); err != nil {
			return ""
		}
	}
	var held []string
	for _, g := range grants {
		if now.Sub(g.Granted) >= nudgeAfter {
			held = append(held, fmt.Sprintf("%s (grant %s, since %s)", g.Summary, g.ID, g.Granted.Format("15:04")))
		}
	}
	if len(held) == 0 {
		return ""
	}
	n.last = now
	return "The sandbox still holds: " + strings.Join(held, "; ") +
		". Release what you no longer need with the permissions server's release."
}
