package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/schema"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
)

// The host commands as MCP tools, from the declarations the module writes into the store: listed from the server's
// start, before the daemon may have found the sandbox. Claude Code doesn't pick up tools added later. The daemon
// validates every call against its own copy

// Commands is a host command capability as the module declares it, of which the server reads what makes its tools
type Commands struct {
	Name        string                     `json:"name"`
	Description string                     `json:"description"`
	Bounding    map[string]json.RawMessage `json:"bounding"`
	Commands    map[string]*Command        `json:"commands"`
}

// Command is one host command of a capability: its description and free arguments
type Command struct {
	Description string                     `json:"description"`
	Arguments   map[string]json.RawMessage `json:"arguments"`
}

// How long a call waits for the daemon to listen
var brokerWait = 30 * time.Second

func readCommands(path string) ([]Commands, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Read the host commands: %w", err)
	}
	var cfgs []Commands
	if err := json.Unmarshal(data, &cfgs); err != nil {
		return nil, fmt.Errorf("Parse the host commands %s: %w", path, err)
	}
	return cfgs, nil
}

// addCommandTools adds a tool <capability>_<command> per host command
func addCommandTools(server *mcp.Server, socket string, n *nudger, cfgs []Commands) {
	for _, cc := range cfgs {
		for _, name := range slices.Sorted(maps.Keys(cc.Commands)) {
			cmd := cc.Commands[name]
			server.AddTool(&mcp.Tool{Name: cc.Name + "_" + name, InputSchema: toolSchema(cc, cmd),
				Description: cmd.Description + ". Runs on the host under a grant of " + cc.Name + " (" + cc.Description +
					"), which covers all its commands" + boundBy(cc) + ": without one, the user is asked, and sees " +
					"your reason."},
				commandHandler(socket, n, cc, name))
		}
	}
}

func boundBy(cc Commands) string {
	if len(cc.Bounding) == 0 {
		return ""
	}
	return " for the same " + fmt.Sprint(slices.Sorted(maps.Keys(cc.Bounding)))
}

// toolSchema is a command's input schema: the capability's bounding arguments, the command's free ones, a reason and
// a lease, all required but the lease. The broker's own keywords go; a pattern matches the whole value
func toolSchema(cc Commands, cmd *Command) map[string]any {
	props := map[string]any{
		"reason": map[string]any{"type": "string", "description": "why you need it, in a sentence: the user sees it " +
			"when asked"},
		"lease": map[string]any{"type": "string", "description": "how long a grant asked for lasts: a duration such " +
			"as PT1H (the default), lock (until the screen locks), or once (this call only)"},
	}
	required := []string{"reason"}
	for _, m := range []map[string]json.RawMessage{cc.Bounding, cmd.Arguments} {
		for k, raw := range m {
			var s map[string]any
			_ = json.Unmarshal(raw, &s)
			for _, own := range []string{"opaque", "multiline", "instances"} {
				delete(s, own)
			}
			if p, ok := s["pattern"].(string); ok {
				s["pattern"] = "^(?:" + p + ")$"
			}
			props[k] = s
			required = append(required, k)
		}
	}
	slices.Sort(required)
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}

func commandHandler(socket string, n *nudger, cc Commands, name string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		in, err := schema.DecodeObject(req.Params.Arguments)
		if err != nil {
			return nil, fmt.Errorf("Arguments aren't an object: %w", err)
		}
		reason, _ := in["reason"].(string)
		lease, _ := in["lease"].(string)
		delete(in, "reason")
		delete(in, "lease")
		bounding := map[string]any{}
		for k := range cc.Bounding {
			if v, ok := in[k]; ok {
				bounding[k] = v
				delete(in, k)
			}
		}
		params, _ := json.Marshal(bounding)
		args, _ := json.Marshal(in)
		call := wire.Request{Op: "call", Capability: cc.Name, Command: name, Params: params, Arguments: args,
			Reason: reason, Lease: lease}
		res, err := callBroker(socket, call)
		// The app starts its MCP servers at once, maybe before the daemon found the sandbox and listens
		for wait := time.Now().Add(brokerWait); errors.Is(err, wire.ErrNotRunning) && time.Now().Before(wait); {
			time.Sleep(500 * time.Millisecond)
			res, err = callBroker(socket, call)
		}
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, nil
		}
		out := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: res.Output}}}
		if res.Mime != "" {
			out.Content = []mcp.Content{&mcp.ImageContent{Data: res.Data, MIMEType: res.Mime}}
		}
		out, _, err = n.add(out, nil, nil)
		return out, err
	}
}
