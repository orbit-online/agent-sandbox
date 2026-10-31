package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// pluginTools offers the tools of the service plugins that speak MCP on their grant sockets, while their grants live.
// It follows the broker's watch events, and syncs every so often besides, so an offer that failed is tried again.
// Adding and removing tools sends list_changed. Grants are the whole sandbox's, so are their tools: every session
// sees them
type pluginTools struct {
	server *mcp.Server
	socket string
	dial   func(path string) (net.Conn, error)

	nudge *nudger

	mu      sync.Mutex
	live    map[string]*grant   // the grants with tools, as of the last sync
	grants  map[string][]string // live grant id: the names of the tools offered for it
	pending map[string]bool     // grants being offered
}

func newPluginTools(socket string, dial func(string) (net.Conn, error), n *nudger) *pluginTools {
	return &pluginTools{socket: socket, dial: dial, nudge: n, live: map[string]*grant{}, grants: map[string][]string{},
		pending: map[string]bool{}}
}

// How long offering a grant's tools may take: the plugin may hang, and socket activation accepts the connection
// whether or not the plugin answers. And how often to sync without an event
var (
	offerTimeout = 10 * time.Second
	syncEvery    = 30 * time.Second
)

// follow keeps a watch stream on the broker open and syncs on every event, every syncEvery, and after reconnecting
func (p *pluginTools) follow(ctx context.Context) {
	tick := time.NewTicker(syncEvery)
	defer tick.Stop()
	for ctx.Err() == nil {
		conn, err := net.Dial("unix", p.socket)
		if err == nil {
			if _, err = conn.Write([]byte(`{"op": "watch"}` + "\n")); err == nil {
				events := make(chan struct{})
				go func() {
					sc := bufio.NewScanner(conn)
					for sc.Scan() {
						events <- struct{}{}
					}
					close(events)
				}()
				p.sync(ctx)
			watch:
				for {
					select {
					case _, ok := <-events:
						if !ok {
							break watch
						}
						p.sync(ctx)
					case <-tick.C:
						p.sync(ctx)
					case <-ctx.Done():
						break watch
					}
				}
			}
			conn.Close()
		}
		// The broker went: its grants with it
		p.apply(ctx, nil)
		time.Sleep(2 * time.Second)
	}
}

// sync offers the tools of the live grants whose capabilities have them, and withdraws the rest
func (p *pluginTools) sync(ctx context.Context) {
	res, err := callBroker(p.socket, request{Op: "list"})
	if err != nil {
		return
	}
	withTools := map[string]bool{}
	for _, c := range res.Capabilities {
		withTools[c.ID] = c.Tools
	}
	live := map[string]*grant{}
	for _, g := range res.Grants {
		if withTools[g.Capability] && g.Socket != "" {
			live[g.ID] = g
		}
	}
	p.apply(ctx, live)
}

// apply withdraws the tools of grants no longer live and starts offering those of new ones, each on its own, so a
// plugin that hangs holds up nothing else
func (p *pluginTools) apply(ctx context.Context, live map[string]*grant) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.live = live
	for id, names := range p.grants {
		if live[id] == nil {
			p.server.RemoveTools(names...)
			delete(p.grants, id)
		}
	}
	for id, g := range live {
		if _, offered := p.grants[id]; offered || p.pending[id] {
			continue
		}
		p.pending[id] = true
		go p.offer(ctx, g)
	}
}

var toolNameRe = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// offer lists a grant's plugin tools, then, if the grant still lives, offers each as <plugin>_<tool>, its calls
// forwarded to the plugin. A grant whose offer failed isn't recorded, so the next sync tries again
func (p *pluginTools) offer(ctx context.Context, g *grant) {
	ctx, cancel := context.WithTimeout(ctx, offerTimeout)
	defer cancel()
	tools, err := p.list(ctx, g.Socket)
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pending, g.ID)
	if err != nil {
		slog.Warn("Plugin tools", "grant", g.ID, "err", err)
		return
	}
	if p.live[g.ID] == nil {
		return
	}
	plugin, _, _ := strings.Cut(g.Capability, "/")
	var names []string
	taken := func(name string) bool { return p.offered(name) || slices.Contains(names, name) }
	for _, t := range tools {
		if !objectSchema(t.InputSchema) {
			slog.Warn("Plugin tool without an object schema", "grant", g.ID, "tool", t.Name)
			continue
		}
		name := toolNameRe.ReplaceAllString(plugin+"_"+t.Name, "_")
		if len(name) > 56 {
			name = name[:56]
		}
		// Another grant of the plugin offers it already (a second VM), or another of this grant's tools comes out the
		// same (a.b, a_b): this one carries the grant's id
		if taken(name) {
			name += "_" + g.ID[:7]
		}
		// Still taken: left out rather than put in another's place
		if taken(name) {
			slog.Warn("Plugin tool name taken", "grant", g.ID, "tool", t.Name, "as", name)
			continue
		}
		offered := *t
		offered.Name = name
		offered.Description = fmt.Sprintf("While %s is granted: %s", g.Summary, t.Description)
		original, socket := t.Name, g.Socket
		p.server.AddTool(&offered, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			res, err := p.forward(ctx, socket, original, req.Params.Arguments)
			res, _, err = p.nudge.add(res, nil, err)
			return res, err
		})
		names = append(names, name)
	}
	p.grants[g.ID] = names
}

// list lists a plugin's tools, every page
func (p *pluginTools) list(ctx context.Context, socket string) ([]*mcp.Tool, error) {
	cs, err := p.connect(ctx, socket)
	if err != nil {
		return nil, err
	}
	defer cs.Close()
	var tools []*mcp.Tool
	var cursor string
	for {
		page, err := cs.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, fmt.Errorf("List the plugin's tools: %w", err)
		}
		tools = append(tools, page.Tools...)
		if page.NextCursor == "" {
			return tools, nil
		}
		cursor = page.NextCursor
	}
}

// offered reports whether a live grant offers a tool of that name. Under p.mu
func (p *pluginTools) offered(name string) bool {
	for _, names := range p.grants {
		if slices.Contains(names, name) {
			return true
		}
	}
	return false
}

// forward calls a plugin's tool in a session of its own: socket activation may have started the plugin anew since
func (p *pluginTools) forward(ctx context.Context, socket, name string, args json.RawMessage) (*mcp.CallToolResult, error) {
	cs, err := p.connect(ctx, socket)
	if err != nil {
		return nil, err
	}
	defer cs.Close()
	return cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
}

func (p *pluginTools) connect(ctx context.Context, socket string) (*mcp.ClientSession, error) {
	conn, err := p.dial(socket)
	if err != nil {
		return nil, fmt.Errorf("Connect to the plugin: %w", err)
	}
	// The handshake's deadline is the caller's
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	cs, err := mcp.NewClient(implementation, nil).Connect(ctx, &mcp.IOTransport{Reader: conn, Writer: conn}, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("Start a session with the plugin: %w", err)
	}
	return cs, nil
}

// objectSchema reports whether a tool's input schema is an object, which the MCP server requires
func objectSchema(schema any) bool {
	data, err := json.Marshal(schema)
	if err != nil {
		return false
	}
	var s struct{ Type any }
	return json.Unmarshal(data, &s) == nil && s.Type == "object"
}
