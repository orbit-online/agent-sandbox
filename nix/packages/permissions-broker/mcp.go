package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
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

func runMCP(socket string) error {
	server := mcp.NewServer(&mcp.Implementation{Name: "permissions", Version: "0.1.0"}, &mcp.ServerOptions{
		Instructions: "Access outside the sandbox that the user grants while it runs: folders, devices, services, " +
			"credentials. list shows what can be asked for. request asks the user, who sees what you ask for and your " +
			"reason, and waits for their answer. Ask only for what the task needs, for as short as it needs, and " +
			"release a grant as soon as you're done with it.",
	})
	call := func(req request) (response, error) { return callBroker(socket, req) }

	mcp.AddTool(server, &mcp.Tool{Name: "list", Description: "What can be granted, with its parameters, and what is."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			res, err := call(request{Op: "list"})
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(map[string]any{"capabilities": res.Capabilities, "granted": res.Grants})
		})
	mcp.AddTool(server, &mcp.Tool{Name: "request", Description: "Ask the user for a grant. Waits for their " +
		"answer, up to two minutes, longer if they open the Permissions window on it. Returns the grant: a socket to " +
		"connect to, a credential or a path."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in requestIn) (*mcp.CallToolResult, any, error) {
			params, _ := json.Marshal(in.Params)
			res, err := call(request{Op: "request", Capability: in.Capability, Params: params, Reason: in.Reason,
				Lease: in.Lease})
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(map[string]any{"grant": res.Grant, "credential": res.Credential})
		})
	mcp.AddTool(server, &mcp.Tool{Name: "release", Description: "Give a grant back once you're done with it."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in releaseIn) (*mcp.CallToolResult, any, error) {
			if _, err := call(request{Op: "release", Grant: in.Grant}); err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Released"}}}, nil, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "status", Description: "This session's grants."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			res, err := call(request{Op: "status"})
			if err != nil {
				return nil, nil, err
			}
			return jsonResult(map[string]any{"granted": res.Grants})
		})
	return server.Run(context.Background(), &mcp.StdioTransport{})
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
		return response{}, fmt.Errorf("The permissions broker isn't running: %w", err)
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
