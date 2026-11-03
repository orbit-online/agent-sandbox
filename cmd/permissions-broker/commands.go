package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Host commands (docs/permissions.md): scripts the module declares, run on the host per call under a grant of their
// capability. A capability fixes its bounding arguments in the grant; each command takes free arguments of its own.
// Bounding arguments and instances serve host sockets too

// A capability of host commands, as the config declares it. The MCP server reads the same without run
type commandConfig struct {
	Name        string                     `json:"name"`
	Description string                     `json:"description"`
	Bounding    map[string]json.RawMessage `json:"bounding"`
	Exclusive   bool                       `json:"exclusive"`
	Commands    map[string]*hostCommand    `json:"commands"`
}

type hostCommand struct {
	Description string                     `json:"description"`
	Arguments   map[string]json.RawMessage `json:"arguments"`
	Result      string                     `json:"result"`
	Run         []string                   `json:"run,omitempty"`
	Timeout     string                     `json:"timeout"`
	MaxValidity string                     `json:"maxValidity"`

	args map[string]*argSchema
}

const (
	// A free string without maxLength may be this long: the consent covers it whole, the window shows it
	maxFree = 64 << 10
	// MCP tool names: <capability>_<command>
	maxToolName = 64
	// A call's timeout unless its command declares one
	defaultTimeout = "PT1M"
)

var commandName = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// Names the broker adds to every command's arguments, or uses itself
var reservedArgs = []string{"reason", "lease"}

// loadCommands makes the config's host command capabilities, each under its own name
func loadCommands(cfgs []commandConfig, caps map[string]*capability) error {
	for _, cc := range cfgs {
		c := &capability{Name: cc.Name, Type: "command", Description: cc.Description, Params: cc.Bounding,
			Exclusive: cc.Exclusive, Commands: cc.Commands}
		if err := c.check(); err != nil {
			return fmt.Errorf("Host commands %s: %w", cc.Name, err)
		}
		if _, dup := caps[c.id()]; dup {
			return fmt.Errorf("Capability %s declared twice", c.id())
		}
		caps[c.id()] = c
	}
	return nil
}

// checkCommands checks a host command capability: names that make MCP tool names, every argument described, bounding
// and free arguments apart, at most one instances glob
func (c *capability) checkCommands() error {
	if !commandName.MatchString(c.Name) {
		return fmt.Errorf("name %q: letters, digits and -", c.Name)
	}
	if len(c.Commands) == 0 {
		return fmt.Errorf("no commands")
	}
	if err := c.checkBounding(); err != nil {
		return err
	}
	for name, cmd := range c.Commands {
		if !commandName.MatchString(name) || len(c.Name)+1+len(name) > maxToolName {
			return fmt.Errorf("command %q: letters, digits and -, and %s_%s at most %d characters", name, c.Name,
				name, maxToolName)
		}
		if cmd.Description == "" || len(cmd.Run) == 0 {
			return fmt.Errorf("command %s needs a description and run", name)
		}
		switch {
		case cmd.Result == "":
			cmd.Result = "text"
		case cmd.Result != "text" && !strings.HasPrefix(cmd.Result, "image/"):
			return fmt.Errorf("command %s: result %q, text or an image MIME type", name, cmd.Result)
		}
		if cmd.Timeout == "" {
			cmd.Timeout = defaultTimeout
		}
		if _, err := parseDuration(cmd.Timeout); err != nil {
			return fmt.Errorf("command %s: timeout: %w", name, err)
		}
		if cmd.MaxValidity != "" {
			if _, err := parseDuration(cmd.MaxValidity); err != nil {
				return fmt.Errorf("command %s: maxValidity: %w", name, err)
			}
		}
		cmd.args = map[string]*argSchema{}
		for arg, raw := range cmd.Arguments {
			s, err := parseSchema(raw)
			if err != nil {
				return fmt.Errorf("command %s: argument %s: %w", name, arg, err)
			}
			switch {
			case s.Description == "":
				return fmt.Errorf("command %s: argument %s has no description: the consent names it", name, arg)
			case slices.Contains(reservedArgs, arg) || c.schemas[arg] != nil:
				return fmt.Errorf("command %s: argument %s: a bounding argument or the broker's has that name", name, arg)
			case s.Instances != "":
				return fmt.Errorf("command %s: argument %s: instances are for bounding arguments", name, arg)
			}
			cmd.args[arg] = s
		}
	}
	return nil
}

// checkBounding checks a capability's bounding arguments: each described, none named as the broker's own, and at most
// one with an instances glob
func (c *capability) checkBounding() error {
	for name, s := range c.schemas {
		if s.Description == "" {
			return fmt.Errorf("bounding argument %s has no description: the consent names it", name)
		}
		if slices.Contains(reservedArgs, name) {
			return fmt.Errorf("bounding argument %s: the broker uses that name", name)
		}
		if s.Instances != "" {
			if c.globArg != "" {
				return fmt.Errorf("instances on %s and %s: one bounding argument at most", c.globArg, name)
			}
			if strings.Count(s.Instances, "*") != 1 || strings.ContainsAny(s.Instances, "?[") || s.Type != "string" {
				return fmt.Errorf("instances of %s: a glob with one * and nothing else, on a string", name)
			}
			c.glob, c.globArg = s.Instances, name
		}
	}
	return nil
}

// validateArgs checks a call's free arguments: each declared one, of its schema, and no other. Returns them re-encoded
// with sorted keys
func (cmd *hostCommand) validateArgs(raw json.RawMessage) (json.RawMessage, error) {
	args, err := decodeObject(raw)
	if err != nil {
		return nil, fmt.Errorf("Arguments aren't an object: %w", err)
	}
	for k := range args {
		if cmd.args[k] == nil {
			return nil, fmt.Errorf("No argument %q", k)
		}
	}
	for k, s := range cmd.args {
		v, ok := args[k]
		if !ok {
			return nil, fmt.Errorf("Argument %s is missing", k)
		}
		if err := s.checkValue(v, maxFree); err != nil {
			return nil, fmt.Errorf("Argument %s: %w", k, err)
		}
	}
	return json.Marshal(args)
}

// expandPath expands the environment's variables in a declared path, and a leading ~
func expandPath(path string) string {
	path = os.ExpandEnv(path)
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		path = filepath.Join(os.Getenv("HOME"), rest)
	}
	return path
}

// globMatches is what a capability's instances glob matches now: each bounding value, the part of its path segment
// the * matched, with the path it matched (for a host socket, the socket). A host socket's match the broker refuses
// isn't one
func (c *capability) globMatches() (map[string]string, error) {
	pattern := expandPath(c.glob)
	segs := strings.Split(pattern, "/")
	i := slices.IndexFunc(segs, func(s string) bool { return strings.Contains(s, "*") })
	if i < 0 {
		return nil, fmt.Errorf("Instances of %s: no * once expanded", c.id())
	}
	prefix, suffix, _ := strings.Cut(segs[i], "*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("Instances of %s: %w", c.id(), err)
	}
	found := map[string]string{}
	for _, m := range matches {
		ms := strings.Split(m, "/")
		if len(ms) != len(segs) {
			continue
		}
		v := strings.TrimSuffix(strings.TrimPrefix(ms[i], prefix), suffix)
		if c.Type == "socket" && refusedSocket(m) != nil {
			continue
		}
		if s := c.schemas[c.globArg]; v != "" && found[v] == "" && s.checkValue(v, maxParam) == nil {
			found[v] = m
		}
	}
	return found, nil
}

// globInstances is what a capability's instances glob matches now, as list shows instances: objects naming each
// bounding value
func (c *capability) globInstances() (json.RawMessage, error) {
	found, err := c.globMatches()
	if err != nil {
		return nil, err
	}
	values := slices.Sorted(maps.Keys(found))
	inst := make([]map[string]string, len(values))
	for i, v := range values {
		inst[i] = map[string]string{c.globArg: v}
	}
	return json.Marshal(inst)
}

// One part of what a grant of a host command capability covers: a command without free arguments, or one free
// argument of a command with its declaration's description and what its schema lets through. The window shows them
// as the notification's scope line says them
type scopeItem struct {
	Command     string `json:"command"`
	Description string `json:"description"`
	Argument    string `json:"argument,omitempty"`
	About       string `json:"about,omitempty"`
	Allows      string `json:"allows,omitempty"`
	// Any text: no enum or pattern
	Unrestricted bool `json:"unrestricted,omitempty"`
}

// scopeItems is what a grant of c covers: unrestricted free arguments first, then the rest, each by command and
// argument name
func (c *capability) scopeItems() []scopeItem {
	var open, bounded []scopeItem
	for _, name := range slices.Sorted(maps.Keys(c.Commands)) {
		cmd := c.Commands[name]
		if len(cmd.args) == 0 {
			bounded = append(bounded, scopeItem{Command: name, Description: cmd.Description})
		}
		for _, arg := range slices.Sorted(maps.Keys(cmd.args)) {
			s := cmd.args[arg]
			item := scopeItem{Command: name, Description: cmd.Description, Argument: arg, About: s.Description,
				Allows: s.allows(), Unrestricted: s.unrestricted()}
			if item.Unrestricted {
				open = append(open, item)
			} else {
				bounded = append(bounded, item)
			}
		}
	}
	return append(open, bounded...)
}

// scope says what a grant of c covers, for the consent, in scopeItems' order
func (c *capability) scope() string {
	var parts []string
	for _, s := range c.scopeItems() {
		switch {
		case s.Argument == "":
			parts = append(parts, s.Description+" ("+s.Command+")")
		case s.Unrestricted:
			parts = append(parts, fmt.Sprintf("%s: %s, unrestricted (%s)", s.Description, s.About, s.Command))
		default:
			parts = append(parts, fmt.Sprintf("%s: %s, %s (%s)", s.Description, s.About, s.Allows, s.Command))
		}
	}
	return strings.Join(parts, ". ") + "."
}

// bounds names the bounding values of params by their declarations' descriptions, for the consent's body: the summary
// names them too, but a server may cut a summary. Opaque values by digest, as the summary has them
func (c *capability) bounds(params json.RawMessage) string {
	m, _ := decodeObject(params)
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		about := k
		if s := c.schemas[k]; s != nil && s.Description != "" {
			about = s.Description
		}
		v, isString := m[k].(string)
		switch {
		case isString && c.schemas[k] != nil && c.schemas[k].Opaque:
			parts = append(parts, about+" is "+opaqueDigest(v))
		case isString:
			parts = append(parts, fmt.Sprintf("%s is %q", about, v))
		default:
			parts = append(parts, fmt.Sprintf("%s is %v", about, m[k]))
		}
	}
	return strings.Join(parts, " and ")
}

// How often the broker looks again for the instances grants are of
var instanceEvery = 30 * time.Second

// watchInstance ends g once its instance is gone: a VM shut down
func (b *broker) watchInstance(g *grant) {
	for {
		select {
		case <-b.clock.after(instanceEvery):
		case <-g.ended:
			return
		}
		if err := g.cap.inList(g.Params); err != nil {
			g.end("its instance went away")
			return
		}
	}
}
