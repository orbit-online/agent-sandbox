package main

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Host commands (docs/permissions.md): scripts the module declares, run on the host per call under a grant of their
// capability. A capability fixes its bounding arguments in the grant; each command takes free arguments of its own

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

// globInstances is what a capability's instances glob matches now, as list prints instances: each a bounding value,
// the part of its path segment the * matched
func (c *capability) globInstances() (json.RawMessage, error) {
	pattern := os.ExpandEnv(c.glob)
	if rest, ok := strings.CutPrefix(pattern, "~/"); ok {
		pattern = filepath.Join(os.Getenv("HOME"), rest)
	}
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
	seen := map[string]bool{}
	for _, m := range matches {
		ms := strings.Split(m, "/")
		if len(ms) != len(segs) {
			continue
		}
		v := strings.TrimSuffix(strings.TrimPrefix(ms[i], prefix), suffix)
		if s := c.schemas[c.globArg]; v != "" && s.checkValue(v, maxParam) == nil {
			seen[v] = true
		}
	}
	values := make([]string, 0, len(seen))
	for v := range seen {
		values = append(values, v)
	}
	sort.Strings(values)
	inst := make([]map[string]string, len(values))
	for i, v := range values {
		inst[i] = map[string]string{c.globArg: v}
	}
	return json.Marshal(inst)
}

// scope says what a grant of c covers, for the consent: unrestricted free arguments first, then the rest
func (c *capability) scope() string {
	var open, bounded []string
	for _, name := range slices.Sorted(maps.Keys(c.Commands)) {
		cmd := c.Commands[name]
		if len(cmd.args) == 0 {
			bounded = append(bounded, cmd.Description+" ("+name+")")
		}
		for _, arg := range slices.Sorted(maps.Keys(cmd.args)) {
			s := cmd.args[arg]
			if s.unrestricted() {
				open = append(open, fmt.Sprintf("%s: %s, unrestricted (%s)", cmd.Description, s.Description, name))
			} else {
				bounded = append(bounded, fmt.Sprintf("%s: %s, %s (%s)", cmd.Description, s.Description, s.allows(), name))
			}
		}
	}
	return strings.Join(append(open, bounded...), ". ") + "."
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
		if err := g.cap.inList(context.Background(), g.Params); err != nil {
			g.end("its instance went away")
			return
		}
	}
}
