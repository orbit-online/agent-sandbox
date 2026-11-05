package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/hostcmd"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/hostsock"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/schema"
)

// Host commands (docs/permissions.md): scripts the module declares, run on the host per call under a grant of their
// capability. A capability fixes its bounding arguments in the grant; each command takes free arguments of its own.
// Bounding arguments and instances serve host sockets too

// A capability of host commands, as the config declares it. The MCP server reads the same without run
type commandConfig struct {
	Name        string                      `json:"name"`
	Description string                      `json:"description"`
	Bounding    map[string]json.RawMessage  `json:"bounding"`
	Exclusive   bool                        `json:"exclusive"`
	Commands    map[string]*hostcmd.Command `json:"commands"`
	// For the user, where Description is for Claude
	Consent struct {
		// Completes "Claude wants to …": "control the Windows VM"
		Title string `json:"title"`
	} `json:"consent"`
}

var commandName = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// loadCommands makes the config's host command capabilities, each under its own name
func loadCommands(cfgs []commandConfig, caps map[string]*capability) error {
	for _, cc := range cfgs {
		c := &capability{Name: cc.Name, Type: "command", Description: cc.Description, Title: cc.Consent.Title,
			Params: cc.Bounding, Exclusive: cc.Exclusive, Commands: cc.Commands}
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

// checkCommands checks a host command capability: names that make MCP tool names, a title and every command's
// phrase for the consent, every argument described, bounding and free arguments apart, at most one instances glob
func (c *capability) checkCommands() error {
	if !commandName.MatchString(c.Name) {
		return fmt.Errorf("name %q: letters, digits and -", c.Name)
	}
	if err := hostcmd.CheckPhrase(c.Title); err != nil {
		return fmt.Errorf("consent.title: %w", err)
	}
	if len(c.Commands) == 0 {
		return fmt.Errorf("no commands")
	}
	if err := c.checkBounding(); err != nil {
		return err
	}
	for name, cmd := range c.Commands {
		if err := cmd.Check(c.Name, name, c.schemas); err != nil {
			return err
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
		if slices.Contains(hostcmd.ReservedArgs, name) {
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

// expandPath expands the environment's variables in a declared path, and a leading ~
func expandPath(path string) string {
	path = os.ExpandEnv(path)
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		path = filepath.Join(os.Getenv("HOME"), rest)
	}
	return path
}

// globMatches is what a capability's instances glob matches now: each bounding value, the part of its path segment
// the * matched, with the path it matched (for a host socket, the socket). A host socket's match the broker refuses, or
// that isn't a socket reached without links, isn't one
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
		// A host socket's instance names its address, bound as a file name of at most MaxAddrName bytes: a value
		// of as many characters may be twice that and more
		if c.Type == "socket" && (!hostsock.IsSocket(m) || len(v) > hostsock.MaxAddrName) {
			continue
		}
		if s := c.schemas[c.globArg]; v != "" && found[v] == "" && s.CheckValue(v, maxParam) == nil {
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

// boundValues says the bounding values of params for the consent's summary, after the title: a value alone, quoted, or
// with several, each after its name. Opaque values by digest
func (c *capability) boundValues(params json.RawMessage) string {
	m, _ := schema.DecodeObject(params)
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		v, isString := m[k].(string)
		var shown string
		switch {
		case isString && c.schemas[k] != nil && c.schemas[k].Opaque:
			shown = schema.OpaqueDigest(v)
		case isString:
			// Quoted, so a value can't pass itself off as more values or text of the notification's own
			shown = strconv.Quote(v)
		default:
			shown = fmt.Sprint(m[k])
		}
		if len(m) > 1 {
			shown = k + " " + shown
		}
		parts = append(parts, shown)
	}
	return strings.Join(parts, ", ")
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

// commandKind is the kind of host command capabilities: their grants make nothing live, calls run under them
type commandKind struct{ baseKind }

func (commandKind) check(c *capability) error { return c.checkCommands() }

func (commandKind) scope(c *capability, params json.RawMessage) (string, string) {
	return hostcmd.Covers(c.Commands), c.boundValues(params)
}

func (commandKind) info(c *capability, i *capabilityInfo) {
	// What the sandbox may call, not what runs on the host
	i.Commands = map[string]*hostcmd.Command{}
	for name, cmd := range c.Commands {
		v := *cmd
		v.Run = nil
		i.Commands[name] = &v
	}
	i.Title = c.Title
	i.Consent = hostcmd.ConsentItems(c.Commands)
	i.Scope = hostcmd.ScopeItems(c.Commands)
}
