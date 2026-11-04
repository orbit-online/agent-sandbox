package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/dbusgrant"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/hostcmd"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mounts"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/schema"
)

type capability struct {
	// How requests name it: a host command or host socket capability's name, or folders/folder
	Name        string
	Type        string
	Description string
	Params      map[string]json.RawMessage
	Exclusive   bool
	// Host commands: by name
	Commands map[string]*hostcmd.Command
	// Folders: the ceiling, what may be granted at all
	Sources []mounts.Source
	// Host sockets: the host's socket, or none with an instances glob, whose matches are the sockets
	Path string
	// D-Bus: the bus and the rule set
	DBus *dbusgrant.Config
	// The bounding argument whose values the instances glob gives, and the glob
	glob, globArg string

	schemas map[string]*schema.Schema

	// Held while a request looks for a grant covering it
	covered sync.Mutex
	// Host commands: one call per instance (its bounding values) at a time
	slotsMu sync.Mutex
	slots   map[string]chan struct{}
	// This daemon's exclusive locks, by file, and how many of its grants hold each (once grants beside another)
	locksMu sync.Mutex
	locks   map[string]int
	// The instances for a few seconds, so the sandbox asking again and again doesn't glob each time
	listMu   sync.Mutex
	listed   json.RawMessage
	listErr  error
	listedAt time.Time
}

// At most this many host command calls run at once, whatever the sandbox sends
var callSlots = make(chan struct{}, 4)

// A parameter's string value is at most this long: the notification shows it whole. An opaque one, data for a
// host command that the user has nothing to read in (a CSR), is shown as a digest instead and may be up to
// schema.MaxOpaque long
const maxParam = 200

// id is how requests name a capability
func (c *capability) id() string { return c.Name }

func (c *capability) check() error {
	c.schemas = map[string]*schema.Schema{}
	for k, raw := range c.Params {
		s, err := schema.Parse(raw)
		if err != nil {
			return fmt.Errorf("%s: parameter %s: %w", c.Name, k, err)
		}
		// A parameter is quoted in the notification's summary: one line, one value
		if s.Type == "array" || s.Multiline {
			return fmt.Errorf("%s: parameter %s can't be an array or multiline", c.Name, k)
		}
		c.schemas[k] = s
	}
	k := c.kind()
	if k == nil {
		return fmt.Errorf("%s has type %q, not command, socket, dbus or attach", c.Name, c.Type)
	}
	return k.check(c)
}

// validate checks params against the capability's declared ones: no others, each of its schema. Returns them re-encoded
// with sorted keys and numbers written one way, so equal requests compare equal
func (c *capability) validate(raw json.RawMessage) (json.RawMessage, error) {
	params, err := schema.DecodeObject(raw)
	if err != nil {
		return nil, fmt.Errorf("Parameters aren't an object: %w", err)
	}
	for k, v := range params {
		s, ok := c.schemas[k]
		if !ok {
			return nil, fmt.Errorf("%s takes no parameter %q", c.id(), k)
		}
		if err := s.CheckValue(v, maxParam); err != nil {
			return nil, fmt.Errorf("Parameter %s of %s: %w", k, c.id(), err)
		}
		params[k] = schema.Canonical(v)
	}
	return json.Marshal(params) // maps marshal with sorted keys
}

// describe is the notification's summary of a validated request, built from its parameters, not from the reason
func (c *capability) describe(params json.RawMessage) string {
	var m map[string]any
	_ = json.Unmarshal(params, &m)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	// Quoted, so a value can't pass itself off as more parameters or text of the notification's own
	for i, k := range keys {
		if v, ok := m[k].(string); ok && c.schemas[k].Opaque {
			parts[i] = k + "=" + schema.OpaqueDigest(v)
		} else if ok {
			parts[i] = fmt.Sprintf("%s=%q", k, v)
		} else {
			parts[i] = fmt.Sprintf("%s=%v", k, m[k])
		}
	}
	desc := c.Description
	if desc == "" {
		desc = c.id()
	}
	if len(parts) == 0 {
		return desc
	}
	return desc + " (" + strings.Join(parts, ", ") + ")"
}

// unitPrefix starts the names of a launcher's call units: perm_ for the default launcher, perm-<name>_ for a named
// one. Launcher names can't contain _, so no launcher's prefix starts another's
func unitPrefix(launcher string) string {
	if launcher == "" {
		return "perm_"
	}
	return "perm-" + launcher + "_"
}

// stopAllCalls stops every call unit of the launcher's, left from a daemon that ended without cleaning up
func stopAllCalls(launcher string) {
	_ = exec.Command(systemctl, "--user", "stop", unitPrefix(launcher)+"*").Run()
}
