package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type capability struct {
	Plugin      string                     `json:"-"`
	Name        string                     `json:"name"`
	Type        string                     `json:"type"`
	Description string                     `json:"description"`
	Params      map[string]json.RawMessage `json:"params"`
	List        []string                   `json:"list"`
	Serve       []string                   `json:"serve"`
	Resolve     []string                   `json:"resolve"`
	Watch       []string                   `json:"watch"`
	Tools       bool                       `json:"tools"`
	Exclusive   bool                       `json:"exclusive"`
	Ceiling     ceiling                    `json:"-"`
	// Host commands: by name, and the bounding argument whose values the instances glob gives
	Commands      map[string]*hostCommand `json:"-"`
	glob, globArg string

	schemas map[string]*argSchema

	// Held while a request looks for a grant covering it
	covered sync.Mutex
	// One resolve command of this capability's at a time, so a capability whose commands hang holds one of
	// pluginSlots, not all of them. Host commands: one call per instance (its bounding values) at a time
	slotOnce sync.Once
	slot     chan struct{}
	slotsMu  sync.Mutex
	slots    map[string]chan struct{}
	// This daemon's exclusive locks, by file, and how many of its grants hold each (once grants beside another)
	locksMu sync.Mutex
	locks   map[string]int
	// list's output for a few seconds, so the sandbox asking again and again doesn't fork a process each time. Also
	// what keeps list to one process per capability, without a plugin slot: the window's state runs it, which a busy
	// capability mustn't hold up
	listMu   sync.Mutex
	listed   json.RawMessage
	listErr  error
	listedAt time.Time
}

// At most this many resolve commands and host command calls run at once, whatever the sandbox sends
var pluginSlots = make(chan struct{}, 4)

// runPlugin runs one of c's commands once c's slot and a plugin slot are free
func (c *capability) runPlugin(cmd *exec.Cmd) error {
	c.slotOnce.Do(func() { c.slot = make(chan struct{}, 1) })
	c.slot <- struct{}{}
	defer func() { <-c.slot }()
	pluginSlots <- struct{}{}
	defer func() { <-pluginSlots }()
	return cmd.Run()
}

// A parameter's string value is at most this long: the notification shows it whole. An opaque one, data for the
// plugin that the user has nothing to read in (a CSR), is shown as a digest instead and may be up to maxOpaque long
const (
	maxParam  = 200
	maxOpaque = 8192
)

// What a plugin may grant at all, from the module. Plugin-specific fields pass through to its commands in Raw
type ceiling struct {
	Raw json.RawMessage `json:"-"`
}

// id is how requests name a capability: <plugin>/<name>, or a host command capability's name
func (c *capability) id() string {
	if c.Plugin == "" {
		return c.Name
	}
	return c.Plugin + "/" + c.Name
}

func loadPlugins(cfg config) (map[string]*capability, error) {
	caps := map[string]*capability{}
	for _, p := range cfg.Plugins {
		data, err := os.ReadFile(p.Manifest)
		if err != nil {
			return nil, fmt.Errorf("Read plugin manifest: %w", err)
		}
		var m struct {
			Name         string        `json:"name"`
			Capabilities []*capability `json:"capabilities"`
		}
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("Parse plugin manifest %s: %w", p.Manifest, err)
		}
		var ceil ceiling
		if len(p.Ceiling) > 0 {
			if err := json.Unmarshal(p.Ceiling, &ceil); err != nil {
				return nil, fmt.Errorf("Parse the ceiling of %s: %w", m.Name, err)
			}
			ceil.Raw = p.Ceiling
		}
		for _, c := range m.Capabilities {
			c.Plugin, c.Ceiling = m.Name, ceil
			if err := c.check(); err != nil {
				return nil, fmt.Errorf("Plugin %s: %w", m.Name, err)
			}
			if _, dup := caps[c.id()]; dup {
				return nil, fmt.Errorf("Capability %s declared twice", c.id())
			}
			caps[c.id()] = c
		}
	}
	return caps, nil
}

func (c *capability) check() error {
	if c.Name == "" || strings.ContainsAny(c.Name, "/ ") {
		return fmt.Errorf("Capability name %q", c.Name)
	}
	c.schemas = map[string]*argSchema{}
	for k, raw := range c.Params {
		s, err := parseSchema(raw)
		if err != nil {
			return fmt.Errorf("%s: parameter %s: %w", c.Name, k, err)
		}
		// A parameter is quoted in the notification's summary: one line, one value
		if s.Type == "array" || s.Multiline {
			return fmt.Errorf("%s: parameter %s can't be an array or multiline", c.Name, k)
		}
		c.schemas[k] = s
	}
	switch c.Type {
	case "service":
		if len(c.Serve) == 0 {
			return fmt.Errorf("%s is of type service without serve", c.Name)
		}
	case "command":
		if c.Plugin != "" {
			return fmt.Errorf("%s: host commands are declared in the config, not by plugins", c.Name)
		}
		return c.checkCommands()
	case "attach":
		if len(c.Resolve) == 0 {
			return fmt.Errorf("%s is of type attach without resolve", c.Name)
		}
	default:
		return fmt.Errorf("%s has type %q, not service or attach", c.Name, c.Type)
	}
	return nil
}

// validate checks params against the capability's declared ones: no others, each of its schema. Returns them re-encoded with sorted keys, so equal requests compare equal
func (c *capability) validate(raw json.RawMessage) (json.RawMessage, error) {
	params, err := decodeObject(raw)
	if err != nil {
		return nil, fmt.Errorf("Parameters aren't an object: %w", err)
	}
	for k, v := range params {
		s, ok := c.schemas[k]
		if !ok {
			return nil, fmt.Errorf("%s takes no parameter %q", c.id(), k)
		}
		if err := s.checkValue(v, maxParam); err != nil {
			return nil, fmt.Errorf("Parameter %s of %s: %w", k, c.id(), err)
		}
	}
	return json.Marshal(params) // maps marshal with sorted keys
}

// decodeObject decodes a JSON object with numbers as json.Number; nothing or null is an empty one
func decodeObject(raw json.RawMessage) (map[string]any, error) {
	m := map[string]any{}
	if len(raw) == 0 || string(raw) == "null" {
		return m, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return map[string]any{}, nil
	}
	return m, nil
}

// opaqueDigest is how an opaque parameter is shown: enough to tell two apart, nothing to read
func opaqueDigest(v string) string {
	sum := sha256.Sum256([]byte(v))
	return fmt.Sprintf("sha256:%s (%d characters)", hex.EncodeToString(sum[:])[:16], utf8.RuneCountInString(v))
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
			parts[i] = k + "=" + opaqueDigest(v)
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

// pluginInput is what a plugin's commands read on stdin
type pluginInput struct {
	Params  json.RawMessage `json:"params"`
	Ceiling json.RawMessage `json:"ceiling,omitempty"`
}

// unitPrefix starts the names of a launcher's service units: perm_ for the default launcher, perm-<name>_ for a named
// one. Launcher names can't contain _, so no launcher's prefix starts another's
func unitPrefix(launcher string) string {
	if launcher == "" {
		return "perm_"
	}
	return "perm-" + launcher + "_"
}

// unitName is a service grant's transient unit, found by name again after a restart
func unitName(launcher, grant string) string { return unitPrefix(launcher) + grant }

// startServe runs a service plugin's serve command as a socket-activated transient user unit listening on socket.
// systemd hands the socket over the standard way (sd_listen_fds needs LISTEN_PID, which an exec can't set), and
// stopping the unit kills its cgroup, double-forked children included. Both units are bound to the daemon's (BindsTo):
// they stop when it does, a crash included, so no grant outlives it
func (c *capability) startServe(launcher, grant, socket, daemon string, params json.RawMessage) error {
	in, _ := json.Marshal(pluginInput{Params: params, Ceiling: c.Ceiling.Raw})
	args := []string{"--user", "--quiet", "--collect", "--unit=" + unitName(launcher, grant),
		"--socket-property=ListenStream=" + socket, "--socket-property=SocketMode=0600",
		"--socket-property=RemoveOnStop=yes",
		"--setenv=PERMISSIONS_INPUT=" + string(in)}
	if daemon != "" {
		args = append(args, "--property=BindsTo="+daemon, "--property=After="+daemon,
			"--socket-property=BindsTo="+daemon, "--socket-property=After="+daemon)
	}
	args = append(args, "--")
	args = append(args, c.Serve...)
	if out, err := exec.Command(systemdRun, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("Start %s: %s", c.id(), strings.TrimSpace(string(out)))
	}
	return nil
}

// stopServe stops a grant's unit, socket and service both
func stopServe(launcher, grant string) error {
	u := unitName(launcher, grant)
	if out, err := exec.Command(systemctl, "--user", "stop", u+".socket", u+".service").CombinedOutput(); err != nil {
		return fmt.Errorf("Stop %s: %s", u, strings.TrimSpace(string(out)))
	}
	return nil
}

// stopAllServes stops every unit of the launcher's, left from a daemon that ended without cleaning up
func stopAllServes(launcher string) {
	_ = exec.Command(systemctl, "--user", "stop", unitPrefix(launcher)+"*").Run()
}

// startWatch runs a plugin's watch command for a grant; done is closed when it exits
func (c *capability) startWatch(params json.RawMessage) (stop func(), done <-chan struct{}, err error) {
	ch := make(chan struct{})
	if len(c.Watch) == 0 {
		return func() {}, ch, nil
	}
	in, _ := json.Marshal(pluginInput{Params: params, Ceiling: c.Ceiling.Raw})
	cmd := exec.Command(c.Watch[0], c.Watch[1:]...)
	cmd.Stdin = bytes.NewReader(in)
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("Start the watch of %s: %w", c.id(), err)
	}
	go func() {
		_ = cmd.Wait()
		close(ch)
	}()
	return func() { _ = cmd.Process.Kill() }, ch, nil
}
