package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
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
	Issue       []string                   `json:"issue"`
	Resolve     []string                   `json:"resolve"`
	Watch       []string                   `json:"watch"`
	Tools       bool                       `json:"tools"`
	Exclusive   bool                       `json:"exclusive"`
	Ceiling     ceiling                    `json:"-"`

	// Held while a request looks for a grant covering it, or makes one from an always grant
	covered sync.Mutex
	// list's output for a few seconds, so the sandbox asking again and again doesn't fork a process each time
	listMu   sync.Mutex
	listed   json.RawMessage
	listErr  error
	listedAt time.Time
}

// At most this many plugin commands run at once, whatever the sandbox sends
var pluginSlots = make(chan struct{}, 4)

func runPlugin(cmd *exec.Cmd) error { return runPluginIf(cmd, nil) }

// runPluginIf runs cmd once a slot is free, if ready, run then, doesn't refuse
func runPluginIf(cmd *exec.Cmd, ready func() error) error {
	pluginSlots <- struct{}{}
	defer func() { <-pluginSlots }()
	if ready != nil {
		if err := ready(); err != nil {
			return err
		}
	}
	return cmd.Run()
}

// A parameter's string value is at most this long: the notification shows it whole
const maxParam = 200

// What a plugin may grant at all, from the module. Plugin-specific fields pass through to its commands in Raw
type ceiling struct {
	MaxValidity string          `json:"maxValidity"`
	Raw         json.RawMessage `json:"-"`
}

// id is how requests name a capability: <plugin>/<name>
func (c *capability) id() string { return c.Plugin + "/" + c.Name }

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
	switch c.Type {
	case "A":
		if len(c.Serve) == 0 {
			return fmt.Errorf("%s is type A without serve", c.Name)
		}
	case "B":
		if len(c.Issue) == 0 {
			return fmt.Errorf("%s is type B without issue", c.Name)
		}
		if _, err := parseDuration(c.Ceiling.MaxValidity); err != nil {
			return fmt.Errorf("%s is type B: its ceiling needs maxValidity: %w", c.Name, err)
		}
	case "C":
		if len(c.Resolve) == 0 {
			return fmt.Errorf("%s is type C without resolve", c.Name)
		}
	default:
		return fmt.Errorf("%s has type %q, not A, B or C", c.Name, c.Type)
	}
	for k, schema := range c.Params {
		var s struct{ Type string }
		if err := json.Unmarshal(schema, &s); err != nil || !paramTypes[s.Type] {
			return fmt.Errorf("%s: parameter %s needs a type of string, boolean, integer or number", c.Name, k)
		}
	}
	return nil
}

var paramTypes = map[string]bool{"string": true, "boolean": true, "integer": true, "number": true}

// validate checks params against the capability's declared ones: no others, each of its type. Returns them
// re-encoded with sorted keys, so equal requests compare equal
func (c *capability) validate(raw json.RawMessage) (json.RawMessage, error) {
	params := map[string]any{}
	if len(raw) > 0 && string(raw) != "null" {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&params); err != nil {
			return nil, fmt.Errorf("Parameters aren't an object: %w", err)
		}
	}
	for k, v := range params {
		schema, ok := c.Params[k]
		if !ok {
			return nil, fmt.Errorf("%s takes no parameter %q", c.id(), k)
		}
		var s struct{ Type string }
		_ = json.Unmarshal(schema, &s)
		ok = false
		switch v := v.(type) {
		case string:
			ok = s.Type == "string"
			if strings.IndexFunc(v, unicode.IsControl) >= 0 || utf8.RuneCountInString(v) > maxParam {
				return nil, fmt.Errorf("Parameter %s of %s: at most %d characters, none of them control characters",
					k, c.id(), maxParam)
			}
		case bool:
			ok = s.Type == "boolean"
		case json.Number:
			_, intErr := v.Int64()
			ok = s.Type == "number" || s.Type == "integer" && intErr == nil
		}
		if !ok {
			return nil, fmt.Errorf("Parameter %s of %s must be a %s", k, c.id(), s.Type)
		}
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
		if v, ok := m[k].(string); ok {
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
	Params   json.RawMessage `json:"params"`
	Ceiling  json.RawMessage `json:"ceiling,omitempty"`
	Validity string          `json:"validity,omitempty"`
}

// issue runs a type B plugin's issue command and returns what it prints. validity runs once a plugin slot is free,
// right before the command: the grant may have ended or run down while the request waited for one
func (c *capability) issue(ctx context.Context, params json.RawMessage, validity func() (time.Duration, error)) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Issue[0], c.Issue[1:]...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	var refused error
	err := runPluginIf(cmd, func() error {
		v, err := validity()
		if err != nil {
			refused = err
			return err
		}
		in, _ := json.Marshal(pluginInput{Params: params, Ceiling: c.Ceiling.Raw, Validity: formatDuration(v)})
		cmd.Stdin = bytes.NewReader(in)
		return nil
	})
	if refused != nil {
		return "", refused
	}
	if err != nil {
		return "", fmt.Errorf("%s couldn't issue: %s", c.id(), strings.TrimSpace(errOut.String()))
	}
	return out.String(), nil
}

// unitPrefix starts the names of a launcher's type A units: perm_ for the default launcher, perm-<name>_ for a named
// one. Launcher names can't contain _, so no launcher's prefix starts another's
func unitPrefix(launcher string) string {
	if launcher == "" {
		return "perm_"
	}
	return "perm-" + launcher + "_"
}

// unitName is a type A grant's transient unit, found by name again after a restart
func unitName(launcher, grant string) string { return unitPrefix(launcher) + grant }

// startServe runs a type A plugin's serve command as a socket-activated transient user unit listening on socket.
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
