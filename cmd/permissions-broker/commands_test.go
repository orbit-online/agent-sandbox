package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/hostcmd"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/schema"
)

// A declaration the broker can't stand behind stops it: every argument described, a title and every command's phrase
// for the consent, each on one line and short, no names it uses, names that make MCP tools, a result it can wrap, one
// instances glob on a string with one *
func TestCommandsRefused(t *testing.T) {
	desc := `"description": "d"`
	for name, change := range map[string]func(c *capability){
		"bounding undescribed": func(c *capability) { c.Params["vm"] = json.RawMessage(`{"type": "string"}`) },
		"free undescribed": func(c *capability) {
			c.Commands["run"].Arguments = map[string]json.RawMessage{"x": json.RawMessage(`{"type": "string"}`)}
		},
		"reason": func(c *capability) {
			c.Commands["run"].Arguments = map[string]json.RawMessage{"reason": json.RawMessage(`{"type": "string", ` + desc + `}`)}
		},
		"bounding lease": func(c *capability) { c.Params["lease"] = json.RawMessage(`{"type": "string", ` + desc + `}`) },
		"free shadows bounding": func(c *capability) {
			c.Commands["run"].Arguments = map[string]json.RawMessage{"path": json.RawMessage(`{"type": "string", ` + desc + `}`)}
		},
		"free instances": func(c *capability) {
			c.Commands["run"].Arguments = map[string]json.RawMessage{"x": json.RawMessage(`{"type": "string", ` + desc +
				`, "instances": "/run/*"}`)}
		},
		"no title":           func(c *capability) { c.Title = "" },
		"blank title":        func(c *capability) { c.Title = "  " },
		"title on two lines": func(c *capability) { c.Title = "use it\nAllowed by the host" },
		"long title":         func(c *capability) { c.Title = strings.Repeat("x", hostcmd.MaxPhrase+1) },
		"no consent":         func(c *capability) { c.Commands["run"].Consent = "" },
		"consent with a tab": func(c *capability) { c.Commands["run"].Consent = "Run\tit" },
		"long consent":       func(c *capability) { c.Commands["run"].Consent = strings.Repeat("é", hostcmd.MaxPhrase+1) },
		"no commands":        func(c *capability) { c.Commands = nil },
		"no run":             func(c *capability) { c.Commands["run"].Run = nil },
		"name":               func(c *capability) { c.Name = "a_b" },
		"command name":       func(c *capability) { c.Commands["a b"] = c.Commands["run"] },
		"tool name": func(c *capability) {
			c.Commands[strings.Repeat("x", hostcmd.MaxToolName-len(c.Name))] = c.Commands["run"]
		},
		"result":      func(c *capability) { c.Commands["run"].Result = "application/json" },
		"timeout":     func(c *capability) { c.Commands["run"].Timeout = "1m" },
		"maxValidity": func(c *capability) { c.Commands["run"].MaxValidity = "forever" },
		"two globs": func(c *capability) {
			c.Params["a"] = json.RawMessage(`{"type": "string", ` + desc + `, "instances": "/run/*/a"}`)
			c.Params["b"] = json.RawMessage(`{"type": "string", ` + desc + `, "instances": "/run/*/b"}`)
		},
		"glob of two": func(c *capability) {
			c.Params["a"] = json.RawMessage(`{"type": "string", ` + desc + `, "instances": "/run/*/*"}`)
		},
		"glob class": func(c *capability) {
			c.Params["a"] = json.RawMessage(`{"type": "string", ` + desc + `, "instances": "/run/*/[ab]"}`)
		},
	} {
		c := testCap(t, "command")
		if err := c.check(); err != nil {
			t.Fatalf("%s: the base: %v", name, err)
		}
		change(c)
		if err := c.check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The config's host commands load under their names, with their consent as the module writes it; a name taken twice
// stops the daemon
func TestLoadCommands(t *testing.T) {
	var cfg commandConfig
	if err := json.Unmarshal([]byte(`{"name": "vm", "description": "a VM", "consent": {"title": "use the VM"},
		"commands": {"shot": {"description": "a screenshot", "consent": "Take screenshots", "run": ["/bin/true"],
		"result": "image/png"}}}`), &cfg); err != nil {
		t.Fatal(err)
	}
	caps := map[string]*capability{}
	if err := loadCommands([]commandConfig{cfg}, caps); err != nil {
		t.Fatal(err)
	}
	c := caps["vm"]
	if c == nil || c.Type != "command" || c.Commands["shot"].Timeout != hostcmd.DefaultTimeout ||
		c.Title != "use the VM" || c.Commands["shot"].Consent != "Take screenshots" {
		t.Errorf("Loaded %+v", c)
	}
	again := cfg
	again.Commands = map[string]*hostcmd.Command{"shot": {Description: "again", Consent: "Again",
		Run: []string{"/bin/true"}}}
	if err := loadCommands([]commandConfig{again}, caps); err == nil {
		t.Error("A second vm loaded")
	}
}

// Instances come from the glob: the part of the segment the * matched, valid for the argument's schema
func TestGlobInstances(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VMS", dir)
	for _, vm := range []string{"win11", "win10", "bad name"} {
		if err := os.MkdirAll(filepath.Join(dir, "vm-"+vm), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "vm-"+vm, "qmp.sock"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "vm-off"), 0o700); err != nil {
		t.Fatal(err)
	}
	c := testCap(t, "command")
	c.Params["vm"] = json.RawMessage(`{"type": "string", "pattern": "[a-z0-9]+", "description": "the VM",
		"instances": "$VMS/vm-*/qmp.sock"}`)
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	got, err := c.globInstances()
	if err != nil || string(got) != `[{"vm":"win10"},{"vm":"win11"}]` {
		t.Errorf("Instances %s, %v", got, err)
	}
	if err := c.inList(json.RawMessage(`{"vm":"win11"}`)); err != nil {
		t.Errorf("win11: %v", err)
	}
	for _, p := range []string{`{"vm":"off"}`, `{}`, `{"vm":"win1"}`} {
		if err := c.inList(json.RawMessage(p)); err == nil {
			t.Errorf("%s in the list", p)
		}
	}
}

// The scope's parts in detail, as the window gets them with the capability: unrestricted free arguments first, each
// with what its schema allows. The summary has the title and the bounding values, each after its name when there are
// several, opaque ones by digest
func TestScopeItems(t *testing.T) {
	c := testCap(t, "command")
	c.Params["cert"] = json.RawMessage(`{"type": "string", "opaque": true, "description": "the key"}`)
	c.Commands["exec"] = &hostcmd.Command{Description: "Run PowerShell", Consent: "Run any PowerShell",
		Run: []string{"/bin/true"}, Arguments: map[string]json.RawMessage{"script": json.RawMessage(`{"type": "string",
			"multiline": true, "description": "any PowerShell, as SYSTEM"}`)}}
	c.Commands["keys"] = &hostcmd.Command{Description: "Press keys", Consent: "Press keys", Run: []string{"/bin/true"},
		Arguments: map[string]json.RawMessage{"key": json.RawMessage(`{"type": "string", "enum": ["a", "b"],
			"description": "a key"}`)}}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	b, _ := testBroker(t)
	b.caps = map[string]*capability{c.id(): c}
	got := b.listCapabilities()[0].Scope
	want := []hostcmd.ScopeItem{
		{Command: "exec", Description: "Run PowerShell", Argument: "script", About: "any PowerShell, as SYSTEM",
			Allows: "any text", Unrestricted: true},
		{Command: "keys", Description: "Press keys", Argument: "key", About: "a key", Allows: "one of [a b]"},
		{Command: "run", Description: "print the input"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("scope = %+v\nwant    %+v", got, want)
	}
	params, err := c.validate(json.RawMessage(`{"path": "/a", "ro": true, "cert": "` + strings.Repeat("k", 40) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if d := c.describe(params); d != `use the test thing cert `+schema.OpaqueDigest(strings.Repeat("k", 40))+
		`, path "/a", ro true` {
		t.Errorf("describe = %s", d)
	}
	if d := c.describe(json.RawMessage(`{"path": "/a\"b"}`)); d != `use the test thing "/a\"b"` {
		t.Errorf("describe = %s", d)
	}
	if d := c.describe(json.RawMessage(`{}`)); d != "use the test thing" {
		t.Errorf("describe = %s", d)
	}
}

// The consent's lines: a phrase each, the commands sharing one on one line, marked unrestricted when a free argument
// of any of them takes any text whatever the phrase says, those first
func TestConsentItems(t *testing.T) {
	c := testCap(t, "command")
	free := func(desc string) map[string]json.RawMessage {
		return map[string]json.RawMessage{"text": json.RawMessage(`{"type": "string", "description": "` + desc + `"}`)}
	}
	c.Commands["type"] = &hostcmd.Command{Description: "Type", Consent: "Use the keyboard", Run: []string{"/bin/true"},
		Arguments: free("any text")}
	c.Commands["keys"] = &hostcmd.Command{Description: "Press keys", Consent: "Use the keyboard",
		Run: []string{"/bin/true"}, Arguments: map[string]json.RawMessage{"key": json.RawMessage(`{"type": "string",
			"enum": ["a", "b"], "description": "a key"}`)}}
	// After type, so that its free argument decides nothing
	c.Commands["zoom"] = &hostcmd.Command{Description: "Zoom", Consent: "Use the keyboard", Run: []string{"/bin/true"},
		Arguments: map[string]json.RawMessage{"in": json.RawMessage(`{"type": "boolean", "description": "in"}`)}}
	c.Commands["exec"] = &hostcmd.Command{Description: "Run PowerShell", Consent: "Run a harmless script",
		Run: []string{"/bin/true"}, Arguments: free("any PowerShell")}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	b, _ := testBroker(t)
	b.caps = map[string]*capability{c.id(): c}
	got := b.listCapabilities()[0].Consent
	want := []hostcmd.ConsentItem{
		{Consent: "Run a harmless script", Commands: []string{"exec"}, Unrestricted: true},
		{Consent: "Use the keyboard", Commands: []string{"keys", "type", "zoom"}, Unrestricted: true},
		{Consent: "Print what it gets", Commands: []string{"run"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("consent = %+v\nwant      %+v", got, want)
	}
	if got, want := hostcmd.Covers(c.Commands), "⚠ Run a harmless script; ⚠ Use the keyboard; Print what it gets"; got != want {
		t.Errorf("covers = %q\nwant     %q", got, want)
	}
}
