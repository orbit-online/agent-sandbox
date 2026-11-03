package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// A declaration the broker can't stand behind stops it: every argument described, no names it uses, names that make
// MCP tools, a result it can wrap, one instances glob on a string with one *
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
		"no commands":  func(c *capability) { c.Commands = nil },
		"no run":       func(c *capability) { c.Commands["run"].Run = nil },
		"name":         func(c *capability) { c.Name = "a_b" },
		"command name": func(c *capability) { c.Commands["a b"] = c.Commands["run"] },
		"tool name":    func(c *capability) { c.Commands[strings.Repeat("x", maxToolName-len(c.Name))] = c.Commands["run"] },
		"result":       func(c *capability) { c.Commands["run"].Result = "application/json" },
		"timeout":      func(c *capability) { c.Commands["run"].Timeout = "1m" },
		"maxValidity":  func(c *capability) { c.Commands["run"].MaxValidity = "forever" },
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

// The config's host commands load under their names; a name taken twice stops the daemon
func TestLoadCommands(t *testing.T) {
	cfg := commandConfig{Name: "vm", Description: "a VM", Commands: map[string]*hostCommand{
		"shot": {Description: "a screenshot", Run: []string{"/bin/true"}, Result: "image/png"}}}
	caps := map[string]*capability{}
	if err := loadCommands([]commandConfig{cfg}, caps); err != nil {
		t.Fatal(err)
	}
	c := caps["vm"]
	if c == nil || c.Type != "command" || c.Commands["shot"].Timeout != defaultTimeout {
		t.Errorf("Loaded %+v", c)
	}
	again := cfg
	again.Commands = map[string]*hostCommand{"shot": {Description: "again", Run: []string{"/bin/true"}}}
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

// The scope's parts, as the window gets them with the capability: unrestricted free arguments first, each with what its
// schema allows, and the bounding values by their descriptions for the notification's body
func TestScopeItems(t *testing.T) {
	c := testCap(t, "command")
	c.Params["cert"] = json.RawMessage(`{"type": "string", "opaque": true, "description": "the key"}`)
	c.Commands["exec"] = &hostCommand{Description: "Run PowerShell", Run: []string{"/bin/true"},
		Arguments: map[string]json.RawMessage{"script": json.RawMessage(`{"type": "string", "multiline": true,
			"description": "any PowerShell, as SYSTEM"}`)}}
	c.Commands["keys"] = &hostCommand{Description: "Press keys", Run: []string{"/bin/true"},
		Arguments: map[string]json.RawMessage{"key": json.RawMessage(`{"type": "string", "enum": ["a", "b"],
			"description": "a key"}`)}}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	b, _ := testBroker(t)
	b.caps = map[string]*capability{c.id(): c}
	got := b.listCapabilities()[0].Scope
	want := []scopeItem{
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
	if bounds := c.bounds(params); bounds != `the key is `+opaqueDigest(strings.Repeat("k", 40))+
		` and a path is "/a" and read-only is true` {
		t.Errorf("bounds = %s", bounds)
	}
}
