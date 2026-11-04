package main

import (
	"encoding/json"
	"maps"
	"slices"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/hostcmd"
)

// The state machine's capabilities as declared (machine_world_test.go builds the broker's from these) and as the
// oracle reads them: a host command capability whose free arguments use every keyword of the schema subset, bounding
// values of each scalar type, opaque ones

var (
	// Bounding: the VMs and their consoles by instance, read-only or not
	declVMName = `{"type": "string", "description": "the VM", "instances": "%s"}`
	declRO     = `{"type": "boolean", "description": "read-only"}`
	// Bounding: a token's scope, a CSR (opaque), a slot
	declScope = `{"type": "string", "description": "its scope"}`
	declCSR   = `{"type": "string", "opaque": true, "description": "a CSR"}`
	declSlot  = `{"type": "integer", "minimum": 0, "maximum": 9, "description": "a slot"}`
	// The free arguments of token's sign
	signArgs = map[string]string{
		"count":  `{"type": "integer", "minimum": 0, "maximum": 7679, "description": "a column"}`,
		"ratio":  `{"type": "number", "minimum": -1.5, "maximum": 2.5, "description": "a ratio"}`,
		"level":  `{"type": "number", "enum": [1, 2.5, 1000], "description": "a level"}`,
		"mode":   `{"type": "string", "enum": ["fast", "slow", "ünï"], "description": "a mode"}`,
		"tag":    `{"type": "string", "pattern": "[a-z][a-z0-9-]{0,15}", "description": "a tag"}`,
		"script": `{"type": "string", "multiline": true, "maxLength": 300, "description": "a script"}`,
		"note":   `{"type": "string", "description": "any text"}`,
		"key":    `{"type": "string", "opaque": true, "description": "a public key"}`,
		"flag":   `{"type": "boolean", "description": "a flag"}`,
		"ports": `{"type": "array", "items": {"type": "integer", "minimum": 1, "maximum": 65535, "description": "a port"},
			"maxItems": 3, "description": "ports"}`,
	}
)

func rawArgs(m map[string]string) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for k, v := range m {
		out[k] = json.RawMessage(v)
	}
	return out
}

// oracleCap is a capability as the oracle knows it from its declaration
type oracleCap struct {
	typ      string
	params   map[string]*decl
	commands map[string]map[string]*decl
	// The bounding argument instances name, if any
	instanceArg string
	exclusive   bool
	// The validity the commands' calls are told at most, none if 0
	maxValidity time.Duration
}

func declsOf(raw map[string]json.RawMessage) map[string]*decl {
	out := map[string]*decl{}
	for k, v := range raw {
		out[k] = readDecl(v)
	}
	return out
}

// oracleCaps reads the capabilities as the list shows them, the declarations alone
func oracleCaps(infos []capabilityInfo) map[string]*oracleCap {
	caps := map[string]*oracleCap{}
	for _, i := range infos {
		c := &oracleCap{typ: i.Type, params: declsOf(i.Params), commands: map[string]map[string]*decl{}}
		for name, cmd := range i.Commands {
			c.commands[name] = declsOf(cmd.Arguments)
		}
		for k, d := range c.params {
			if d.Instances != "" {
				c.instanceArg = k
				// The docs: a host socket's instance names its address, of 80 characters at most
				if c.typ == "socket" && (d.MaxLength == nil || *d.MaxLength > 80) {
					n := 80
					d.MaxLength = &n
				}
			}
		}
		caps[i.ID] = c
	}
	return caps
}

// worldOracle is the oracle's view of the state machine's capabilities: from their declarations, with what the list
// doesn't show (exclusive, maxValidity) from the config
func worldOracle(caps map[string]*capability) map[string]*oracleCap {
	var infos []capabilityInfo
	for _, id := range slices.Sorted(maps.Keys(caps)) {
		c := caps[id]
		i := capabilityInfo{ID: id, Type: c.Type, Params: c.Params, Commands: map[string]*hostcmd.Command{}}
		for name, cmd := range c.Commands {
			i.Commands[name] = &hostcmd.Command{Arguments: cmd.Arguments}
		}
		infos = append(infos, i)
	}
	out := oracleCaps(infos)
	out[capVM].exclusive = true
	out[capToken].maxValidity = maxValidity
	return out
}
