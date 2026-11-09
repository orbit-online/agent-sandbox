package main

import (
	"encoding/json"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mountinfo"
)

// overviewState is the config's overview for the window, with `absent` added: the optional binds and the devices
// that aren't mounted in the sandbox's mount namespace, which nixpak binds only where they exist at launch. As
// configured, without `absent`, when the sandbox's mount table can't be read
func (b *broker) overviewState() json.RawMessage {
	if len(b.cfg.Overview) == 0 || b.sb == nil {
		return b.cfg.Overview
	}
	lines, err := b.sb.Mountinfo()
	if err != nil {
		return b.cfg.Overview
	}
	return withAbsent(b.cfg.Overview, lines)
}

// withAbsent adds to overview the paths of its optional binds and its devices that no line of a mount table has as its
// mount point, an empty list when all are there. The overview unchanged when it isn't an object
func withAbsent(overview json.RawMessage, lines []mountinfo.Line) json.RawMessage {
	var o map[string]json.RawMessage
	if err := json.Unmarshal(overview, &o); err != nil || o == nil {
		return overview
	}
	var binds []struct {
		Path     string `json:"path"`
		Optional bool   `json:"optional"`
	}
	var devices []string
	if raw, ok := o["binds"]; ok {
		_ = json.Unmarshal(raw, &binds)
	}
	if raw, ok := o["devices"]; ok {
		_ = json.Unmarshal(raw, &devices)
	}
	mounted := make(map[string]bool, len(lines))
	for _, l := range lines {
		mounted[l.Point] = true
	}
	absent := []string{}
	for _, bind := range binds {
		if bind.Optional && !mounted[bind.Path] {
			absent = append(absent, bind.Path)
		}
	}
	for _, d := range devices {
		if !mounted[d] {
			absent = append(absent, d)
		}
	}
	o["absent"], _ = json.Marshal(absent)
	out, err := json.Marshal(o)
	if err != nil {
		return overview
	}
	return out
}
