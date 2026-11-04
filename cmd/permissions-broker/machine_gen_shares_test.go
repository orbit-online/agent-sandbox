package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/hostcmd"
	"pgregory.net/rapid"
)

// The generators produce valid and invalid inputs at useful rates, by the oracle: each kind's valid share between a
// fifth and nine tenths. go test -v logs the shares

// sharesOracle is the oracle's view of the state machine's capabilities, without a world
func sharesOracle() map[string]*oracleCap {
	name := json.RawMessage(fmt.Sprintf(declVMName, "/run/vms/*/console.sock"))
	infos := []capabilityInfo{
		{ID: capVM, Type: "command", Params: map[string]json.RawMessage{"name": name, "ro": json.RawMessage(declRO)},
			Commands: map[string]*hostcmd.Command{"start": {}}},
		{ID: capConsole, Type: "socket", Params: map[string]json.RawMessage{"name": name}},
		{ID: capToken, Type: "command", Params: map[string]json.RawMessage{"scope": json.RawMessage(declScope),
			"csr": json.RawMessage(declCSR), "slot": json.RawMessage(declSlot)},
			Commands: map[string]*hostcmd.Command{"issue": {}, "sign": {Arguments: rawArgs(signArgs)}}},
		{ID: capFolder, Type: "attach", Params: map[string]json.RawMessage{
			"path": json.RawMessage(`{"type": "string", "description": "a folder"}`), "ro": json.RawMessage(declRO)}},
	}
	caps := oracleCaps(infos)
	caps[capVM].exclusive = true
	caps[capToken].maxValidity = maxValidity
	return caps
}

func TestGeneratorShares(t *testing.T) {
	caps := sharesOracle()
	root := "/srv/ceiling"
	ceil := &ceiling{sources: []folderSource{{path: root}, {path: root + "/w", rw: true}}, denied: []string{root + "/d/secret"},
		folders: map[string]bool{root: true, root + "/x": true, root + "/w": true}}
	names := []string{"a", "b", "vm7"}
	m := newModel(time.Now(), caps, ceil, nil)
	m.shared, m.lockOK = true, true
	for _, n := range names {
		m.listed[n] = true
	}
	shape := requestShape{caps: caps, ids: slices.Sorted(maps.Keys(caps)), callIDs: []string{capToken, capToken, capVM},
		hint: func(t *rapid.T, id, arg string) (string, bool) {
			switch {
			case arg == "name" && (id == capVM || id == capConsole):
				n := rapid.SampledFrom(names).Draw(t, "instance")
				if !often(t, 8, "known") {
					n = drawInstanceName(t)
				}
				return encodeString(t, n), true
			case arg == "path" && id == capFolder:
				return encodeString(t, drawPath(t, []string{root, root + "/w", "/srv/outside"})), true
			}
			return "", false
		}}
	kinds := map[string]func(*rapid.T) bool{
		"capability id": func(t *rapid.T) bool { return caps[drawName(t, shape.ids, "id")] != nil },
		"lease": func(t *rapid.T) bool {
			_, ok := leaseKind(drawLease(t))
			return ok
		},
		"reason":        func(t *rapid.T) bool { return oracleReason(drawReason(t, "")) != "" },
		"instance name": func(t *rapid.T) bool { return caps[capVM].params["name"].accepts(drawInstanceName(t), oracleMaxParam) },
		"folder path": func(t *rapid.T) bool {
			ok, _ := ceil.allows(drawPath(t, []string{root, root + "/w", "/srv/outside"}), true)
			return ok
		},
		"grant id": func(t *rapid.T) bool { return drawGrantID(t, []string{"live1", "live2"}, []string{"old"})[0] == 'l' },
		"token params": func(t *rapid.T) bool {
			return paramsOK(caps[capToken].params, drawObject(t, caps[capToken].params, oracleMaxParam, false,
				often(t, 7, "valid"), nil))
		},
		"sign arguments": func(t *rapid.T) bool {
			d := caps[capToken].commands["sign"]
			return argumentsOK(d, drawObject(t, d, oracleMaxFree, true, often(t, 7, "valid"), nil))
		},
		"request": func(t *rapid.T) bool {
			r := shape.draw(t, false, "why")
			return !m.judge(false, r.Capability, r.Command, r.Params, r.Arguments, r.Reason, r.Lease).refused()
		},
		"call": func(t *rapid.T) bool {
			r := shape.draw(t, true, "why")
			return !m.judge(true, r.Capability, r.Command, r.Params, r.Arguments, r.Reason, r.Lease).refused()
		},
	}
	for _, name := range slices.Sorted(maps.Keys(kinds)) {
		gen := rapid.Custom(kinds[name])
		valid, n := 0, 2000
		for i := range n {
			if gen.Example(i) {
				valid++
			}
		}
		share := float64(valid) / float64(n)
		t.Logf("%-15s %3.0f%% valid", name, 100*share)
		if share < 0.2 || share > 0.9 {
			t.Errorf("%s: %.0f%% valid", name, 100*share)
		}
	}
}
