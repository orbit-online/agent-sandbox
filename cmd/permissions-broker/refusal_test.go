package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/hostcmd"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/schema"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
)

// Requests the state machines once sampled, kept as examples: each refused with its category, or served, as the
// oracle (machine_oracle_test.go) says too. The machines draw theirs from the declarations

// exampleBroker is a broker with the state machine's token capability (machine_decls_test.go), its calls printing
// their input, and a D-Bus capability that takes no calls
func exampleBroker(t *testing.T, answers ...string) (*broker, *fakeAsker, map[string]*oracleCap) {
	b, f := testBroker(t, answers...)
	fakeSystemd(t)
	run := filepath.Join(t.TempDir(), "run")
	if err := os.WriteFile(run, []byte("#!/bin/sh\ncat\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	token := &capability{Name: capToken, Type: "command", Description: "a token",
		Params: map[string]json.RawMessage{"scope": json.RawMessage(declScope), "csr": json.RawMessage(declCSR),
			"slot": json.RawMessage(declSlot)},
		Commands: map[string]*hostcmd.Command{
			"issue": {Description: "issue one", Run: []string{run}},
			"sign":  {Description: "sign something", Run: []string{run}, Arguments: rawArgs(signArgs)},
		}}
	if err := token.check(); err != nil {
		t.Fatal(err)
	}
	b.caps[capToken] = token
	caps := sharesOracle()
	delete(caps, capVM)
	delete(caps, capConsole)
	delete(caps, capFolder)
	return b, f, caps
}

var signOK = `{"count": 7679, "ratio": -1.5, "level": 1e3, "mode": "ünï", "tag": "a-1", "script": "a\n\tb",
	"note": "", "key": "AAAA", "flag": false, "ports": [1, 65535]}`

// signWith is signOK with one argument replaced
func signWith(arg, value string) string {
	var m map[string]json.RawMessage
	_ = json.Unmarshal([]byte(signOK), &m)
	m[arg] = json.RawMessage(value)
	data, _ := json.Marshal(m)
	return string(data)
}

func TestRefusalExamples(t *testing.T) {
	long := func(c string, n int) string { return `"` + strings.Repeat(c, n) + `"` }
	for _, tc := range []struct {
		req  wire.Request
		want refusal // none: served
	}{
		{wire.Request{Capability: "other", Params: json.RawMessage(`{"name":"a"}`)}, refUnknown},
		{wire.Request{Capability: capToken + " ", Params: json.RawMessage(`{}`)}, refUnknown},
		{wire.Request{Capability: capToken, Params: json.RawMessage(`{"scope":"a","unit":"evil"}`)}, refParams},
		{wire.Request{Capability: capToken, Params: json.RawMessage(`{"scope":5}`)}, refParams},
		{wire.Request{Capability: capToken, Params: json.RawMessage(`{"scope":"a\nAllowed"}`)}, refParams},
		{wire.Request{Capability: capToken, Params: json.RawMessage(`{"scope":` + long("w", maxParam+1) + `}`)}, refParams},
		{wire.Request{Capability: capToken, Params: json.RawMessage(`{"scope":` + long("é", maxParam) + `}`)}, ""},
		{wire.Request{Capability: capToken, Params: json.RawMessage(`{"csr":` + long("C", schema.MaxOpaque+1) + `}`)},
			refParams},
		{wire.Request{Capability: capToken, Params: json.RawMessage(`{"csr":` + long("C", schema.MaxOpaque) + `}`)}, ""},
		{wire.Request{Capability: capToken, Params: json.RawMessage(`{"csr":"MIIB\nAllowed"}`)}, refParams},
		{wire.Request{Capability: capToken, Params: json.RawMessage(`["scope"]`)}, refParams},
		{wire.Request{Capability: capToken, Params: json.RawMessage(`{"slot":10}`)}, refParams},
		{wire.Request{Capability: capToken, Params: json.RawMessage(`{"slot":1.0}`)}, refParams},
		{wire.Request{Capability: capToken, Params: json.RawMessage(`{"slot":9}`)}, ""},
		{wire.Request{Capability: capToken, Params: json.RawMessage(`null`)}, ""},
		{wire.Request{Capability: capToken, Reason: " \n\x07\t "}, refReason},
		{wire.Request{Capability: capToken, Lease: "session"}, refLease},
		{wire.Request{Capability: capToken, Lease: "forever"}, refLease},
		{wire.Request{Capability: capToken, Lease: "PT0S"}, refLease},
		{wire.Request{Capability: capToken, Lease: "once"}, refLease},
		{wire.Request{Capability: capToken, Lease: "PT5124096H"}, refLease},
		{wire.Request{Capability: capToken, Lease: "PT1H30M", Params: json.RawMessage(`{"scope":"é😀​"}`)}, ""},
		{wire.Request{Op: "call", Capability: capToken, Command: "other"}, refUnknown},
		{wire.Request{Op: "call", Capability: capToken, Command: "issue", Arguments: json.RawMessage(`{"extra":1}`)},
			refArguments},
		{wire.Request{Op: "call", Capability: capToken, Command: "sign", Arguments: json.RawMessage(signOK)}, ""},
		{wire.Request{Op: "call", Capability: capToken, Command: "sign", Arguments: json.RawMessage(signWith("count", "1.0"))},
			refArguments},
		{wire.Request{Op: "call", Capability: capToken, Command: "sign",
			Arguments: json.RawMessage(signWith("ratio", "2.50000000000000001"))}, refArguments},
		{wire.Request{Op: "call", Capability: capToken, Command: "sign",
			Arguments: json.RawMessage(signWith("script", long("x", 301)))}, refArguments},
		{wire.Request{Op: "call", Capability: capToken, Command: "sign",
			Arguments: json.RawMessage(signWith("note", long("x", hostcmd.MaxFree)))}, ""},
		{wire.Request{Op: "call", Capability: capToken, Command: "sign",
			Arguments: json.RawMessage(signWith("ports", "[1, 2, 3, 4]"))}, refArguments},
	} {
		b, _, caps := exampleBroker(t, "allow")
		m := newModel(b.now(), caps, &ceiling{}, nil)
		r := tc.req
		if r.Op == "" {
			r.Op = "request"
		}
		if r.Reason == "" {
			r.Reason = "to test"
		}
		v := m.judge(r.Op == "call", r.Capability, r.Command, r.Params, r.Arguments, r.Reason, r.Lease)
		res := b.handleRequest(nil, peerAt(t, os.Getpid()), r)
		about := compressRuns(string(r.Params) + " " + string(r.Arguments) + " " + r.Lease)
		switch {
		case tc.want == "" && (v.refused() || res.Error != ""):
			t.Errorf("%s %s: refused (%s %q; oracle %v), want served", r.Op, about, res.Refused, res.Error, v.broken)
		case tc.want != "" && (res.Refused != tc.want || !refusedAs(res, v)):
			t.Errorf("%s %s: %s %q (oracle %v), want refused as %s", r.Op, about, res.Refused, res.Error, v.broken, tc.want)
		}
	}
}

// release and revoke of a grant there isn't
func TestNoGrantRefused(t *testing.T) {
	b, _, _ := exampleBroker(t)
	res := b.handleRequest(nil, peerAt(t, os.Getpid()), wire.Request{Op: "release", Grant: "0123456789abcdef"})
	if res.Refused != refNoGrant {
		t.Errorf("Release of no grant: %+v", res)
	}
	if res := b.handleControl(nil, peerAt(t, os.Getpid()), wire.Request{Op: "revoke"}); res.Refused != refNoGrant {
		t.Errorf("Revoke of no grant: %+v", res)
	}
}
