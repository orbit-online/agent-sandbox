package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Each keyword of the schema subset lets through what it allows and nothing else
func TestSchemaValues(t *testing.T) {
	for _, tc := range []struct {
		schema string
		ok     []string
		bad    []string
	}{
		{`{"type": "string"}`, []string{`"a"`, `"` + strings.Repeat("x", 10) + `"`},
			[]string{`5`, `true`, `"a\nb"`, `"a\u0007"`, `"` + strings.Repeat("x", 11) + `"`}},
		{`{"type": "string", "multiline": true}`, []string{`"a\nb\tc"`}, []string{`"a\u0007"`, `"a\rb"`}},
		{`{"type": "string", "maxLength": 3}`, []string{`"abc"`}, []string{`"abcd"`}},
		{`{"type": "string", "opaque": true}`, []string{`"` + strings.Repeat("x", maxOpaque) + `"`},
			[]string{`"` + strings.Repeat("x", maxOpaque+1) + `"`}},
		// A pattern matches the whole value
		{`{"type": "string", "pattern": "[a-z]+"}`, []string{`"abc"`}, []string{`"abc1"`, `"1abc"`, `""`}},
		{`{"type": "string", "enum": ["a", "b"]}`, []string{`"a"`, `"b"`}, []string{`"c"`}},
		{`{"type": "integer", "minimum": 0, "maximum": 10}`, []string{`0`, `10`}, []string{`-1`, `11`, `1.5`, `"1"`}},
		{`{"type": "number", "maximum": 1}`, []string{`0.5`, `1`}, []string{`1.5`}},
		{`{"type": "integer", "enum": [1, 3]}`, []string{`3`}, []string{`2`}},
		// Exactly, past what a float64 tells apart
		{`{"type": "integer", "maximum": 9007199254740992}`, []string{`9007199254740992`}, []string{`9007199254740993`}},
		{`{"type": "boolean"}`, []string{`true`, `false`}, []string{`"true"`, `1`}},
		{`{"type": "array", "items": {"type": "string", "enum": ["x", "y"]}, "maxItems": 2}`,
			[]string{`[]`, `["x", "y"]`}, []string{`["x", "y", "x"]`, `["z"]`, `"x"`}},
	} {
		s, err := parseSchema(json.RawMessage(tc.schema))
		if err != nil {
			t.Fatalf("%s: %v", tc.schema, err)
		}
		for _, list := range []struct {
			values []string
			want   bool
		}{{tc.ok, true}, {tc.bad, false}} {
			for _, v := range list.values {
				m, err := decodeObject(json.RawMessage(`{"v": ` + v + `}`))
				if err != nil {
					t.Fatal(err)
				}
				if err := s.checkValue(m["v"], 10); (err == nil) != list.want {
					t.Errorf("%s with %s: %v, want ok=%v", tc.schema, v, err, list.want)
				}
			}
		}
	}
}

// Schemas the broker can't check, or keywords on types they don't fit, are config errors
func TestSchemaRefused(t *testing.T) {
	for _, schema := range []string{
		`{"type": "object"}`,
		`{"type": "integer", "pattern": "1"}`,
		`{"type": "string", "minimum": 1}`,
		`{"type": "string", "pattern": "("}`,
		`{"type": "array"}`,
		`{"type": "string", "items": {"type": "string"}}`,
		`{"type": "array", "items": {"type": "array", "items": {"type": "string"}}}`,
		`{"type": "string", "enum": [1]}`,
		`{"type": "boolean", "opaque": true}`,
	} {
		if _, err := parseSchema(json.RawMessage(schema)); err == nil {
			t.Errorf("%s accepted", schema)
		}
	}
}

// What the consent says a schema allows, and which free arguments it calls unrestricted
func TestSchemaScope(t *testing.T) {
	c := testCap(t, "command")
	c.Commands["exec"] = &hostCommand{Description: "Run PowerShell", Run: []string{"/bin/true"},
		Arguments: map[string]json.RawMessage{"script": json.RawMessage(`{"type": "string", "multiline": true,
			"description": "any PowerShell, as SYSTEM"}`)}}
	c.Commands["click"] = &hostCommand{Description: "Click", Run: []string{"/bin/true"},
		Arguments: map[string]json.RawMessage{"x": json.RawMessage(`{"type": "integer", "minimum": 0,
			"maximum": 99, "description": "column"}`)}}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	want := "Run PowerShell: any PowerShell, as SYSTEM, unrestricted (exec). Click: column, a number within 0–99 " +
		"(click). print the input (run)."
	if got := c.scope(); got != want {
		t.Errorf("scope = %q\nwant    %q", got, want)
	}
}

// A long enum (windows-vm's 161 key names) reads as a count, a short one as its values
func TestSchemaLongEnum(t *testing.T) {
	names := make([]string, 161)
	for i := range names {
		names[i] = fmt.Sprintf("%q", fmt.Sprintf("k%d", i))
	}
	for schema, want := range map[string]string{
		`{"type": "string", "enum": [` + strings.Join(names, ", ") + `]}`:                             "one of 161 values",
		`{"type": "string", "enum": [` + strings.Join(names[:maxListedEnum], ", ") + `]}`:             "one of [k0 k1 k2 k3 k4 k5 k6 k7]",
		`{"type": "array", "items": {"type": "string", "enum": [` + strings.Join(names, ", ") + `]}}`: "a list of one of 161 values",
	} {
		s, err := parseSchema(json.RawMessage(schema))
		if err != nil {
			t.Fatal(err)
		}
		if got := s.allows(); got != want {
			t.Errorf("allows = %q, want %q", got, want)
		}
	}
}
