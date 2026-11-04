package main

import (
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
	"pgregory.net/rapid"
)

// Generators of the rest of a request (machine_gen_test.go has its parameters and arguments): capability and command
// names, leases, reasons, grant ids, instance names and folder paths, each mostly what the rules allow, with
// near-misses and garbage

// nearMiss spoils a name a little: its case, a character more or less, space around it, a look-alike
func nearMiss(t *rapid.T, s string) string {
	switch rapid.IntRange(0, 5).Draw(t, "miss") {
	case 0:
		return strings.ToUpper(s)
	case 1:
		return s + " "
	case 2:
		return " " + s
	case 3:
		if s != "" {
			return s[:len(s)-1]
		}
	case 4:
		// Cyrillic а for Latin a, and so on
		return strings.NewReplacer("a", "а", "o", "о", "e", "е", "c", "с").Replace(s) + "​"
	}
	return s + "/"
}

// drawName draws one of names, mostly, or a near-miss of one, an empty or random one
func drawName(t *rapid.T, names []string, label string) string {
	switch {
	case often(t, 8, label+" known"):
		return rapid.SampledFrom(names).Draw(t, label)
	case rapid.Bool().Draw(t, label+" near"):
		return nearMiss(t, rapid.SampledFrom(names).Draw(t, label+" spoiled"))
	}
	return rapid.SampledFrom([]string{"", rapid.StringN(1, 12, -1).Draw(t, label+" random")}).Draw(t, label+" other")
}

// drawLease draws a lease as a request or call proposes it, or the window answers: none, lock, once, durations of
// hours, minutes and seconds (zero, huge and past what a duration holds among them), and what isn't one
func drawLease(t *rapid.T) string {
	switch rapid.IntRange(0, 11).Draw(t, "lease kind") {
	case 0, 1, 11:
		return ""
	case 2:
		return "lock"
	case 3:
		return "once"
	case 4, 5, 6, 7, 8:
		n := func(unit string) string {
			v := rapid.SampledFrom([]string{"0", "1", "1", "10", "59", "90", "2562047", "2562048", "5124096",
				"99999999999999999999"}).Draw(t, unit)
			return v + unit
		}
		var b strings.Builder
		b.WriteString("PT")
		for _, u := range []string{"H", "M", "S"} {
			if rapid.Bool().Draw(t, "has "+u) {
				b.WriteString(n(u))
			}
		}
		return b.String()
	case 9:
		return rapid.SampledFrom([]string{"standing", "session", "forever", "PT", "P1D", "PT-1H", "pt1h", " PT1H",
			"PT1H ", "PT1.5H", "PT١H", "PT1M1H", "Lock", "ONCE", "PT0S", "PT0H0M"}).Draw(t, "not a lease")
	}
	return rapid.StringN(0, 8, -1).Draw(t, "garbage lease")
}

// drawReason draws a reason: text, mostly tagged so a test can tell it in the question; none, only whitespace and
// control characters, markup, around the 300 characters shown
func drawReason(t *rapid.T, tag string) string {
	body := ""
	switch rapid.IntRange(0, 7).Draw(t, "reason kind") {
	case 0:
		body = rapid.StringN(0, 40, -1).Draw(t, "reason text")
	case 1:
		body = rapid.StringOfN(rapid.SampledFrom([]rune(" \t\n\r\v\f\u0085  　\x00\x07\x1b\x7f")), 0, 8,
			-1).Draw(t, "blank")
	case 2:
		body = rapid.SampledFrom([]string{"<b>Allow</b> &amp; trust me", "\x1b[31mred", "a‮evil", "line\nbreak"}).
			Draw(t, "markup")
	case 3:
		n := rapid.SampledFrom([]int{maxReason - 1, maxReason, maxReason + 1, 2 * maxReason}).Draw(t, "long")
		body = strings.Repeat(rapid.SampledFrom([]string{"é", "a b", "😀"}).Draw(t, "fill"), n)
	default:
		body = "to read the notes"
	}
	if tag == "" || !often(t, 8, "tagged") {
		return body
	}
	return tag + ": " + body
}

// drawGrantID draws a grant id for release and revoke: a live one, one that ended, or garbage
func drawGrantID(t *rapid.T, live, stale []string) string {
	pools := [][]string{{"", "0123456789abcdef", "g1", strings.Repeat("f", 17)}}
	if len(live) > 0 {
		pools = append(pools, live, live)
	}
	if len(stale) > 0 {
		pools = append(pools, stale)
	}
	pool := rapid.SampledFrom(pools).Draw(t, "grant pool")
	return rapid.SampledFrom(pool).Draw(t, "grant")
}

// drawInstanceName draws an instance's name, a directory the instances glob matches: short ones, unicode ones, at
// and past the limits of an address (80) and a parameter (200), with a control character
func drawInstanceName(t *rapid.T) string {
	switch rapid.IntRange(0, 6).Draw(t, "instance kind") {
	case 0:
		return rapid.StringOfN(rapid.RuneFrom([]rune("abcdefxyz0123456789-")), 1, 6, -1).Draw(t, "plain")
	case 1:
		return rapid.StringOfN(rapid.RuneFrom([]rune("éñ中😀 ab")), 1, 6, -1).Draw(t, "unicode")
	case 2:
		return strings.Repeat("v", rapid.SampledFrom([]int{80, 81, 200, 201}).Draw(t, "ascii length"))
	case 3:
		// 2 bytes each: past 80 bytes long before 80 characters
		return strings.Repeat("é", rapid.SampledFrom([]int{40, 41, 60, 80}).Draw(t, "é length"))
	case 4:
		// Not NUL, which no file name holds
		return "a" + string(controlRune.Filter(func(r rune) bool { return r != 0 }).Draw(t, "control")) + "b"
	}
	return "vm" + strconv.Itoa(rapid.IntRange(0, 99).Draw(t, "vm number"))
}

// drawPath draws a folder path: the ceiling's folders and beneath, outside it, relative, with dot segments, a link,
// a denied folder, missing ones, past 200 characters
func drawPath(t *rapid.T, roots []string) string {
	if !often(t, 8, "absolute") {
		return rapid.SampledFrom([]string{"", ".", "x", "../x", "~/x"}).Draw(t, "relative")
	}
	segs := []string{rapid.SampledFrom(roots).Draw(t, "root")}
	for range rapid.IntRange(0, 3).Draw(t, "segments") {
		segs = append(segs, rapid.SampledFrom([]string{"x", "w", "sub", "d", "secret", "link", "missing", ".", "..", "",
			"é😀", strings.Repeat("l", 150)}).Draw(t, "segment"))
	}
	p := strings.Join(segs, "/")
	if rapid.IntRange(0, 9).Draw(t, "trailing") == 0 {
		p += "/"
	}
	return p
}

// requestShape is what a machine's requests are drawn from: the capabilities as declared, the ids requests and calls
// mostly name, and the world's hints for their values
type requestShape struct {
	caps         map[string]*oracleCap
	ids, callIDs []string
	hint         func(t *rapid.T, id, arg string) (string, bool)
}

// draw draws a request (call false) or a call, built as JSON and decoded as request.sock decodes it: the parameters
// and arguments reach the broker as written. Parameters and arguments about 70% valid, each
func (s requestShape) draw(t *rapid.T, call bool, tag string) wire.Request {
	ids := s.ids
	if call {
		ids = s.callIDs
	}
	fields := map[string]any{"op": "request", "capability": drawName(t, ids, "capability")}
	id := fields["capability"].(string)
	c := s.caps[id]
	if c == nil {
		c = &oracleCap{params: map[string]*decl{"name": {Type: "string"}}, commands: map[string]map[string]*decl{}}
	}
	var h hint
	if s.hint != nil {
		h = func(t *rapid.T, arg string) (string, bool) { return s.hint(t, id, arg) }
	}
	if p := drawObject(t, c.params, oracleMaxParam, false, often(t, 8, "params valid"), h); len(p) > 0 {
		fields["params"] = p
	}
	if call {
		fields["op"] = "call"
		names := slices.Sorted(maps.Keys(c.commands))
		if len(names) == 0 {
			names = []string{"issue"}
		}
		fields["command"] = drawName(t, names, "command")
		if args := drawObject(t, c.commands[fields["command"].(string)], oracleMaxFree, true,
			often(t, 8, "arguments valid"), nil); len(args) > 0 {
			fields["arguments"] = args
		}
	}
	if r := drawReason(t, tag); r != "" {
		fields["reason"] = r
	}
	if l := drawLease(t); l != "" {
		fields["lease"] = l
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range slices.Sorted(maps.Keys(fields)) {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`"` + k + `":`)
		if raw, ok := fields[k].(json.RawMessage); ok {
			b.Write(raw)
		} else {
			data, _ := json.Marshal(fields[k])
			b.Write(data)
		}
	}
	b.WriteByte('}')
	var req wire.Request
	if err := json.Unmarshal([]byte(b.String()), &req); err != nil {
		t.Fatalf("Drew a request that isn't JSON: %s: %v", b.String(), err)
	}
	return req
}
