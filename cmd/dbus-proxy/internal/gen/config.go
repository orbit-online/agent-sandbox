package gen

import (
	"encoding/json"
	"fmt"
	"strings"

	"pgregory.net/rapid"
)

// ConfigNames are where a config's names and its rules' parts come from
type ConfigNames struct {
	Name, Path, Iface, Member *rapid.Generator[string]
}

// One name's entry: its members' keys and JSON values, in order
type cfgEntry struct {
	name   string
	fields [][2]string
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func quoteList(l []string) string {
	q := make([]string, len(l))
	for i, s := range l {
		q[i] = quote(s)
	}
	return "[" + strings.Join(q, ",") + "]"
}

// A rule: any method, an interface's, or one method, on any path, one, or a subtree; never empty
func cfgRule(t *rapid.T, n ConfigNames) string {
	var method, path string
	switch rapid.IntRange(0, 4).Draw(t, "method") {
	case 1:
		method = "*"
	case 2:
		method = n.Iface.Draw(t, "iface") + ".*"
	case 3, 4:
		method = n.Iface.Draw(t, "iface") + "." + n.Member.Draw(t, "member")
	}
	switch rapid.IntRange(0, 3).Draw(t, "path") {
	case 1:
		path = "@" + n.Path.Draw(t, "path")
	case 2:
		if p := n.Path.Draw(t, "path"); p != "/" {
			path = "@" + p + "/*"
		}
	case 3:
		path = "@/*"
	}
	if method == "" && path == "" {
		method = "*"
	}
	return method + path
}

// An entry: a policy, call and broadcast rules, or both, its fields in any order
func cfgEntryOf(t *rapid.T, n ConfigNames, name string) cfgEntry {
	e := cfgEntry{name: name}
	if p := rapid.SampledFrom([]string{"", "see", "talk", "own"}).Draw(t, "policy"); p != "" {
		e.fields = append(e.fields, [2]string{"policy", quote(p)})
	}
	for _, kind := range []string{"call", "broadcast"} {
		if k := rapid.IntRange(-2, 3).Draw(t, kind); k >= 0 {
			rules := make([]string, k)
			for i := range rules {
				rules[i] = cfgRule(t, n)
			}
			e.fields = append(e.fields, [2]string{kind, quoteList(rules)})
		}
	}
	gives := false
	for _, f := range e.fields {
		gives = gives || f[1] != "[]"
	}
	if !gives {
		e.fields = append(e.fields, [2]string{"policy", quote("see")})
	}
	e.fields = rapid.Permutation(e.fields).Draw(t, "order")
	return e
}

// Renders entries as a JSON object, with whitespace between the tokens now and then
func render(t *rapid.T, entries []cfgEntry) string {
	ws := func() string { return rapid.SampledFrom([]string{"", "", " ", "\n  "}).Draw(t, "ws") }
	var b strings.Builder
	b.WriteString(ws() + "{")
	for i, e := range entries {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(ws() + quote(e.name) + ws() + ":" + ws() + "{")
		for j, f := range e.fields {
			if j > 0 {
				b.WriteString(",")
			}
			b.WriteString(ws() + quote(f[0]) + ":" + ws() + f[1])
		}
		b.WriteString("}")
	}
	b.WriteString(ws() + "}" + ws())
	return b.String()
}

// Config: the proxy's static rules as JSON. Without misses, valid when the names drawn are: up to five names, each
// once. With them, a near miss one time in three: a field unknown or of another case, a policy that isn't, a name
// that isn't (a wildcard, a unique name, the bus driver's), a name or field twice, an entry giving nothing, a rule
// that isn't, a null, not an object, data after it, a cap reached and passed (names, rules, bytes), or cut short
func Config(n ConfigNames, misses bool) *rapid.Generator[[]byte] {
	return rapid.Custom(func(t *rapid.T) []byte {
		var entries []cfgEntry
		seen := map[string]bool{}
		for range rapid.IntRange(0, 5).Draw(t, "names") {
			if name := n.Name.Draw(t, "name"); !seen[name] {
				seen[name] = true
				entries = append(entries, cfgEntryOf(t, n, name))
			}
		}
		if !misses || rapid.IntRange(0, 2).Draw(t, "miss") > 0 {
			return []byte(render(t, entries))
		}
		return []byte(cfgMiss(t, n, entries))
	})
}

func cfgMiss(t *rapid.T, n ConfigNames, entries []cfgEntry) string {
	some := func() *cfgEntry {
		if len(entries) == 0 {
			entries = append(entries, cfgEntryOf(t, n, "org.test.Miss"))
		}
		return &entries[rapid.IntRange(0, len(entries)-1).Draw(t, "entry")]
	}
	// Sets a field of some entry, in place if it has one: a field twice is a miss of its own
	set := func(key, val string) {
		e := some()
		for i, f := range e.fields {
			if f[0] == key {
				e.fields[i][1] = val
				return
			}
		}
		e.fields = append(e.fields, [2]string{key, val})
	}
	switch rapid.IntRange(0, 14).Draw(t, "kind") {
	case 0:
		set(rapid.SampledFrom([]string{"polcy", "Policy", "CALL", "", "talk"}).Draw(t, "field"), quote("see"))
	case 1:
		e := some()
		e.fields = [][2]string{{"policy", rapid.SampledFrom([]string{`"Talk"`, `"none"`, `""`, `null`, `1`,
			`["see"]`, `"see "`}).Draw(t, "policy")}}
	case 2:
		some().name = rapid.SampledFrom([]string{":1.2", "org.freedesktop.DBus", "org.test.*", "org.test.X.*", "org",
			"org..test", "", "1org.test"}).Draw(t, "name")
	case 3:
		entries = append(entries, *some())
	case 4:
		e := some()
		e.fields = append(e.fields, e.fields[0])
	case 5:
		some().fields = rapid.SampledFrom([][][2]string{nil, {{"call", "[]"}}, {{"call", "[]"}, {"broadcast", "[]"}}}).
			Draw(t, "empty")
	case 6:
		bad := rapid.SampledFrom([]string{"", "@//*", "*.Get", "Iface", "Iface.*", "org.test.I.M@", "@", "@bad",
			"@/a/", "@/a/*/b", "org.test.I.M@/a@/b", "org.test..M", "org.test.I.9M", "org.test.I.M-x", "*@",
			".M", "org.test.I.", "org-x.test.I.M", " *"}).Draw(t, "rule")
		set(rapid.SampledFrom([]string{"call", "broadcast"}).Draw(t, "kind"), quoteList([]string{cfgRule(t, n), bad}))
	case 7:
		e := some()
		e.fields = [][2]string{{rapid.SampledFrom([]string{"call", "broadcast", "policy"}).Draw(t, "field"),
			rapid.SampledFrom([]string{"null", "[null]", "[1]", `"*"`, `{}`, `[["*"]]`}).Draw(t, "value")}}
	case 8:
		return rapid.SampledFrom([]string{"", "[]", "null", `"x"`, "1", "{", `{"org.test.A":null}`,
			`{"org.test.A":[]}`, `{"org.test.A":"talk"}`}).Draw(t, "top")
	case 9:
		return render(t, entries) + rapid.SampledFrom([]string{"{}", "x", ",", "null", "}"}).Draw(t, "after")
	case 10:
		// 64 names may be, 65 may not
		entries = nil
		for i := range rapid.SampledFrom([]int{64, 65}).Draw(t, "count") {
			entries = append(entries, cfgEntry{name: fmt.Sprintf("org.test.N%d", i), fields: [][2]string{{"policy", `"see"`}}})
		}
	case 11:
		rules := make([]string, rapid.SampledFrom([]int{64, 65}).Draw(t, "count"))
		for i := range rules {
			rules[i] = "*"
		}
		set(rapid.SampledFrom([]string{"call", "broadcast"}).Draw(t, "kind"), quoteList(rules))
	case 12:
		// About the 64 KiB cap
		s := render(t, entries)
		return s + strings.Repeat(" ", max(0, rapid.SampledFrom([]int{64<<10 - 1, 64 << 10, 64<<10 + 1}).Draw(t, "size")-len(s)))
	case 13:
		s := render(t, entries)
		return s[:rapid.IntRange(0, len(s)-1).Draw(t, "cut")]
	case 14:
		// A field null beside one that gives the entry something, so the null alone is what's wrong
		e := some()
		field := rapid.SampledFrom([]string{"policy", "call", "broadcast"}).Draw(t, "null field")
		other := [2]string{"policy", quote("see")}
		if field == "policy" {
			other = [2]string{"call", quoteList([]string{cfgRule(t, n)})}
		}
		e.fields = rapid.Permutation([][2]string{other, {field, "null"}}).Draw(t, "null order")
	}
	return render(t, entries)
}
