package main

import (
	"bytes"
	"encoding/json"
	"maps"
	"math"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The oracle the state machines judge requests by: the rules of docs/permissions.md (Declared host commands,
// Requests, Leases and triggers) and the schema subset's documented semantics, written here from the docs and read
// from the declarations' JSON, never by calling the broker's own checks. Where the docs leave a corner open, the rule
// chosen says so

// decl is an argument's declaration as the oracle reads it
type decl struct {
	Type      string            `json:"type"`
	Opaque    bool              `json:"opaque"`
	Multiline bool              `json:"multiline"`
	MaxLength *int              `json:"maxLength"`
	Pattern   string            `json:"pattern"`
	Enum      []json.RawMessage `json:"enum"`
	Minimum   json.Number       `json:"minimum"`
	Maximum   json.Number       `json:"maximum"`
	Items     *decl             `json:"items"`
	MaxItems  *int              `json:"maxItems"`
	Instances string            `json:"instances"`

	re       *regexp.Regexp
	min, max *big.Rat
	enum     []any
}

// readDecl reads a declaration the test config holds, which is valid
func readDecl(raw json.RawMessage) *decl {
	var d decl
	if err := json.Unmarshal(raw, &d); err != nil {
		panic(err)
	}
	d.prepare()
	return &d
}

func (d *decl) prepare() {
	if d.Pattern != "" {
		// A pattern matches the whole value
		d.re = regexp.MustCompile(`^(?:` + d.Pattern + `)$`)
	}
	d.min, d.max = ratOf(d.Minimum), ratOf(d.Maximum)
	for _, e := range d.Enum {
		d.enum = append(d.enum, decodeJSON(e))
	}
	if d.Items != nil {
		d.Items.prepare()
	}
}

func ratOf(n json.Number) *big.Rat {
	if n == "" {
		return nil
	}
	r, ok := new(big.Rat).SetString(string(n))
	if !ok {
		panic("not a number: " + n)
	}
	return r
}

// decodeJSON decodes a JSON value with its numbers as written. Strings decode as JSON decoding gives them: bytes that
// aren't UTF-8 and lone surrogates read as U+FFFD
func decodeJSON(raw []byte) any {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		panic(err)
	}
	return v
}

// Limits the docs give: a parameter's string 200 characters, an opaque one 8192, a free argument's 64 Ki
const (
	oracleMaxParam  = 200
	oracleMaxOpaque = 8192
	oracleMaxFree   = 64 << 10
)

// accepts reports whether v is a value d allows, a string without maxLength being at most limit characters
func (d *decl) accepts(v any, limit int) bool {
	if d.Type == "array" {
		items, ok := v.([]any)
		if !ok || d.MaxItems != nil && len(items) > *d.MaxItems {
			return false
		}
		for _, item := range items {
			if !d.Items.accepts(item, limit) {
				return false
			}
		}
		return true
	}
	switch v := v.(type) {
	case string:
		return d.Type == "string" && d.stringOK(v, limit) && d.inEnum(v)
	case bool:
		return d.Type == "boolean" && d.inEnum(v)
	case json.Number:
		r, ok := numberValue(d.Type, v)
		return ok && (d.min == nil || r.Cmp(d.min) >= 0) && (d.max == nil || r.Cmp(d.max) <= 0) && d.inEnum(v)
	}
	return false
}

func (d *decl) stringOK(s string, limit int) bool {
	switch {
	case d.MaxLength != nil:
		limit = *d.MaxLength
	case d.Opaque:
		limit = oracleMaxOpaque
	}
	if utf8.RuneCountInString(s) > limit {
		return false
	}
	// No control characters (Unicode's Cc), but newlines and tabs in a multiline one
	for _, r := range s {
		if unicode.Is(unicode.Cc, r) && !(d.Multiline && (r == '\n' || r == '\t')) {
			return false
		}
	}
	return d.re == nil || d.re.MatchString(s)
}

// Integers as JSON writes them: an optional minus and digits, no fraction or exponent. The docs leave open whether
// 1.0 or 1e2 is an integer; the oracle says no, so a script declared to take an integer gets one written as such. It
// must fit 64 bits
var integerText = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// A number as JSON writes it: the digits ahead of the exponent, and the exponent
var numberText = regexp.MustCompile(`^-?([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$`)

// numberValue is n's exact value, if it is a value of type typ: an integer as above, or a number a float64 holds
// without overflowing or rounding to 0 (the docs leave the range open). Either written in at most 800 digits ahead of
// an exponent within ±400, as the docs say
func numberValue(typ string, n json.Number) (*big.Rat, bool) {
	m := numberText.FindStringSubmatch(string(n))
	if m == nil || len(m[1])+len(m[2]) > 800 {
		return nil, false
	}
	if m[3] != "" {
		if e, err := strconv.Atoi(m[3]); err != nil || e < -400 || e > 400 {
			return nil, false
		}
	}
	r, ok := new(big.Rat).SetString(string(n))
	if !ok {
		return nil, false
	}
	switch typ {
	case "integer":
		lo, hi := big.NewRat(math.MinInt64, 1), new(big.Rat).SetInt(new(big.Int).SetUint64(math.MaxInt64))
		return r, integerText.MatchString(string(n)) && r.Cmp(lo) >= 0 && r.Cmp(hi) <= 0
	case "number":
		limit := new(big.Rat).SetFloat64(math.MaxFloat64)
		// Half the smallest float64, 2^-1075, rounds to 0 (to even), and so does anything smaller
		half := new(big.Rat).SetFrac(big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), 1075))
		abs := new(big.Rat).Abs(r)
		return r, abs.Cmp(limit) <= 0 && (abs.Sign() == 0 || abs.Cmp(half) > 0)
	}
	return nil, false
}

// inEnum: no enum, or v equals one of its values (numbers by value)
func (d *decl) inEnum(v any) bool {
	if len(d.enum) == 0 {
		return true
	}
	return slices.ContainsFunc(d.enum, func(e any) bool { return sameJSON(e, v) })
}

// sameJSON compares JSON values, numbers by their exact value
func sameJSON(a, b any) bool {
	return canonical(a) == canonical(b)
}

// canonical writes a decoded JSON value one way: keys sorted, numbers by their exact value. The model keys grants by
// it
func canonical(v any) string {
	var b strings.Builder
	var write func(v any)
	write = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			b.WriteByte('{')
			for i, k := range slices.Sorted(maps.Keys(v)) {
				if i > 0 {
					b.WriteByte(',')
				}
				data, _ := json.Marshal(k)
				b.Write(data)
				b.WriteByte(':')
				write(v[k])
			}
			b.WriteByte('}')
		case []any:
			b.WriteByte('[')
			for i, x := range v {
				if i > 0 {
					b.WriteByte(',')
				}
				write(x)
			}
			b.WriteByte(']')
		case json.Number:
			// Integers plainly, so decoding the key reads them; other values as their exact fraction in a string,
			// which no valid value of a number's declaration is
			r, _ := new(big.Rat).SetString(string(v))
			if r.IsInt() {
				b.WriteString(r.Num().String())
			} else {
				data, _ := json.Marshal("#num:" + r.RatString())
				b.Write(data)
			}
		default:
			data, _ := json.Marshal(v)
			b.Write(data)
		}
	}
	write(v)
	return b.String()
}

// objectOf reads parameters or arguments as the docs' requests carry them: a JSON object, nothing or null an empty
// one. Not an object: nil
func objectOf(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	switch v := decodeJSON(raw).(type) {
	case nil:
		return map[string]any{}
	case map[string]any:
		return v
	}
	return nil
}

// paramsOK: parameters are an object of declared keys, each value as its declaration allows; any may be left out
func paramsOK(decls map[string]*decl, raw json.RawMessage) bool {
	m := objectOf(raw)
	if m == nil {
		return false
	}
	for k, v := range m {
		if decls[k] == nil || !decls[k].accepts(v, oracleMaxParam) {
			return false
		}
	}
	return true
}

// argumentsOK: a call's free arguments are an object with every declared one and no other, each as declared allows
func argumentsOK(decls map[string]*decl, raw json.RawMessage) bool {
	m := objectOf(raw)
	if m == nil || len(m) != len(decls) {
		return false
	}
	for k, d := range decls {
		v, ok := m[k]
		if !ok || !d.accepts(v, oracleMaxFree) {
			return false
		}
	}
	return true
}

// foldReason is the reason as the docs show it: whitespace (Unicode's White_Space) and control characters (Cc)
// folded to single spaces, none at the ends, cut to 300 characters with an ellipsis. Empty: no reason
func oracleReason(r string) string {
	var out []rune
	space := false
	for _, c := range r {
		if unicode.Is(unicode.White_Space, c) || unicode.Is(unicode.Cc, c) {
			space = len(out) > 0
			continue
		}
		if space {
			out = append(out, ' ')
			space = false
		}
		out = append(out, c)
	}
	if len(out) > maxReason {
		return string(out[:maxReason]) + "…"
	}
	return string(out)
}

// oracleDuration reads a lease's duration: PT, then hours, minutes and seconds, each at most once and in that order,
// in ASCII digits; a positive total. The docs name PT<n>H and PT<n>M; seconds and combinations read the same way. A
// total past what a duration holds (292 years) is refused: the docs set no bound, and a lease can't outlast that
func oracleDuration(lease string) (time.Duration, bool) {
	rest, ok := strings.CutPrefix(lease, "PT")
	if !ok || rest == "" {
		return 0, false
	}
	total := new(big.Int)
	for _, u := range []struct {
		suffix byte
		unit   time.Duration
	}{{'H', time.Hour}, {'M', time.Minute}, {'S', time.Second}} {
		i := 0
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		if i == 0 || i >= len(rest) || rest[i] != u.suffix {
			continue
		}
		n, _ := new(big.Int).SetString(rest[:i], 10)
		total.Add(total, n.Mul(n, big.NewInt(int64(u.unit))))
		rest = rest[i+1:]
	}
	if rest != "" || total.Sign() <= 0 || !total.IsInt64() {
		return 0, false
	}
	return time.Duration(total.Int64()), true
}

// leaseKind reads a proposed lease: none proposes PT1H; lock, once, a duration. Anything else ("standing" included,
// which only the config gives) is no lease
func leaseKind(lease string) (string, bool) {
	switch lease {
	case "":
		return "PT1H", true
	case "lock", "once":
		return lease, true
	}
	_, ok := oracleDuration(lease)
	return lease, ok
}
