package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"pgregory.net/rapid"
)

// Generators of the state machines' parameters and arguments, from the declarations' grammar (machine_oracle_test.go
// reads the same declarations): values of the declared type, unusual but allowed ones (boundary lengths, unicode,
// number forms) and ones past each rule, as JSON text so odd forms (escapes, exponents, bytes that aren't UTF-8) reach
// the broker as written. What a draw means is the oracle's call; the generator only aims, about 60% valid
// (TestGeneratorShares)

// often reports true about share in ten draws
func often(t *rapid.T, share int, label string) bool {
	return rapid.IntRange(0, 9).Draw(t, label) < share
}

// Runes a string may hold: letters, marks, digits, punctuation, symbols, spaces, line and paragraph separators
// (U+2028, U+2029) and format characters such as U+200B and U+202E, which aren't control characters (Cc) but mustn't
// reach the consent raw
var textRune = rapid.RuneFrom([]rune("aé中😀 -_./<>&\"\\\u2028\u2029\u202e\u2066\u200b"), unicode.L, unicode.M,
	unicode.N, unicode.P, unicode.S, unicode.Zs, unicode.Zl, unicode.Zp, unicode.Cf)

// Control characters (Cc): C0, DEL and C1, newline and tab among them
var controlRune = rapid.SampledFrom([]rune{0, '\a', '\b', '\n', '\t', '\r', 0x1b, 0x7f, 0x85, 0x9b})

// limitOf is how long a string d declares may be: maxLength, an opaque one's, or limit
func limitOf(d *decl, limit int) int {
	switch {
	case d.MaxLength != nil:
		return *d.MaxLength
	case d.Opaque:
		return oracleMaxOpaque
	}
	return limit
}

// drawText draws a string for d: an enum member, a match of its pattern, or text of any length up to its limit,
// exactly at it included
func drawText(t *rapid.T, d *decl, limit int) string {
	if len(d.enum) > 0 {
		s, _ := rapid.SampledFrom(d.enum).Draw(t, "member").(string)
		return s
	}
	if d.re != nil {
		return rapid.StringMatching(d.Pattern).Draw(t, "matching")
	}
	n := limitOf(d, limit)
	switch rapid.IntRange(0, 4).Draw(t, "text") {
	case 0:
		return filled(t, n)
	case 1:
		return filled(t, n-1)
	case 2:
		if d.Multiline {
			return rapid.StringOfN(rapid.SampledFrom([]rune("ab \n\t")), 0, min(n, 20), -1).Draw(t, "lines")
		}
	}
	return rapid.StringOfN(textRune, 0, min(n, 16), -1).Draw(t, "short")
}

// filled is a string of n characters: one rune repeated, multibyte ones too
func filled(t *rapid.T, n int) string {
	return strings.Repeat(string(rapid.SampledFrom([]rune("aé中😀")).Draw(t, "fill")), max(n, 0))
}

// drawBadText draws a string past one of d's rules: a character too many, a control character where none may be,
// a near-member of the enum, a pattern's match spoiled
func drawBadText(t *rapid.T, d *decl, limit int) string {
	s := drawText(t, d, limit)
	switch rapid.IntRange(0, 3).Draw(t, "spoil") {
	case 0:
		return filled(t, limitOf(d, limit)+1)
	case 1:
		r := []rune(s)
		i := rapid.IntRange(0, len(r)).Draw(t, "at")
		return string(r[:i]) + string(controlRune.Draw(t, "control")) + string(r[i:])
	case 2:
		return strings.ToUpper(s) + " "
	}
	return s + "!"
}

// drawNumber draws a number for d as JSON writes it: integers within its bounds and at them, -0, and for numbers
// fractions and exponents of values within
func drawNumber(t *rapid.T, d *decl) string {
	if len(d.enum) > 0 {
		r := ratOf(json.Number(fmt.Sprint(rapid.SampledFrom(d.enum).Draw(t, "member"))))
		return numberForm(t, r, d.Type == "integer")
	}
	lo, hi := int64(-1000000), int64(1000000)
	if d.min != nil {
		lo = ceilRat(d.min)
	}
	if d.max != nil {
		hi = floorRat(d.max)
	}
	if d.Type == "number" && rapid.IntRange(0, 9).Draw(t, "edge") == 0 {
		// At the edges of what a float64 holds and of a number's written digits and exponent, when within the bounds
		n := rapid.SampledFrom([]string{"5e-324", "-4.9406564584124654E-324", "0e-400", "-0E+400",
			"1." + strings.Repeat("0", 799)}).Draw(t, "edge form")
		if r := ratOf(json.Number(n)); (d.min == nil || r.Cmp(d.min) >= 0) && (d.max == nil || r.Cmp(d.max) <= 0) {
			return n
		}
	}
	if d.Type == "number" && rapid.Bool().Draw(t, "fraction") {
		// Hundredths within the bounds
		n := rapid.Int64Range(lo*100, hi*100).Draw(t, "hundredths")
		return numberForm(t, big.NewRat(n, 100), false)
	}
	switch rapid.IntRange(0, 3).Draw(t, "integer") {
	case 0:
		return strconv.FormatInt(lo, 10)
	case 1:
		return strconv.FormatInt(hi, 10)
	case 2:
		if lo <= 0 && hi >= 0 {
			return "-0"
		}
	}
	return strconv.FormatInt(rapid.Int64Range(lo, hi).Draw(t, "n"), 10)
}

// numberForm writes r one of the ways JSON may: plainly, and for a number with a fraction or an exponent
func numberForm(t *rapid.T, r *big.Rat, integer bool) string {
	plain := r.FloatString(2)
	if r.IsInt() {
		plain = r.Num().String()
	}
	if integer {
		return plain
	}
	scaled := new(big.Rat).Mul(r, big.NewRat(100, 1))
	return rapid.SampledFrom([]string{plain, plain, r.FloatString(4), scaled.FloatString(0) + "e-2",
		scaled.FloatString(0) + "E-2"}).Draw(t, "form")
}

func ceilRat(r *big.Rat) int64 {
	q := new(big.Int).Div(r.Num(), r.Denom()) // floor, Denom > 0
	if !r.IsInt() {
		q.Add(q, big.NewInt(1))
	}
	return q.Int64()
}

func floorRat(r *big.Rat) int64 { return new(big.Int).Div(r.Num(), r.Denom()).Int64() }

// drawBadNumber draws a number past d: a step beyond a bound, a hair beyond one, an integer written with a fraction or
// an exponent, past 64 bits or a float64, a hair from an enum member
func drawBadNumber(t *rapid.T, d *decl) string {
	hair := big.NewRat(1, 100000000000000000) // 1e-17: within a float64's rounding of most values
	switch rapid.IntRange(0, 6).Draw(t, "past") {
	case 0:
		if d.max != nil {
			return new(big.Rat).Add(d.max, big.NewRat(1, 1)).FloatString(0)
		}
	case 1:
		if d.max != nil {
			return new(big.Rat).Add(d.max, hair).FloatString(17)
		}
		if d.min != nil {
			return new(big.Rat).Sub(d.min, hair).FloatString(17)
		}
	case 2:
		return drawNumber(t, d) + rapid.SampledFrom([]string{".0", "e0", "E+0"}).Draw(t, "dressed")
	case 3:
		return rapid.SampledFrom([]string{"9223372036854775808", "-9223372036854775809", "123456789012345678901234567890",
			"1e309", "-1e400"}).Draw(t, "huge")
	case 5:
		// Past what a float64 holds the other way, or written past 800 digits or an exponent of ±400: 1e-9999999 rounds
		// to 0, and costs the exact arithmetic hours
		return rapid.SampledFrom([]string{"1e-400", "-2e-324", "1e-9999999", "0e-401", "0e9999999",
			"0." + strings.Repeat("0", 800), "1." + strings.Repeat("0", 800)}).Draw(t, "tiny")
	case 4:
		if len(d.enum) > 0 {
			r := ratOf(json.Number(fmt.Sprint(rapid.SampledFrom(d.enum).Draw(t, "member"))))
			return new(big.Rat).Add(r, hair).FloatString(17)
		}
	}
	return "0.5"
}

// drawValue draws a value d allows, as JSON text: mostly; a value of d's type that breaks one of its rules, or one
// of another type, when valid is false
func drawValue(t *rapid.T, d *decl, limit int, valid bool) string {
	if !valid && often(t, 4, "wrong type") {
		return rapid.SampledFrom([]string{`"5"`, `5`, `true`, `null`, `[]`, `{}`, `{"a":1}`, `"x"`, `1.5`}).Draw(t, "other")
	}
	switch d.Type {
	case "string":
		if valid {
			return encodeString(t, drawText(t, d, limit))
		}
		return encodeString(t, drawBadText(t, d, limit))
	case "integer", "number":
		if valid {
			return drawNumber(t, d)
		}
		return drawBadNumber(t, d)
	case "boolean":
		if valid {
			return strconv.FormatBool(rapid.Bool().Draw(t, "bool"))
		}
		return rapid.SampledFrom([]string{`"true"`, `1`, `0`, `"no"`}).Draw(t, "not bool")
	case "array":
		n := 3
		if d.MaxItems != nil {
			n = *d.MaxItems
		}
		count := rapid.IntRange(0, n).Draw(t, "items")
		bad := -1
		if !valid {
			if rapid.Bool().Draw(t, "too many") {
				count = n + 1
			} else {
				count = max(count, 1)
				bad = rapid.IntRange(0, count-1).Draw(t, "bad item")
			}
		}
		items := make([]string, count)
		for i := range items {
			items[i] = drawValue(t, d.Items, limit, i != bad)
		}
		return "[" + strings.Join(items, ",") + "]"
	}
	return "null"
}

// encodeString writes s as a JSON string: as encoding/json does, with every non-ASCII character escaped (surrogate
// pairs past the BMP), or with a byte that isn't UTF-8 or a lone surrogate in place of a character, which decode as
// U+FFFD
func encodeString(t *rapid.T, s string) string {
	switch rapid.IntRange(0, 7).Draw(t, "encoding") {
	case 0:
		var b strings.Builder
		b.WriteByte('"')
		for _, r := range s {
			if r < 0x80 && r >= 0x20 && r != '"' && r != '\\' {
				b.WriteRune(r)
				continue
			}
			for _, u := range utf16Of(r) {
				fmt.Fprintf(&b, `\u%04x`, u)
			}
		}
		b.WriteByte('"')
		return b.String()
	case 1:
		if s != "" {
			_, size := utf8.DecodeRuneInString(s)
			rest, _ := json.Marshal(s[size:])
			return `"` + rapid.SampledFrom([]string{"\xff", `\ud800`, "\xc3"}).Draw(t, "broken") + string(rest[1:])
		}
	}
	data, _ := json.Marshal(s)
	return string(data)
}

func utf16Of(r rune) []uint16 {
	if r < 0x10000 {
		return []uint16{uint16(r)}
	}
	r -= 0x10000
	return []uint16{uint16(0xd800 + r>>10), uint16(0xdc00 + r&0x3ff)}
}

// A hint draws a value of its own for an argument, as JSON text, where the world knows better values than the
// declaration (instances, folders): false to leave it to the declaration
type hint func(t *rapid.T, arg string) (string, bool)

// drawObject draws parameters or a call's arguments for decls as a JSON object: with required, every one of them,
// otherwise any, those hint draws mostly. When valid is false, one thing about it is wrong: a value, a key too many (a
// near-miss of a declared one, the broker's own reason or lease), one missing, or no object at all
func drawObject(t *rapid.T, decls map[string]*decl, limit int, required, valid bool, h hint) json.RawMessage {
	keys := slices.Sorted(maps.Keys(decls))
	var present []string
	hinted := map[string]string{}
	for _, k := range keys {
		if h != nil {
			if v, ok := h(t, k); ok {
				hinted[k] = v
			}
		}
		if _, ok := hinted[k]; required || ok && often(t, 9, "has "+k) || !ok && rapid.Bool().Draw(t, "has "+k) {
			present = append(present, k)
		}
	}
	mutation := -1
	if !valid {
		mutation = rapid.IntRange(0, 3).Draw(t, "mutation")
	}
	if mutation == 0 && len(present) == 0 || mutation == 2 && (!required || len(present) == 0) {
		mutation = 1
	}
	switch mutation {
	case 2:
		present = slices.Delete(present, 0, 1)
	case 3:
		return json.RawMessage(rapid.SampledFrom([]string{`[]`, `"x"`, `1`, `true`, `[{"name":"a"}]`, `""`}).Draw(t,
			"not an object"))
	}
	bad := ""
	if mutation == 0 {
		bad = rapid.SampledFrom(present).Draw(t, "bad")
	}
	fields := map[string]string{}
	for _, k := range present {
		if v, ok := hinted[k]; ok && k != bad {
			fields[k] = v
		} else {
			fields[k] = drawValue(t, decls[k], limit, k != bad)
		}
	}
	if mutation == 1 {
		extra := rapid.SampledFrom(append(slices.Clone(keys), "reason", "lease", "")).Draw(t, "near")
		extra = rapid.SampledFrom([]string{extra + "s", strings.ToUpper(extra), extra + " ", "x" + extra}).Draw(t, "extra")
		fields[extra] = rapid.SampledFrom([]string{`"a"`, `1`, `true`}).Draw(t, "extra value")
	}
	if len(fields) == 0 && valid && often(t, 3, "absent") {
		return json.RawMessage(rapid.SampledFrom([]string{"", "null", "{}"}).Draw(t, "empty"))
	}
	order := rapid.Permutation(slices.Sorted(maps.Keys(fields))).Draw(t, "order")
	parts := make([]string, len(order))
	for i, k := range order {
		name, _ := json.Marshal(k)
		parts[i] = string(name) + ":" + fields[k]
	}
	return json.RawMessage("{" + strings.Join(parts, ",") + "}")
}
