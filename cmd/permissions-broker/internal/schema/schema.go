// Package schema is the subset of JSON Schema the broker checks arguments and parameters against itself: string
// (maxLength, pattern, enum), integer and number (minimum, maximum, enum), boolean, and arrays of those (items,
// maxItems). opaque marks a string the user has nothing to read in (a CSR); multiline lets a string hold newlines and
// tabs. A pattern matches the whole value. instances, on a host command capability's bounding argument, is the glob
// its values come from
package schema

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Schema struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Opaque      bool        `json:"opaque"`
	Multiline   bool        `json:"multiline"`
	MaxLength   *int        `json:"maxLength"`
	Pattern     string      `json:"pattern"`
	Enum        []any       `json:"enum"`
	Minimum     json.Number `json:"minimum"`
	Maximum     json.Number `json:"maximum"`
	Items       *Schema     `json:"items"`
	MaxItems    *int        `json:"maxItems"`
	Instances   string      `json:"instances"`

	re *regexp.Regexp
	// The bounds' exact values, nil for none
	min, max *big.Rat
}

// An opaque string, data that the user has nothing to read in (a CSR), may be this long: it's shown as a digest
const MaxOpaque = 8192

var argTypes = map[string]bool{"string": true, "boolean": true, "integer": true, "number": true, "array": true}

// Parse reads and checks one argument's schema. Numbers stay as written: bounds and enum values compare exactly
func Parse(raw json.RawMessage) (*Schema, error) {
	var s Schema
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&s); err != nil {
		return nil, err
	}
	return &s, s.check(true)
}

// ratOf is a number's exact value
func ratOf(n json.Number) (*big.Rat, bool) {
	return new(big.Rat).SetString(string(n))
}

func (s *Schema) check(top bool) error {
	if !argTypes[s.Type] || s.Type == "array" && !top {
		return fmt.Errorf("type %q: string, boolean, integer, number, or an array of those", s.Type)
	}
	if (s.Opaque || s.Multiline || s.MaxLength != nil || s.Pattern != "") && s.Type != "string" {
		return fmt.Errorf("opaque, multiline, maxLength and pattern are for strings only")
	}
	if (s.Minimum != "" || s.Maximum != "") && s.Type != "integer" && s.Type != "number" {
		return fmt.Errorf("minimum and maximum are for numbers only")
	}
	for _, b := range []struct {
		n json.Number
		r **big.Rat
	}{{s.Minimum, &s.min}, {s.Maximum, &s.max}} {
		if b.n == "" {
			continue
		}
		r, ok := ratOf(b.n)
		if !ok {
			return fmt.Errorf("minimum and maximum must be numbers")
		}
		*b.r = r
	}
	if (s.Items != nil || s.MaxItems != nil) != (s.Type == "array") || s.Type == "array" && s.Items == nil {
		return fmt.Errorf("an array needs items, and only an array takes items and maxItems")
	}
	if s.Pattern != "" {
		re, err := regexp.Compile(`^(?:` + s.Pattern + `)$`)
		if err != nil {
			return fmt.Errorf("pattern: %w", err)
		}
		s.re = re
	}
	if s.Items != nil {
		if err := s.Items.check(false); err != nil {
			return fmt.Errorf("items: %w", err)
		}
	}
	for _, e := range s.Enum {
		if err := s.checkScalar(normalize(e), math.MaxInt32); err != nil {
			return fmt.Errorf("enum value %v: %w", e, err)
		}
	}
	return nil
}

// normalize turns numbers into json.Number, as values decoded with UseNumber are
func normalize(v any) any {
	if f, ok := v.(float64); ok {
		return json.Number(strconv.FormatFloat(f, 'f', -1, 64))
	}
	return v
}

// CheckValue checks v, decoded with UseNumber, against s. A string without maxLength may be maxDefault characters
// long, an opaque one maxOpaque
func (s *Schema) CheckValue(v any, maxDefault int) error {
	if s.Type != "array" {
		return s.checkScalar(v, maxDefault)
	}
	items, ok := v.([]any)
	if !ok {
		return fmt.Errorf("must be an array")
	}
	if s.MaxItems != nil && len(items) > *s.MaxItems {
		return fmt.Errorf("at most %d items", *s.MaxItems)
	}
	for i, item := range items {
		if err := s.Items.checkScalar(item, maxDefault); err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
	}
	return nil
}

func (s *Schema) checkScalar(v any, maxDefault int) error {
	switch v := v.(type) {
	case string:
		if s.Type != "string" {
			break
		}
		limit := maxDefault
		switch {
		case s.MaxLength != nil:
			limit = *s.MaxLength
		case s.Opaque:
			limit = MaxOpaque
		}
		if utf8.RuneCountInString(v) > limit || !utf8.ValidString(v) {
			return fmt.Errorf("at most %d characters", limit)
		}
		if strings.IndexFunc(v, func(r rune) bool { return unicode.IsControl(r) && !(s.Multiline && (r == '\n' || r == '\t')) }) >= 0 {
			return fmt.Errorf("no control characters%s", map[bool]string{true: " but newlines and tabs"}[s.Multiline])
		}
		if s.re != nil && !s.re.MatchString(v) {
			return fmt.Errorf("must match %s", s.Pattern)
		}
		return s.inEnum(v)
	case bool:
		if s.Type == "boolean" {
			return s.inEnum(v)
		}
	case json.Number:
		// A number a float64 holds, an integer as one of 64 bits
		f, err := v.Float64()
		if err != nil || math.IsInf(f, 0) {
			break
		}
		_, intErr := v.Int64()
		if s.Type == "integer" && intErr != nil || s.Type != "integer" && s.Type != "number" {
			break
		}
		// Bounds exactly, not as float64s: 2.50000000000000001 is past 2.5, whatever a float64 rounds it to
		r, ok := ratOf(v)
		if !ok {
			break
		}
		if s.min != nil && r.Cmp(s.min) < 0 || s.max != nil && r.Cmp(s.max) > 0 {
			return fmt.Errorf("must lie within %s", s.bounds())
		}
		return s.inEnum(v)
	}
	return fmt.Errorf("must be a %s", s.Type)
}

func (s *Schema) inEnum(v any) error {
	if len(s.Enum) == 0 {
		return nil
	}
	for _, e := range s.Enum {
		if n, ok := v.(json.Number); ok {
			// Exactly, as the bounds
			en, isNumber := normalize(e).(json.Number)
			if r, ok := ratOf(n); ok && isNumber {
				if er, ok := ratOf(en); ok && r.Cmp(er) == 0 {
					return nil
				}
			}
			continue
		}
		if reflect.DeepEqual(e, v) {
			return nil
		}
	}
	return fmt.Errorf("must be one of %v", s.Enum)
}

func (s *Schema) bounds() string {
	lo, hi := "any", "any"
	if s.Minimum != "" {
		lo = s.Minimum.String()
	}
	if s.Maximum != "" {
		hi = s.Maximum.String()
	}
	return lo + "–" + hi
}

// Unrestricted reports whether any string the request size allows passes s: what the consent must say plainly
func (s *Schema) Unrestricted() bool {
	if s.Type == "array" {
		return s.Items.Unrestricted()
	}
	return s.Type == "string" && len(s.Enum) == 0 && s.Pattern == ""
}

// An enum longer than this reads as a count in the consent (161 key names would bury the rest); the window lists the
// values when the user expands a grant
const maxListedEnum = 8

// Allows says what s lets through, for the consent
func (s *Schema) Allows() string {
	switch {
	case s.Type == "array":
		return "a list of " + s.Items.Allows()
	case len(s.Enum) > maxListedEnum:
		return fmt.Sprintf("one of %d values", len(s.Enum))
	case len(s.Enum) > 0:
		return fmt.Sprintf("one of %v", s.Enum)
	case s.Pattern != "":
		return "matching " + s.Pattern
	case s.Type == "string" && s.Opaque:
		return "opaque data"
	case s.Type == "string":
		return "any text"
	case s.Type == "boolean":
		return "yes or no"
	default:
		return "a number within " + s.bounds()
	}
}

// DecodeObject decodes a JSON object with numbers as json.Number; nothing or null is an empty one
func DecodeObject(raw json.RawMessage) (map[string]any, error) {
	m := map[string]any{}
	if len(raw) == 0 || string(raw) == "null" {
		return m, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return map[string]any{}, nil
	}
	return m, nil
}

// OpaqueDigest is how an opaque parameter is shown: enough to tell two apart, nothing to read
func OpaqueDigest(v string) string {
	sum := sha256.Sum256([]byte(v))
	return fmt.Sprintf("sha256:%s (%d characters)", hex.EncodeToString(sum[:])[:16], utf8.RuneCountInString(v))
}

// Canonical writes v's numbers one way, items of an array too: an integer without sign of zero, fraction or exponent,
// any other number as its exact decimal. Equal values then encode equally: a grant of slot 0 covers slot -0
func Canonical(v any) any {
	switch v := v.(type) {
	case json.Number:
		r, ok := ratOf(v)
		if !ok {
			return v
		}
		if r.IsInt() {
			return json.Number(r.Num().String())
		}
		// A decimal's denominator is 2^a 5^b: max(a, b) digits write it exactly
		digits, d := 0, new(big.Int).Set(r.Denom())
		for _, p := range []int64{2, 5} {
			n, q, m := 0, new(big.Int), new(big.Int)
			for q.DivMod(d, big.NewInt(p), m); m.Sign() == 0; q.DivMod(d, big.NewInt(p), m) {
				d.Set(q)
				n++
			}
			digits = max(digits, n)
		}
		return json.Number(strings.TrimRight(r.FloatString(digits), "0"))
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = Canonical(x)
		}
		return out
	}
	return v
}
