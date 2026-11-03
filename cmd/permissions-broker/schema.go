package main

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The subset of JSON Schema the broker checks arguments and parameters against itself: string (maxLength, pattern,
// enum), integer and number (minimum, maximum, enum), boolean, and arrays of those (items, maxItems). opaque marks a
// string the user has nothing to read in (a CSR); multiline lets a string hold newlines and tabs. A pattern matches the
// whole value. instances, on a host command capability's bounding argument, is the glob its values come from

type argSchema struct {
	Type        string     `json:"type"`
	Description string     `json:"description"`
	Opaque      bool       `json:"opaque"`
	Multiline   bool       `json:"multiline"`
	MaxLength   *int       `json:"maxLength"`
	Pattern     string     `json:"pattern"`
	Enum        []any      `json:"enum"`
	Minimum     *float64   `json:"minimum"`
	Maximum     *float64   `json:"maximum"`
	Items       *argSchema `json:"items"`
	MaxItems    *int       `json:"maxItems"`
	Instances   string     `json:"instances"`

	re *regexp.Regexp
}

var argTypes = map[string]bool{"string": true, "boolean": true, "integer": true, "number": true, "array": true}

// parseSchema reads and checks one argument's schema
func parseSchema(raw json.RawMessage) (*argSchema, error) {
	var s argSchema
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, s.check(true)
}

func (s *argSchema) check(top bool) error {
	if !argTypes[s.Type] || s.Type == "array" && !top {
		return fmt.Errorf("type %q: string, boolean, integer, number, or an array of those", s.Type)
	}
	if (s.Opaque || s.Multiline || s.MaxLength != nil || s.Pattern != "") && s.Type != "string" {
		return fmt.Errorf("opaque, multiline, maxLength and pattern are for strings only")
	}
	if (s.Minimum != nil || s.Maximum != nil) && s.Type != "integer" && s.Type != "number" {
		return fmt.Errorf("minimum and maximum are for numbers only")
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

// checkValue checks v, decoded with UseNumber, against s. A string without maxLength may be maxDefault characters
// long, an opaque one maxOpaque
func (s *argSchema) checkValue(v any, maxDefault int) error {
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

func (s *argSchema) checkScalar(v any, maxDefault int) error {
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
			limit = maxOpaque
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
		f, err := v.Float64()
		if err != nil || math.IsInf(f, 0) {
			break
		}
		n, intErr := v.Int64()
		if s.Type == "integer" && intErr != nil || s.Type != "integer" && s.Type != "number" {
			break
		}
		// Integers exactly: past 2^53 a float64 can't tell neighbours apart
		below := func(b float64) bool { return f < b }
		above := func(b float64) bool { return f > b }
		if s.Type == "integer" {
			below = func(b float64) bool { return b > math.MinInt64 && n < int64(math.Ceil(b)) }
			above = func(b float64) bool { return b < math.MaxInt64 && n > int64(math.Floor(b)) }
		}
		if s.Minimum != nil && below(*s.Minimum) || s.Maximum != nil && above(*s.Maximum) {
			return fmt.Errorf("must lie within %s", s.bounds())
		}
		return s.inEnum(v)
	}
	return fmt.Errorf("must be a %s", s.Type)
}

func (s *argSchema) inEnum(v any) error {
	if len(s.Enum) == 0 {
		return nil
	}
	for _, e := range s.Enum {
		if n, ok := v.(json.Number); ok {
			if ef, ok := e.(float64); ok {
				if f, _ := n.Float64(); f == ef {
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

func (s *argSchema) bounds() string {
	lo, hi := "any", "any"
	if s.Minimum != nil {
		lo = fmt.Sprint(*s.Minimum)
	}
	if s.Maximum != nil {
		hi = fmt.Sprint(*s.Maximum)
	}
	return lo + "–" + hi
}

// unrestricted reports whether any string the request size allows passes s: what the consent must say plainly
func (s *argSchema) unrestricted() bool {
	if s.Type == "array" {
		return s.Items.unrestricted()
	}
	return s.Type == "string" && len(s.Enum) == 0 && s.Pattern == ""
}

// An enum longer than this reads as a count in the consent (161 key names would bury the rest); the window lists the
// values when the user expands a grant
const maxListedEnum = 8

// allows says what s lets through, for the consent
func (s *argSchema) allows() string {
	switch {
	case s.Type == "array":
		return "a list of " + s.Items.allows()
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
