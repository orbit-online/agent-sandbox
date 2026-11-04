// Package gen generates D-Bus input for the proxy's property tests from the specification's grammar, valid and
// invalid alike: names, signatures, header fields, bodies, whole messages and byte-level mutations of them, SASL
// lines and the proxy's configs. Valid input leans to the unusual (long names, deep signatures, odd paths); invalid
// input is mostly near misses of the grammar. What's valid is for internal/spec to decide, not the generator: the labels
// here only steer the mix
package gen

import (
	"strings"

	"pgregory.net/rapid"
)

const (
	lower  = "abcdefghijklmnopqrstuvwxyz"
	upper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits = "0123456789"
)

// Characters a near miss puts in a name: what the grammar leaves out
var badChars = []string{" ", "/", "*", "!", ":", "@", "=", "'", "\t", "é", "\x00", "\xff", ".", "-"}

func charFrom(set string) *rapid.Generator[byte] {
	return rapid.Custom(func(t *rapid.T) byte { return set[rapid.IntRange(0, len(set)-1).Draw(t, "c")] })
}

// An element of [A-Za-z_] then [A-Za-z0-9_] (with '-' when hyphen), 1 to n bytes; digitFirst lets it start with a
// digit
func element(t *rapid.T, n int, hyphen, digitFirst bool) string {
	first := lower + upper + "_"
	rest := first + digits
	if hyphen {
		first += "-"
		rest += "-"
	}
	if digitFirst {
		first += digits
	}
	size := rapid.IntRange(1, n).Draw(t, "len")
	b := []byte{charFrom(first).Draw(t, "first")}
	for len(b) < size {
		b = append(b, charFrom(rest).Draw(t, "rest"))
	}
	return string(b)
}

// Elements joined by dots, 2 to 5 of them, or one long name filled up to 255 bytes
func dotted(t *rapid.T, hyphen, digitFirst bool, room int) string {
	if rapid.IntRange(0, 9).Draw(t, "long") == 0 {
		// The longest valid: elements filling exactly room bytes
		var elems []string
		left := room
		for left > 0 {
			n := min(left, rapid.IntRange(1, 64).Draw(t, "elem"))
			if len(elems) > 0 {
				n = min(left-1, n)
				if n < 1 {
					break
				}
				left--
			}
			elems = append(elems, element(t, 1, hyphen, digitFirst)+strings.Repeat("a", n-1))
			left -= n
		}
		if len(elems) >= 2 {
			return strings.Join(elems, ".")
		}
	}
	k := rapid.IntRange(2, 5).Draw(t, "elems")
	elems := make([]string, k)
	for i := range elems {
		elems[i] = element(t, 12, hyphen, digitFirst)
	}
	return strings.Join(elems, ".")
}

// A near miss of a dotted name: an empty element, a leading digit, one element, 256 bytes, a bad character, a
// leading or trailing dot
func dottedMiss(t *rapid.T, valid string) string {
	switch rapid.IntRange(0, 6).Draw(t, "miss") {
	case 0:
		i := strings.IndexByte(valid, '.')
		return valid[:i] + "." + valid[i:]
	case 1:
		return "7" + valid
	case 2:
		return strings.ReplaceAll(valid, ".", "")
	case 3:
		return valid + "." + strings.Repeat("x", max(1, 255-len(valid)))
	case 4:
		i := rapid.IntRange(0, len(valid)).Draw(t, "at")
		return valid[:i] + rapid.SampledFrom(badChars).Draw(t, "bad") + valid[i:]
	case 5:
		return "." + valid
	}
	return valid + "."
}

// Draws a valid name most of the time, a near miss otherwise
func mostly(valid func(*rapid.T) string, miss func(*rapid.T, string) string) *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		v := valid(t)
		if rapid.IntRange(0, 3).Draw(t, "valid") > 0 {
			return v
		}
		return miss(t, v)
	})
}

// WellKnownName: a well-known bus name or a near miss
func WellKnownName() *rapid.Generator[string] {
	return mostly(func(t *rapid.T) string { return dotted(t, true, false, 255) }, dottedMiss)
}

// UniqueName: a unique name (":1.42", or elements that may start with digits) or a near miss
func UniqueName() *rapid.Generator[string] {
	return mostly(func(t *rapid.T) string {
		if rapid.Bool().Draw(t, "plain") {
			return ":" + rapid.SampledFrom([]string{"1", "2", "10"}).Draw(t, "a") + "." +
				rapid.SampledFrom([]string{"0", "5", "42", "65536"}).Draw(t, "b")
		}
		return ":" + dotted(t, true, true, 254)
	}, func(t *rapid.T, v string) string {
		if rapid.Bool().Draw(t, "colon") {
			return v + ":"
		}
		return ":" + dottedMiss(t, v[1:])
	})
}

// InterfaceName: an interface or error name, or a near miss (a hyphen among them); now and then the reserved local
// interface, valid by the grammar and refused by the bus
func InterfaceName() *rapid.Generator[string] {
	return mostly(func(t *rapid.T) string {
		if rapid.IntRange(0, 19).Draw(t, "local") == 0 {
			return "org.freedesktop.DBus.Local"
		}
		return dotted(t, false, false, 255)
	}, dottedMiss)
}

// MemberName: a member or a near miss: a dot, a leading digit, empty, 256 bytes, a bad character
func MemberName() *rapid.Generator[string] {
	return mostly(func(t *rapid.T) string {
		if rapid.IntRange(0, 9).Draw(t, "long") == 0 {
			return element(t, 1, false, false) + strings.Repeat("m", 254)
		}
		return element(t, 24, false, false)
	}, func(t *rapid.T, v string) string {
		switch rapid.IntRange(0, 4).Draw(t, "miss") {
		case 0:
			return v + ".x"
		case 1:
			return "9" + v
		case 2:
			return ""
		case 3:
			return v + strings.Repeat("m", 256)
		}
		i := rapid.IntRange(0, len(v)).Draw(t, "at")
		return v[:i] + rapid.SampledFrom(badChars).Draw(t, "bad") + v[i:]
	})
}

// ObjectPath: "/", or elements of [A-Za-z0-9_] (deep ones, digits first, long ones), now and then the reserved local
// path, or a near miss: a trailing or doubled slash, none leading, a bad character
func ObjectPath() *rapid.Generator[string] {
	return mostly(func(t *rapid.T) string {
		if rapid.IntRange(0, 19).Draw(t, "local") == 0 {
			return "/org/freedesktop/DBus/Local"
		}
		k := rapid.IntRange(0, 8).Draw(t, "depth")
		if k == 0 {
			return "/"
		}
		var b strings.Builder
		for range k {
			b.WriteString("/" + element(t, 16, false, true))
		}
		return b.String()
	}, func(t *rapid.T, v string) string {
		switch rapid.IntRange(0, 3).Draw(t, "miss") {
		case 0:
			return v + "/"
		case 1:
			return v + "//x"
		case 2:
			return strings.TrimPrefix(v, "/") + "x"
		}
		return v + "/" + rapid.SampledFrom(badChars).Draw(t, "bad")
	})
}
