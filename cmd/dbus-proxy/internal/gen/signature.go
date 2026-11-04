package gen

import (
	"strings"

	"pgregory.net/rapid"
)

// Basic type codes; 'h' only where file descriptors come along
const basics = "ybnqiuxtdsog"

// A single complete type of at most depth containers: basic types, variants, arrays, dicts and structs
func singleType(t *rapid.T, depth int) string {
	k := rapid.IntRange(0, 9).Draw(t, "kind")
	if depth <= 0 || k < 5 {
		if k == 4 {
			return "v"
		}
		return string(charFrom(basics).Draw(t, "basic"))
	}
	switch k {
	case 5, 6:
		return "a" + singleType(t, depth-1)
	case 7:
		return "a{" + string(charFrom(basics).Draw(t, "key")) + singleType(t, depth-1) + "}"
	}
	n := rapid.IntRange(1, 4).Draw(t, "fields")
	var b strings.Builder
	b.WriteByte('(')
	for range n {
		b.WriteString(singleType(t, depth-1))
	}
	b.WriteByte(')')
	return b.String()
}

// ValidSignature: up to four single complete types, or a deep legal one at the specification's limits: 32 arrays,
// 32 structs, both, 255 bytes
func ValidSignature() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		switch rapid.IntRange(0, 9).Draw(t, "shape") {
		case 0:
			return strings.Repeat("a", 32) + "y"
		case 1:
			return strings.Repeat("(", 32) + "y" + strings.Repeat(")", 32)
		case 2:
			return strings.Repeat("a", 32) + strings.Repeat("(", 32) + "s" + strings.Repeat(")", 32)
		case 3:
			return strings.Repeat("y", 255)
		}
		var b strings.Builder
		for range rapid.IntRange(0, 4).Draw(t, "types") {
			b.WriteString(singleType(t, 3))
		}
		return b.String()
	})
}

// InvalidSignature: a near miss: unbalanced, an empty struct, a dict entry outside an array or with a container key
// or three types, nesting past the limits, 256 bytes, a code that isn't one
func InvalidSignature() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		ok := singleType(t, 2)
		switch rapid.IntRange(0, 10).Draw(t, "miss") {
		case 0:
			return "(" + ok
		case 1:
			return ok + ")"
		case 2:
			return "()"
		case 3:
			return "{s" + ok + "}"
		case 4:
			return "a{" + rapid.SampledFrom([]string{"v", "as", "(i)"}).Draw(t, "key") + "s}"
		case 5:
			return "a{sss}"
		case 6:
			return strings.Repeat("a", 33) + "y"
		case 7:
			return strings.Repeat("(", 33) + "y" + strings.Repeat(")", 33)
		case 8:
			return strings.Repeat("y", 256)
		case 9:
			return "a"
		}
		return ok + rapid.SampledFrom([]string{"z", "e", "m", "*", " ", "r"}).Draw(t, "code")
	})
}

// Signature: valid three times in four
func Signature() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		if rapid.IntRange(0, 3).Draw(t, "valid") > 0 {
			return ValidSignature().Draw(t, "sig")
		}
		return InvalidSignature().Draw(t, "sig")
	})
}
