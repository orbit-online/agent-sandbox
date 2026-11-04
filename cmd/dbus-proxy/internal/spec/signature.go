package spec

// Signatures ("Type System", "Valid Signatures"): at most 255 bytes, of single complete types, arrays nested at most 32
// deep and structs at most 32, structs not empty, dict entries only as an array's element, of two types, the first
// basic

const (
	MaxSignature   = 255
	MaxArrayDepth  = 32
	MaxStructDepth = 32
)

// Validity of a check the specification may leave open
type Validity int

const (
	Valid Validity = iota
	Invalid
	// Unspecified: the specification doesn't say. libdbus counts a dict entry as a struct toward the depth limit,
	// godbus doesn't; neither is wrong by the text
	Unspecified
)

// BasicType: a type code of a basic type
func BasicType(c byte) bool {
	switch c {
	case 'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 'd', 'h', 's', 'o', 'g':
		return true
	}
	return false
}

type sigParser struct {
	s     string
	pos   int
	worst Validity
}

// One single complete type from p.pos, with the arrays and structs (and, as libdbus counts them, dict entries)
// around it
func (p *sigParser) single(arrays, structs, dicts int) bool {
	if p.pos >= len(p.s) {
		return false
	}
	c := p.s[p.pos]
	p.pos++
	switch {
	case BasicType(c), c == 'v':
		return true
	case c == 'a':
		if arrays+1 > MaxArrayDepth {
			return false
		}
		if p.pos < len(p.s) && p.s[p.pos] == '{' {
			p.pos++
			if structs+dicts+1 > MaxStructDepth {
				p.worst = Unspecified
			}
			if p.pos >= len(p.s) || !BasicType(p.s[p.pos]) {
				return false
			}
			p.pos++
			if !p.single(arrays+1, structs, dicts+1) {
				return false
			}
			if p.pos >= len(p.s) || p.s[p.pos] != '}' {
				return false
			}
			p.pos++
			return true
		}
		return p.single(arrays+1, structs, dicts)
	case c == '(':
		if structs+1 > MaxStructDepth {
			return false
		}
		if structs+dicts+1 > MaxStructDepth {
			p.worst = Unspecified
		}
		n := 0
		for p.pos < len(p.s) && p.s[p.pos] != ')' {
			if !p.single(arrays, structs+1, dicts) {
				return false
			}
			n++
		}
		if p.pos >= len(p.s) || n == 0 {
			return false
		}
		p.pos++
		return true
	}
	return false
}

// Signature: a sequence of single complete types (the empty one included), as a message's body has
func Signature(s string) Validity {
	if len(s) > MaxSignature {
		return Invalid
	}
	p := &sigParser{s: s}
	for p.pos < len(s) {
		if !p.single(0, 0, 0) {
			return Invalid
		}
	}
	return p.worst
}

// SingleType: exactly one single complete type, as a variant holds
func SingleType(s string) Validity {
	if s == "" || len(s) > MaxSignature {
		return Invalid
	}
	p := &sigParser{s: s}
	if !p.single(0, 0, 0) || p.pos != len(s) {
		return Invalid
	}
	return p.worst
}
