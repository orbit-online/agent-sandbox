package rules

// The bus driver, which every client may talk to
const BusName = "org.freedesktop.DBus"

// The rule sets a proxy applies, looked up together: the bus's own, the command line's, then the live ones. Never
// changed once in use: adding or removing a live set makes new Rules (With, Without)
type Rules struct {
	sets []*Set
}

// Every client may talk to the bus itself
func New(sets ...*Set) *Rules {
	bus := newSet()
	bus.byName[BusName] = []*Filter{{policy: Talk, types: All, Set: bus}}
	return &Rules{sets: append([]*Set{bus}, sets...)}
}

// With is the rules with rs added
func (r *Rules) With(rs *Set) *Rules {
	return &Rules{sets: append(append([]*Set{}, r.sets...), rs)}
}

// Without is the rules without rs
func (r *Rules) Without(rs *Set) *Rules {
	out := &Rules{}
	for _, s := range r.sets {
		if s != rs {
			out.sets = append(out.sets, s)
		}
	}
	return out
}

// The highest policy and the filters that apply to a well-known name, from every set
func (r *Rules) Lookup(name string) (Policy, []*Filter) {
	p := None
	var matched []*Filter
	for _, rs := range r.sets {
		for _, f := range rs.byName[name] {
			p = max(p, f.policy)
			matched = append(matched, f)
		}
	}
	return p, matched
}

// The names the static sets mention other than the bus
func (r *Rules) Names() []string {
	var out []string
	for _, rs := range r.sets {
		if rs.Live() {
			continue
		}
		for _, name := range rs.Names() {
			if name != BusName {
				out = append(out, name)
			}
		}
	}
	return out
}

// The live sets
func (r *Rules) Live() []*Set {
	var out []*Set
	for _, rs := range r.sets {
		if rs.Live() {
			out = append(out, rs)
		}
	}
	return out
}
