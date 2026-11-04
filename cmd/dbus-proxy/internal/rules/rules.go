package rules

// The bus driver, which every client may talk to
const BusName = "org.freedesktop.DBus"

// The rule sets a proxy applies, looked up together: the bus's own and the command line's. Never changed once in use
type Rules struct {
	sets []*Set
}

// Every client may talk to the bus itself
func New(sets ...*Set) *Rules {
	bus := newSet()
	bus.byName[BusName] = []*Filter{{policy: Talk, types: All}}
	return &Rules{sets: append([]*Set{bus}, sets...)}
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

// The names the sets mention other than the bus
func (r *Rules) Names() []string {
	var out []string
	for _, rs := range r.sets {
		for _, name := range rs.Names() {
			if name != BusName {
				out = append(out, name)
			}
		}
	}
	return out
}
