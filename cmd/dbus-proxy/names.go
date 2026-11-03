package main

import "errors"

const (
	// Unique names a client's policy tracks
	maxUniqueIDs = 16384
	// Well-known names one unique name is recorded as having owned
	maxOwnedNames = 256
)

// A unique name's policy of its own (TALK for the client itself, SEE for peers that sent it something) and the
// well-known names it has owned while the proxy watched, whose rules apply to it too. Sticky, as in xdg-dbus-proxy: a
// name released keeps its rules on its last owner, since a proxy can't drop them without racing
type uniqueID struct {
	policy policy
	owned  []string
}

// The unique names one client's policy knows, bounded: when full, the oldest that only SEE (a past caller) goes
// first; when none does, the table refuses and the connection ends
type nameTable struct {
	ids   map[string]*uniqueID
	order []string
}

var errTooManyNames = errors.New("Too many unique names tracked")

func newNameTable() *nameTable {
	return &nameTable{ids: map[string]*uniqueID{}}
}

func (t *nameTable) entry(id string) (*uniqueID, error) {
	if e, ok := t.ids[id]; ok {
		return e, nil
	}
	if len(t.ids) >= maxUniqueIDs && !t.evict() {
		return nil, errTooManyNames
	}
	e := &uniqueID{}
	t.ids[id] = e
	t.order = append(t.order, id)
	return e, nil
}

func (t *nameTable) evict() bool {
	for i, id := range t.order {
		if e := t.ids[id]; e.policy <= policySee && len(e.owned) == 0 {
			delete(t.ids, id)
			t.order = append(t.order[:i:i], t.order[i+1:]...)
			return true
		}
	}
	return false
}

// Raises a unique name's own policy, never lowers it
func (t *nameTable) raise(id string, p policy) error {
	e, err := t.entry(id)
	if err != nil {
		return err
	}
	if p > e.policy {
		e.policy = p
	}
	return nil
}

func (t *nameTable) addOwned(id, name string) error {
	e, err := t.entry(id)
	if err != nil {
		return err
	}
	for _, n := range e.owned {
		if n == name {
			return nil
		}
	}
	if len(e.owned) >= maxOwnedNames {
		return errTooManyNames
	}
	e.owned = append(e.owned, name)
	return nil
}

// A unique name is never reused, so one that left the bus can go
func (t *nameTable) forget(id string) {
	if _, ok := t.ids[id]; !ok {
		return
	}
	delete(t.ids, id)
	for i, o := range t.order {
		if o == id {
			t.order = append(t.order[:i:i], t.order[i+1:]...)
			break
		}
	}
}

// The highest policy and the filters for a destination or sender: the bus's own talk for none, a unique name's own
// policy and the rules of every name it owned, or a well-known name's rules
func (t *nameTable) lookup(rules *Rules, name string) (policy, []*filter) {
	if name == "" {
		return policyTalk, []*filter{matchAll[policyTalk]}
	}
	if name[0] != ':' {
		return rules.lookup(name)
	}
	e, ok := t.ids[name]
	if !ok {
		return policyNone, nil
	}
	p := e.policy
	var fs []*filter
	if p > policyNone {
		fs = append(fs, matchAll[p])
	}
	for _, owned := range e.owned {
		op, ofs := rules.lookup(owned)
		p = max(p, op)
		fs = append(fs, ofs...)
	}
	return p, fs
}
