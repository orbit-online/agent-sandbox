package judge

import "github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"

// A connection's side of the live rule sets: their names looked up when one is added, before the client's next
// message, and whether the connection used one that's removed

// Holds the client's next message until n more of the proxy's own calls are answered; called with mu held
func (j *Judge) holdFor(n int) {
	j.syncing += n
	if j.synced == nil {
		j.synced = make(chan struct{})
	}
}

// Releases the client once every GetNameOwner it waits for is answered; called with mu held
func (j *Judge) syncDone() {
	if j.syncing == 0 && j.synced != nil {
		close(j.synced)
		j.synced = nil
	}
}

// Held is closed once the client's next message may be judged, or nil when it may be now: after Hello and after a
// live set is added, the proxy first learns who owns the names they mention, so a call by an owner's unique name
// right away passes too
func (j *Judge) Held() <-chan struct{} {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.synced
}

// Watches names and asks who owns them, holding the client until the owners are known. Returns the match rules.
// Called with mu held
func (j *Judge) lookupNames(names []string, fakes *[][]byte) ([]string, error) {
	var matches []string
	for _, name := range names {
		match := ownerMatch(name)
		if err := j.fakeCall(fakes, busCall("AddMatch", match), expect{kind: expectFakeMatch}); err != nil {
			return nil, err
		}
		matches = append(matches, match)
		if err := j.fakeCall(fakes, busCall("GetNameOwner", name), expect{kind: expectFakeOwner, name: name, sync: true}); err != nil {
			return nil, err
		}
		j.holdFor(1)
	}
	return matches, nil
}

// lookupNames for a live set's names, whose match rules go when the set does
func (j *Judge) lookupSet(rs *rules.Set, fakes *[][]byte) error {
	matches, err := j.lookupNames(rs.Names(), fakes)
	j.matches[rs] = append(j.matches[rs], matches...)
	return err
}

// Sync is due before each message from the client is judged: it looks up the names of the live sets added since
// and stops watching those of the sets removed, returning the calls to the bus that takes. Before Hello there's
// nothing to do: Hello takes the live sets there are then. The caller sends the calls on the client's side, so they
// never overtake its Hello, then waits for Held
func (j *Judge) Sync() ([][]byte, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var calls [][]byte
	var err error
	if j.helloSeen {
		for _, rs := range j.goneSets {
			for _, m := range j.matches[rs] {
				if err == nil {
					err = j.fakeCall(&calls, busCall("RemoveMatch", m), expect{kind: expectFakeMatch})
				}
			}
			delete(j.matches, rs)
		}
		for _, rs := range j.newSets {
			if err == nil {
				err = j.lookupSet(rs, &calls)
			}
		}
	}
	j.goneSets, j.newSets = nil, nil
	return calls, err
}

// AddSet notes a live set added to the rules in force, whose names the next Sync looks up
func (j *Judge) AddSet(rs *rules.Set) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.newSets = append(j.newSets, rs)
}

// RemoveSet notes a live set removed from the rules in force, after the removal: a message judged under the set
// finished before, one judged after sees the rules without it. Whether a message the client sent or got was judged
// under it, which ends the connection (ErrRevoked); otherwise the next Sync stops watching its names
func (j *Judge) RemoveSet(rs *rules.Set) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	used := j.used[rs]
	delete(j.used, rs)
	for i, s := range j.newSets {
		if s == rs {
			j.newSets = append(j.newSets[:i:i], j.newSets[i+1:]...)
			break
		}
	}
	if !used && j.matches[rs] != nil {
		j.goneSets = append(j.goneSets, rs)
	}
	return used
}
