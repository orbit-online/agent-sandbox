package judge

// The hold after Hello: the proxy looks up who owns the names the rules mention, and the client's next message waits
// for the answers

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

// Held is closed once the client's next message may be judged, or nil when it may be now: after Hello, the proxy
// first learns who owns the names the rules mention, so a call by an owner's unique name right away passes too
func (j *Judge) Held() <-chan struct{} {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.synced
}

// Watches names and asks who owns them, holding the client until the owners are known. Called with mu held
func (j *Judge) lookupNames(names []string, fakes *[][]byte) error {
	for _, name := range names {
		if err := j.fakeCall(fakes, busCall("AddMatch", ownerMatch(name)), expect{kind: expectFakeMatch}); err != nil {
			return err
		}
		if err := j.fakeCall(fakes, busCall("GetNameOwner", name), expect{kind: expectFakeOwner, name: name, sync: true}); err != nil {
			return err
		}
		j.holdFor(1)
	}
	return nil
}
