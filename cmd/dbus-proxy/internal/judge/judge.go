// Package judge is one client connection's state and what it makes of each message, without I/O: FromClient and
// FromBus say what to do with a message (forward it, drop it or replace it) and which calls of the proxy's own go to
// the bus. One mutex covers everything a verdict reads or writes, the rules in force, the live sets marked used, the
// unique names and the calls awaiting replies, so a live set removed while a message is judged either applies to it
// whole or not at all (models/proxy.als, D1)
package judge

import (
	"errors"
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
)

// Calls waiting for a reply, in each direction
const MaxPendingReplies = 8192

// What becomes of a message
type Verdict int

const (
	Forward Verdict = iota // As it came, with its file descriptors
	Drop                   // Not passed on; its file descriptors closed
	Replace                // Message goes in its place
)

// Action is what to do with a message, then the proxy's own calls to send to the bus after it
type Action struct {
	Verdict Verdict
	Message []byte
	Calls   [][]byte
}

var (
	forwarded = Action{}
	dropped   = Action{Verdict: Drop}
)

// An Action that replaces the message with data, or the error encoding it
func replaced(data []byte, err error) (Action, error) {
	if err != nil {
		return Action{}, err
	}
	return Action{Verdict: Replace, Message: data}, nil
}

// What a reply from the bus to a serial the client (or the proxy) sent is for
type expectKind int

const (
	expectNormal expectKind = iota
	expectHello
	expectListNames // ListNames or ListActivatableNames: the reply is filtered
	expectRewrite   // A refused call sent as a Ping: the reply is swapped for the refusal
	expectFakeMatch // The proxy's own AddMatch
	expectFakeOwner // The proxy's own GetNameOwner of name
)

// A call awaiting its reply from the bus side. Calls to the bus driver, the proxy's own among them, take a reply
// only from the bus; sync marks the proxy's own GetNameOwner of a name, which the client waits for
type expect struct {
	kind    expectKind
	name    string
	rewrite *dbus.Message
	fromBus bool
	sync    bool
}

// A call to the client awaiting its reply: the caller's unique name and serial
type peerCall struct {
	caller string
	serial uint32
}

// ErrRevoked ends a connection that used a live set when the set is removed
var ErrRevoked = errors.New("A live rule set the connection used was removed")

// Judge is one client connection's state
type Judge struct {
	current func() *rules.Rules // The rules in force now
	unixFDs bool                // Whether the client negotiated file descriptors

	mu         sync.Mutex
	awaitBus   map[uint32]expect     // Calls to the bus side awaiting a reply, by the client's (or proxy's) serial
	awaitPeer  map[peerCall]struct{} // Calls to the client awaiting its reply
	names      *nameTable
	fakeSerial uint32
	helloSeen  bool
	// Closed once the owners of the names looked up are known (after Hello, after a live set is added), or nil when
	// there are none; syncing counts the GetNameOwner replies still out
	synced  chan struct{}
	syncing int
	// The rules this message is judged by, taken under mu as it's judged: a live set added or removed applies from
	// the next message
	cur *rules.Rules
	// The live sets a message the client sent or got was judged under, which a set's removal closes the connection
	// for; the live sets added or removed since the client's last message, whose names it hasn't looked up or
	// stopped watching yet; and the match rules watching each set's names
	used     map[*rules.Set]bool
	newSets  []*rules.Set
	goneSets []*rules.Set
	matches  map[*rules.Set][]string
}

// New is the state of a connection judged by the rules current returns, whose client negotiated file descriptors or
// not
func New(current func() *rules.Rules, unixFDs bool) *Judge {
	return &Judge{current: current, unixFDs: unixFDs, awaitBus: map[uint32]expect{},
		awaitPeer: map[peerCall]struct{}{}, names: newNameTable(), fakeSerial: MaxClientSerial,
		used: map[*rules.Set]bool{}, matches: map[*rules.Set][]string{}}
}

// Records a reply expected from the bus side; called with mu held. A serial already awaiting its reply ends the
// connection: overwriting it would let the bus's reply to one call be judged as the reply to another
func (j *Judge) expectFromBus(serial uint32, e expect) error {
	if _, ok := j.awaitBus[serial]; ok {
		return fmt.Errorf("Serial %d reused while its call awaits a reply", serial)
	}
	if len(j.awaitBus) >= MaxPendingReplies {
		return fmt.Errorf("Too many calls awaiting replies")
	}
	j.awaitBus[serial] = e
	return nil
}

// Encodes a call of the proxy's own to the bus and records its reply's purpose; called with mu held
func (j *Judge) fakeCall(out *[][]byte, m *dbus.Message, e expect) error {
	if j.fakeSerial == ^uint32(0) {
		return fmt.Errorf("Out of serials for the proxy's own calls")
	}
	j.fakeSerial++
	e.fromBus = true
	data, err := wire.Encode(m, j.fakeSerial)
	if err != nil {
		return err
	}
	if err := j.expectFromBus(j.fakeSerial, e); err != nil {
		return err
	}
	*out = append(*out, data)
	return nil
}

// The policy and filters for a name by the rules the message is judged by; called with mu held. A live set with a
// filter for the name counts as used, whatever the verdict: its removal ends the connection
func (j *Judge) lookup(name string) (rules.Policy, []*rules.Filter) {
	if j.cur == nil {
		j.cur = j.current()
	}
	p, fs := j.names.lookup(j.cur, name)
	for _, f := range fs {
		if f.Set != nil && f.Set.Live() {
			j.used[f.Set] = true
		}
	}
	return p, fs
}
