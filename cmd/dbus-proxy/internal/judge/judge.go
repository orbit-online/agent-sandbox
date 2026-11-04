// Package judge is one client connection's state and what it makes of each message, without I/O: FromClient and
// FromBus say what to do with a message (forward it, drop it or replace it) and which calls of the proxy's own go to
// the bus. One mutex covers everything a verdict reads or writes, the unique names and the calls awaiting replies
package judge

import (
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

// Judge is one client connection's state
type Judge struct {
	rules   *rules.Rules
	unixFDs bool // Whether the client negotiated file descriptors

	mu         sync.Mutex
	awaitBus   map[uint32]expect     // Calls to the bus side awaiting a reply, by the client's (or proxy's) serial
	awaitPeer  map[peerCall]struct{} // Calls to the client awaiting its reply
	names      *nameTable
	fakeSerial uint32
	helloSeen  bool
	// Closed once the owners of the rules' names are known after Hello, or nil when there are none; syncing counts
	// the GetNameOwner replies still out
	synced  chan struct{}
	syncing int
}

// New is the state of a connection judged by r, whose client negotiated file descriptors or not
func New(r *rules.Rules, unixFDs bool) *Judge {
	return &Judge{rules: r, unixFDs: unixFDs, awaitBus: map[uint32]expect{}, awaitPeer: map[peerCall]struct{}{},
		names: newNameTable(), fakeSerial: MaxClientSerial}
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

// The policy and filters for a name; called with mu held
func (j *Judge) lookup(name string) (rules.Policy, []*rules.Filter) {
	return j.names.lookup(j.rules, name)
}
