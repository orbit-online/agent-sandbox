package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// No answer in this long denies
	askTimeout = 2 * time.Minute
	// Once the user opens the window on a request, it waits this long at most
	optionsTimeout = 10 * time.Minute
	// Requests the user may turn down in a row before the broker stops asking about the capability for a while
	maxRefusals = 3
	blockFor    = 2 * time.Minute
	maxReason   = 300
	maxLog      = 200
	// Bounds on what a client can hold or send: open connections per socket (watch streams included), and a
	// request's size
	maxConns   = 64
	maxRequest = 64 << 10
)

// How long a client has to send its request
var readTimeout = 10 * time.Second

// A request on request.sock, or an operation on control.sock
type request struct {
	Op         string          `json:"op"`
	Capability string          `json:"capability,omitempty"`
	Params     json.RawMessage `json:"params,omitempty"`
	Reason     string          `json:"reason,omitempty"`
	Lease      string          `json:"lease,omitempty"`
	Grant      string          `json:"grant,omitempty"`
	// control.sock's answer to a pending request
	Pending string `json:"pending,omitempty"`
	Allow   bool   `json:"allow,omitempty"`
	// control.sock's end: the ended grants whose holders to end, as the window shows them
	Grants []string `json:"grants,omitempty"`
}

type response struct {
	Error        string           `json:"error,omitempty"`
	Grant        *grant           `json:"grant,omitempty"`
	Credential   string           `json:"credential,omitempty"`
	Grants       []*grant         `json:"grants,omitempty"`
	Capabilities []capabilityInfo `json:"capabilities,omitempty"`
	Pending      []*pending       `json:"pending,omitempty"`
	Holders      []holder         `json:"holders,omitempty"`
	Always       []alwaysGrant    `json:"always,omitempty"`
	Log          []logEntry       `json:"log,omitempty"`
	Held         []held           `json:"held,omitempty"`
}

type capabilityInfo struct {
	ID          string                     `json:"id"`
	Type        string                     `json:"type"`
	Description string                     `json:"description"`
	Params      map[string]json.RawMessage `json:"params,omitempty"`
	Instances   json.RawMessage            `json:"instances,omitempty"`
	Error       string                     `json:"error,omitempty"`
	// Service: whether the plugin speaks MCP on its grant socket, whose tools the MCP server offers
	Tools bool `json:"tools,omitempty"`
}

type grant struct {
	ID         string          `json:"id"`
	Capability string          `json:"capability"`
	Params     json.RawMessage `json:"params"`
	Summary    string          `json:"summary"`
	Lease      string          `json:"lease"`
	Expires    time.Time       `json:"expires,omitzero"`
	// The sessions it was given to, which hold it until they release it. A session lease's are its anchors too: it
	// ends with the last
	Sessions []string `json:"sessions,omitempty"`
	Socket   string   `json:"socket,omitempty"`
	// Attach: where it's mounted in the sandbox, and what, as resolved
	Path    string    `json:"path,omitempty"`
	Source  string    `json:"source,omitempty"`
	Granted time.Time `json:"granted"`
	// Attach, once revoked: what still held files on it
	Holders []holder `json:"holders,omitempty"`
	// Attach: the device and root of its mount, by which copies of it are found
	dev, root string
	// Attach: the identity (device:inode) of the folder the user was asked about, which the mount must be
	shown string

	cap      *capability
	sessions map[string]*session // under broker.mu
	anon     bool                // given to a caller without a session, under broker.mu
	sessGone chan struct{}       // closed when the last session leaves
	ended    chan struct{}
	end      func(why string)
	unlock   func()
}

// A request waiting for the user, which the window can answer once they pick Options
type pending struct {
	ID         string          `json:"id"`
	Capability string          `json:"capability"`
	Params     json.RawMessage `json:"params"`
	Summary    string          `json:"summary"`
	Reason     string          `json:"reason"`
	Lease      string          `json:"lease"`
	Options    bool            `json:"options"`

	answer chan request
	// Its place in the window's list, by arrival: rows don't move as others come and go
	seq uint64
}

type alwaysGrant struct {
	Capability string          `json:"capability"`
	Params     json.RawMessage `json:"params"`
	Granted    time.Time       `json:"granted"`
}

type logEntry struct {
	Time     time.Time `json:"time"`
	Summary  string    `json:"summary"`
	Reason   string    `json:"reason,omitempty"`
	Decision string    `json:"decision"`
}

type storeData struct {
	Always []alwaysGrant `json:"always"`
	Log    []logEntry    `json:"log"`
}

// The notification's question and the user's answer: allow, deny or options
type prompt struct {
	Summary, Reason, Lease string
	// Whether to offer Options, which needs the window
	Options bool
}

type asker func(ctx context.Context, p prompt) (string, error)

type gate struct {
	asking       bool
	refused      int
	blockedUntil time.Time
}

type broker struct {
	cfg  config
	caps map[string]*capability
	sb   *sandbox
	ask  asker

	mu         sync.Mutex
	saving     sync.Mutex
	grants     map[string]*grant
	pending    map[string]*pending
	gates      map[string]*gate
	store      storeData
	shared     bool
	pendingSeq uint64
	// share was asked for, or an earlier daemon's found: it's done once per sandbox
	shareAsked bool
	lockOK     bool
	watches    map[chan []byte]bool
	// What still held attach grants when they ended
	heldGrants []held
	// Added to the time, by tests
	skew atomic.Int64
}

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}
