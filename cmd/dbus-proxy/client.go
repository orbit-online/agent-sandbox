package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
	"golang.org/x/sys/unix"
)

const (
	// Calls waiting for a reply, in each direction
	maxPendingReplies = 8192
	// Time a client gets to authenticate
	authTimeout = 30 * time.Second
)

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

// One client's connection and its bus connection. The two readers share the state below under mu
type client struct {
	p             *Proxy
	conn, bus     *net.UnixConn
	toClient      *wire.Sender
	toBus         *wire.Sender
	clientR, busR *wire.Reader
	unixFDs       bool
	log           *slog.Logger

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
	acct    *wire.Account
	// The rules this message is judged by, taken under mu as it's judged: a live set added or removed applies from
	// the next message (livesets.go)
	cur *Rules
	// The live sets a message the client sent or got was judged under, which a set's removal closes the connection
	// for; the live sets added or removed since the client's last message, whose names it hasn't looked up or
	// stopped watching yet; and the match rules watching each set's names
	used     map[*RuleSet]bool
	newSets  []*RuleSet
	goneSets []*RuleSet
	matches  map[*RuleSet][]string
	// Ends the connection, from outside its goroutines
	kill func()
}

func (p *Proxy) handle(conn *net.UnixConn) {
	defer conn.Close()
	c := &client{
		p: p, conn: conn,
		awaitBus:   map[uint32]expect{},
		awaitPeer:  map[peerCall]struct{}{},
		names:      newNameTable(),
		used:       map[*RuleSet]bool{},
		matches:    map[*RuleSet][]string{},
		fakeSerial: maxClientSerial,
		log:        p.log,
		acct:       p.budget.Account(),
	}
	if err := c.connect(); err != nil {
		c.log.Warn("Client refused", "err", err)
		if c.bus != nil {
			c.bus.Close()
		}
		c.clientR.Close()
		if c.busR != nil {
			c.busR.Close()
		}
		return
	}
	defer func() {
		c.clientR.Close()
		c.busR.Close()
	}()
	c.run()
}

// Checks the peer, connects to the bus and authenticates both sides
func (c *client) connect() error {
	c.clientR = wire.NewReader(c.conn, c.acct)
	cred, err := peerCred(c.conn)
	if err != nil {
		return err
	}
	if int(cred.Uid) != c.p.uid {
		return fmt.Errorf("Peer uid %d is not the proxy's %d", cred.Uid, c.p.uid)
	}
	uid := os.Getuid()
	if c.bus, err = dialBus(c.p.bus); err != nil {
		return err
	}
	c.busR = wire.NewReader(c.bus, c.acct)
	deadline := time.Now().Add(authTimeout)
	c.conn.SetDeadline(deadline)
	c.bus.SetDeadline(deadline)
	guid, err := authBus(c.bus, c.busR, uid)
	if err != nil {
		return fmt.Errorf("Authenticate to the bus: %w", err)
	}
	server := &saslServer{conn: c.conn, r: c.clientR, peerUID: int(cred.Uid), guid: guid,
		negotiate: func() (bool, error) { return negotiateFDsBus(c.bus, c.busR) }}
	if c.unixFDs, err = server.run(); err != nil {
		return fmt.Errorf("Authenticate the client: %w", err)
	}
	if _, err := c.bus.Write([]byte("BEGIN\r\n")); err != nil {
		return err
	}
	if c.clientR.PendingFDs() > 0 || c.busR.PendingFDs() > 0 {
		return fmt.Errorf("File descriptors during authentication")
	}
	c.conn.SetDeadline(time.Time{})
	c.bus.SetDeadline(time.Time{})
	return nil
}

func peerCred(conn *net.UnixConn) (*unix.Ucred, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return cred, cerr
}

// Forwards both ways until either side ends or breaks a rule, then closes both
func (c *client) run() {
	c.toClient = wire.NewSender(c.conn, c.acct)
	c.toBus = wire.NewSender(c.bus, c.acct)
	done := make(chan struct{})
	var once sync.Once
	stop := func(side string, err error) {
		once.Do(func() {
			c.log.Debug("Client connection ends", "side", side, "err", err)
			close(done)
			c.conn.Close()
			c.bus.Close()
			c.toClient.Close()
			c.toBus.Close()
		})
	}
	c.kill = func() { stop("live rules", errRevoked) }
	c.p.register(c)
	defer c.p.unregister(c)
	var wg sync.WaitGroup
	for _, f := range []struct {
		side string
		run  func() error
	}{
		{"client", func() error { return c.readClient(done) }},
		{"bus", c.readBus},
		{"to client", c.toClient.Run},
		{"to bus", c.toBus.Run},
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stop(f.side, f.run())
		}()
	}
	wg.Wait()
}

func (c *client) readClient(done chan struct{}) error {
	for {
		m, err := c.clientR.ReadMessage()
		if err != nil {
			return err
		}
		// The names of live sets added since, before the message is judged by them
		if err := c.syncSets(done); err != nil {
			m.CloseFDs()
			m.Release()
			return err
		}
		err = c.fromClient(m)
		m.CloseFDs()
		m.Release()
		if err != nil {
			return err
		}
		// Hold the client's next message until the proxy knows who owns the names it looked up
		c.mu.Lock()
		synced := c.synced
		c.mu.Unlock()
		if synced != nil {
			select {
			case <-synced:
			case <-done:
				return wire.ErrClosed
			}
		}
	}
}

func (c *client) readBus() error {
	for {
		m, err := c.busR.ReadMessage()
		if err != nil {
			return err
		}
		err = c.fromBus(m)
		m.CloseFDs()
		m.Release()
		if err != nil {
			return err
		}
	}
}

// Passes a message on as it came; the sender owns its file descriptors from here
func forward(s *wire.Sender, m *wire.Message) error {
	data, err := m.Encode()
	if err != nil {
		return fmt.Errorf("Encode message: %w", err)
	}
	return s.Send(data, m.TakeFDs())
}

// Records a reply expected from the bus side; called with mu held. A serial already awaiting its reply ends the
// connection: overwriting it would let the bus's reply to one call be judged as the reply to another
func (c *client) expectFromBus(serial uint32, e expect) error {
	if _, ok := c.awaitBus[serial]; ok {
		return fmt.Errorf("Serial %d reused while its call awaits a reply", serial)
	}
	if len(c.awaitBus) >= maxPendingReplies {
		return fmt.Errorf("Too many calls awaiting replies")
	}
	c.awaitBus[serial] = e
	return nil
}

// Encodes a call of the proxy's own to the bus and records its reply's purpose; called with mu held. The caller
// sends it once mu is released
func (c *client) fakeCall(out *[][]byte, m *dbus.Message, e expect) error {
	if c.fakeSerial == ^uint32(0) {
		return fmt.Errorf("Out of serials for the proxy's own calls")
	}
	c.fakeSerial++
	e.fromBus = true
	data, err := wire.Encode(m, c.fakeSerial)
	if err != nil {
		return err
	}
	if err := c.expectFromBus(c.fakeSerial, e); err != nil {
		return err
	}
	*out = append(*out, data)
	return nil
}

func sendAll(s *wire.Sender, msgs [][]byte) error {
	for _, data := range msgs {
		if err := s.Send(data, nil); err != nil {
			return err
		}
	}
	return nil
}
