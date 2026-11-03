package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
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
	expectFakeList  // The proxy's own ListNames, for names under a wildcard
)

type expect struct {
	kind    expectKind
	name    string
	rewrite *dbus.Message
}

// One client's connection and its bus connection. The two readers share the state below under mu
type client struct {
	p             *Proxy
	conn, bus     *net.UnixConn
	toClient      *sender
	toBus         *sender
	clientR, busR *reader
	unixFDs       bool
	log           *slog.Logger

	mu         sync.Mutex
	awaitBus   map[uint32]expect   // Calls to the bus side awaiting a reply, by the caller's serial
	awaitPeer  map[uint32]struct{} // Calls to the client awaiting its reply, by the caller's serial
	names      *nameTable
	fakeSerial uint32
	helloSeen  bool
	synced     chan struct{} // Closed once the names under wildcards are known, or nil when there are none
}

func (p *Proxy) handle(conn *net.UnixConn) {
	defer conn.Close()
	c := &client{
		p: p, conn: conn,
		awaitBus:   map[uint32]expect{},
		awaitPeer:  map[uint32]struct{}{},
		names:      newNameTable(),
		fakeSerial: maxClientSerial,
		log:        p.log,
	}
	if err := c.connect(); err != nil {
		c.log.Warn("Client refused", "err", err)
		if c.bus != nil {
			c.bus.Close()
		}
		c.clientR.close()
		if c.busR != nil {
			c.busR.close()
		}
		return
	}
	c.run()
}

// Checks the peer, connects to the bus and authenticates both sides
func (c *client) connect() error {
	c.clientR = newReader(c.conn)
	cred, err := peerCred(c.conn)
	if err != nil {
		return err
	}
	uid := os.Getuid()
	if int(cred.Uid) != uid {
		return fmt.Errorf("Peer uid %d is not the proxy's %d", cred.Uid, uid)
	}
	if c.bus, err = dialBus(c.p.bus); err != nil {
		return err
	}
	c.busR = newReader(c.bus)
	deadline := time.Now().Add(authTimeout)
	c.conn.SetDeadline(deadline)
	c.bus.SetDeadline(deadline)
	guid, err := authBus(c.bus, c.busR, uid)
	if err != nil {
		return fmt.Errorf("Authenticate to the bus: %w", err)
	}
	server := &saslServer{conn: c.conn, r: c.clientR, peerUID: uid, guid: guid,
		negotiate: func() (bool, error) { return negotiateFDsBus(c.bus, c.busR) }}
	if c.unixFDs, err = server.run(); err != nil {
		return fmt.Errorf("Authenticate the client: %w", err)
	}
	if _, err := c.bus.Write([]byte("BEGIN\r\n")); err != nil {
		return err
	}
	if len(c.clientR.fds) > 0 || len(c.busR.fds) > 0 {
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
	c.toClient = newSender(c.conn)
	c.toBus = newSender(c.bus)
	done := make(chan struct{})
	var once sync.Once
	stop := func(side string, err error) {
		once.Do(func() {
			c.log.Debug("Client connection ends", "side", side, "err", err)
			close(done)
			c.conn.Close()
			c.bus.Close()
			c.toClient.close()
			c.toBus.close()
		})
	}
	var wg sync.WaitGroup
	for _, f := range []struct {
		side string
		run  func() error
	}{
		{"client", func() error { return c.readClient(done) }},
		{"bus", c.readBus},
		{"to client", c.toClient.run},
		{"to bus", c.toBus.run},
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stop(f.side, f.run())
		}()
	}
	wg.Wait()
	c.clientR.close()
	c.busR.close()
}

func (c *client) readClient(done chan struct{}) error {
	for {
		m, err := c.clientR.readMessage()
		if err != nil {
			return err
		}
		if err := c.fromClient(m); err != nil {
			m.closeFDs()
			return err
		}
		// Hold the client's next message until the proxy knows who owns the names under wildcards
		c.mu.Lock()
		synced := c.synced
		c.mu.Unlock()
		if synced != nil {
			select {
			case <-synced:
			case <-done:
				return errClosed
			}
		}
	}
}

func (c *client) readBus() error {
	for {
		m, err := c.busR.readMessage()
		if err != nil {
			return err
		}
		if err := c.fromBus(m); err != nil {
			m.closeFDs()
			return err
		}
	}
}

// Passes a message on as it came; the sender owns its file descriptors from here
func forward(s *sender, m *message) error {
	data, err := m.encode()
	if err != nil {
		return fmt.Errorf("Encode message: %w", err)
	}
	fds := m.fds
	m.fds = nil
	return s.send(data, fds)
}

// Records a reply expected from the bus side; called with mu held
func (c *client) expectFromBus(serial uint32, e expect) error {
	if _, ok := c.awaitBus[serial]; !ok && len(c.awaitBus) >= maxPendingReplies {
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
	data, err := encodeNew(m, c.fakeSerial)
	if err != nil {
		return err
	}
	if err := c.expectFromBus(c.fakeSerial, e); err != nil {
		return err
	}
	*out = append(*out, data)
	return nil
}

func sendAll(s *sender, msgs [][]byte) error {
	for _, data := range msgs {
		if err := s.send(data, nil); err != nil {
			return err
		}
	}
	return nil
}
