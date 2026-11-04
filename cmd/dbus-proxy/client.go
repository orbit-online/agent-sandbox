package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/judge"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/sasl"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
	"golang.org/x/sys/unix"
)

// Time a client gets to authenticate
const authTimeout = 30 * time.Second

// One client's connection and its bus connection: a reader each way judging what it reads, and a sender each way
type client struct {
	p             *Proxy
	conn, bus     *net.UnixConn
	toClient      *wire.Sender
	toBus         *wire.Sender
	clientR, busR *wire.Reader
	unixFDs       bool
	log           *slog.Logger
	acct          *wire.Account
	j             *judge.Judge
	// Ends the connection, from outside its goroutines
	kill func()
}

func (p *Proxy) handle(conn *net.UnixConn) {
	defer conn.Close()
	c := &client{p: p, conn: conn, log: p.log, acct: p.budget.Account()}
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
	guid, err := sasl.Client(c.bus, c.busR, uid)
	if err != nil {
		return fmt.Errorf("Authenticate to the bus: %w", err)
	}
	negotiate := func() (bool, error) { return sasl.NegotiateFDs(c.bus, c.busR) }
	if c.unixFDs, err = sasl.Serve(c.conn, c.clientR, int(cred.Uid), guid, negotiate); err != nil {
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
	c.j = judge.New(c.p.current, c.unixFDs)
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
	c.kill = func() { stop("live rules", judge.ErrRevoked) }
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
	held := func() error {
		if h := c.j.Held(); h != nil {
			select {
			case <-h:
			case <-done:
				return wire.ErrClosed
			}
		}
		return nil
	}
	for {
		m, err := c.clientR.ReadMessage()
		if err != nil {
			return err
		}
		// The names of live sets added since, before the message is judged by them
		calls, err := c.j.Sync()
		if err == nil {
			err = sendAll(c.toBus, calls)
		}
		if err == nil {
			err = held()
		}
		if err == nil {
			var a judge.Action
			if a, err = c.j.FromClient(m); err == nil {
				err = c.act(a, m, c.toBus, c.toBus)
			}
		}
		m.CloseFDs()
		m.Release()
		if err == nil {
			// Hold the client's next message until the proxy knows who owns the names it looked up
			err = held()
		}
		if err != nil {
			return err
		}
	}
}

func (c *client) readBus() error {
	for {
		m, err := c.busR.ReadMessage()
		if err != nil {
			return err
		}
		var a judge.Action
		if a, err = c.j.FromBus(m); err == nil {
			err = c.act(a, m, c.toClient, c.toBus)
		}
		m.CloseFDs()
		m.Release()
		if err != nil {
			return err
		}
	}
}

// Does what the judge said: m forwarded to to (the sender owns its file descriptors from there), replaced or dropped,
// then the proxy's own calls to the bus
func (c *client) act(a judge.Action, m *wire.Message, to, bus *wire.Sender) error {
	switch a.Verdict {
	case judge.Forward:
		data, err := m.Encode()
		if err != nil {
			return fmt.Errorf("Encode message: %w", err)
		}
		if err := to.Send(data, m.TakeFDs()); err != nil {
			return err
		}
	case judge.Replace:
		if err := to.Send(a.Message, nil); err != nil {
			return err
		}
	}
	return sendAll(bus, a.Calls)
}

func sendAll(s *wire.Sender, msgs [][]byte) error {
	for _, data := range msgs {
		if err := s.Send(data, nil); err != nil {
			return err
		}
	}
	return nil
}
