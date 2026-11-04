package wire

import (
	"errors"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// What may wait to be written to one side, in bytes: one message of the largest size, or many smaller ones
const maxQueued = MaxMessageSize

type outMsg struct {
	data []byte
	fds  []int
}

// Writes messages to one side in the order they're queued, on a goroutine of its own, so a reader never blocks on
// the side it reads from. A full queue blocks the reader that fills it, which stops reading its side in turn
type Sender struct {
	acct   *Account
	conn   *net.UnixConn
	mu     sync.Mutex
	cond   *sync.Cond
	queue  []outMsg
	bytes  int
	closed bool
}

var ErrClosed = errors.New("Connection closed")

func NewSender(conn *net.UnixConn, acct *Account) *Sender {
	s := &Sender{conn: conn, acct: acct}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// Queues a message; its file descriptors belong to the Sender from here, closed once written or dropped. They
// stay on the client's Account until then (the reader took them); the bytes are taken here. A client over its
// share is refused, and its connection ends
func (s *Sender) Send(data []byte, fds []int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for !s.closed && s.bytes > 0 && s.bytes+len(data) > maxQueued {
		s.cond.Wait()
	}
	if s.closed {
		s.acct.closeFDs(fds)
		return ErrClosed
	}
	if err := s.acct.take(len(data), 0); err != nil {
		s.acct.closeFDs(fds)
		return err
	}
	s.queue = append(s.queue, outMsg{data, fds})
	s.bytes += len(data)
	s.cond.Broadcast()
	return nil
}

// Stops the Sender: queued messages are dropped and their file descriptors closed
func (s *Sender) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, m := range s.queue {
		s.acct.closeFDs(m.fds)
		s.acct.give(len(m.data), 0)
	}
	s.queue = nil
	s.cond.Broadcast()
}

// Writes until closed or a write fails
func (s *Sender) Run() error {
	for {
		s.mu.Lock()
		for !s.closed && len(s.queue) == 0 {
			s.cond.Wait()
		}
		if s.closed {
			s.mu.Unlock()
			return ErrClosed
		}
		m := s.queue[0]
		s.queue[0] = outMsg{}
		s.queue = s.queue[1:]
		s.mu.Unlock()

		err := s.write(m)
		s.acct.closeFDs(m.fds)
		s.acct.give(len(m.data), 0)

		s.mu.Lock()
		s.bytes -= len(m.data)
		s.cond.Broadcast()
		s.mu.Unlock()
		if err != nil {
			return err
		}
	}
}

// The file descriptors go with the message's first bytes; whatever sendmsg left goes after
func (s *Sender) write(m outMsg) error {
	data := m.data
	if len(m.fds) > 0 {
		n, _, err := s.conn.WriteMsgUnix(data, unix.UnixRights(m.fds...), nil)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	for len(data) > 0 {
		n, err := s.conn.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func closeAll(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
}
