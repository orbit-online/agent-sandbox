package main

import (
	"errors"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// What may wait to be written to one side, in bytes: one message of the largest size, or many smaller ones
const maxQueued = maxMessageSize

type outMsg struct {
	data []byte
	fds  []int
}

// Writes messages to one side in the order they're queued, on a goroutine of its own, so a reader never blocks on
// the side it reads from. A full queue blocks the reader that fills it, which stops reading its side in turn
type sender struct {
	conn   *net.UnixConn
	mu     sync.Mutex
	cond   *sync.Cond
	queue  []outMsg
	bytes  int
	closed bool
}

var errClosed = errors.New("Connection closed")

func newSender(conn *net.UnixConn) *sender {
	s := &sender{conn: conn}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// Queues a message; its file descriptors belong to the sender from here, closed once written or dropped
func (s *sender) send(data []byte, fds []int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for !s.closed && s.bytes > 0 && s.bytes+len(data) > maxQueued {
		s.cond.Wait()
	}
	if s.closed {
		closeAll(fds)
		return errClosed
	}
	s.queue = append(s.queue, outMsg{data, fds})
	s.bytes += len(data)
	s.cond.Broadcast()
	return nil
}

// Stops the sender: queued messages are dropped and their file descriptors closed
func (s *sender) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, m := range s.queue {
		closeAll(m.fds)
	}
	s.queue = nil
	s.cond.Broadcast()
}

// Writes until closed or a write fails
func (s *sender) run() error {
	for {
		s.mu.Lock()
		for !s.closed && len(s.queue) == 0 {
			s.cond.Wait()
		}
		if s.closed {
			s.mu.Unlock()
			return errClosed
		}
		m := s.queue[0]
		s.queue[0] = outMsg{}
		s.queue = s.queue[1:]
		s.mu.Unlock()

		err := s.write(m)
		closeAll(m.fds)

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
func (s *sender) write(m outMsg) error {
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
