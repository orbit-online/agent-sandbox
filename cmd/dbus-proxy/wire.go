package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	// The longest message either side may send. The sandbox's traffic is small: portal calls, notifications and the
	// tray, whose largest payloads are icons (a 512x512 ARGB pixmap is 1 MiB). 4 MiB leaves room for a 1024x1024
	// one, an eighth of dbus-daemon's own default of 32 MiB, and keeps what a client can make the proxy hold small
	maxMessageSize = 4 << 20
	// The most file descriptors one sendmsg carries (the kernel's SCM_MAX_FD), so the most a message can pass on
	maxMessageFDs = 253
	// File descriptors received ahead of the message that claims them
	maxPendingFDs = 4 * maxMessageFDs
	// What one read takes in, and the longest SASL line (dbus-daemon's and xdg-dbus-proxy's limit)
	readChunk   = 64 << 10
	maxAuthLine = 16 << 10
	// The largest body of a bus driver call the proxy looks into: names are at most 255 bytes, match rules 1024
	maxInspectBody = 4 << 10
)

// One D-Bus message as read: the parsed header, the byte order, its bytes as they came (the body is raw's tail) and
// the file descriptors it carries, which the holder closes or passes on. The body is decoded only where the proxy
// looks into it
type message struct {
	*dbus.Message
	serial  uint32
	order   binary.ByteOrder
	raw     []byte
	body    []byte
	decoded bool
	fds     []int
	acct    *account
}

// Shadows godbus's, which a message parsed here doesn't set
func (m *message) Serial() uint32 { return m.serial }

func (m *message) closeFDs() {
	m.acct.closeFDs(m.fds)
	m.fds = nil
}

// Gives back what the message's bytes took from the budget, once it's handled
func (m *message) release() {
	if m.raw != nil {
		m.acct.give(len(m.raw), 0)
		m.raw, m.body = nil, nil
	}
}

func (m *message) header(f dbus.HeaderField) string {
	v, ok := m.Headers[f]
	if !ok {
		return ""
	}
	switch s := v.Value().(type) {
	case string:
		return s
	case dbus.ObjectPath:
		return string(s)
	}
	return ""
}

func (m *message) replySerial() (uint32, bool) {
	v, ok := m.Headers[dbus.FieldReplySerial]
	if !ok {
		return 0, false
	}
	s, ok := v.Value().(uint32)
	return s, ok
}

// The first argument when it's a string, for a body no larger than maxInspectBody
func (m *message) arg0() (string, bool) {
	if !m.decodeBody(maxInspectBody) || len(m.Body) == 0 {
		return "", false
	}
	s, ok := m.Body[0].(string)
	return s, ok
}

// Reads a connection's bytes and the file descriptors that come with them, bounded throughout
type reader struct {
	acct *account
	conn *net.UnixConn
	data []byte // Read and not consumed yet
	fds  []int  // Received and not claimed by a message yet
	oob  []byte
	held int // The buffer's capacity, taken from the account
}

func newReader(conn *net.UnixConn, acct *account) *reader {
	return &reader{conn: conn, acct: acct, oob: make([]byte, unix.CmsgSpace(maxMessageFDs*4))}
}

// Swaps the buffer for one of the given capacity, holding what's unread, and accounts for the difference
func (r *reader) resize(capacity int) error {
	if capacity > r.held {
		if err := r.acct.take(capacity-r.held, 0); err != nil {
			return err
		}
	} else {
		r.acct.give(r.held-capacity, 0)
	}
	r.held = capacity
	if capacity == 0 {
		r.data = nil
		return nil
	}
	grown := make([]byte, len(r.data), capacity)
	copy(grown, r.data)
	r.data = grown
	return nil
}

// Reads until n bytes are buffered
func (r *reader) fill(n int) error {
	for len(r.data) < n {
		if cap(r.data)-len(r.data) < readChunk {
			// Grow toward what's needed, a chunk at least, never past the largest message
			want := max(len(r.data)+readChunk, min(2*len(r.data), n), n)
			want = min(want, maxMessageSize+readChunk)
			if want <= len(r.data) {
				return errors.New("Read buffer full")
			}
			if err := r.resize(want); err != nil {
				return err
			}
		}
		k, oobn, flags, _, err := r.conn.ReadMsgUnix(r.data[len(r.data):cap(r.data)], r.oob)
		k, oobn = max(k, 0), max(oobn, 0)
		if oobn > 0 {
			if ferr := r.takeFDs(r.oob[:oobn]); ferr != nil {
				return ferr
			}
		}
		if flags&unix.MSG_CTRUNC != 0 {
			return errors.New("Control message truncated: too many file descriptors at once")
		}
		r.data = r.data[:len(r.data)+k]
		if err != nil {
			return err
		}
		if k == 0 {
			return errors.New("Connection closed")
		}
	}
	return nil
}

func (r *reader) takeFDs(oob []byte) error {
	scms, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return fmt.Errorf("Parse control message: %w", err)
	}
	for _, scm := range scms {
		if scm.Header.Level != unix.SOL_SOCKET || scm.Header.Type != unix.SCM_RIGHTS {
			continue
		}
		fds, err := syscall.ParseUnixRights(&scm)
		if err != nil {
			return fmt.Errorf("Parse file descriptors: %w", err)
		}
		if err := r.acct.take(0, len(fds)); err != nil {
			closeAll(fds)
			return err
		}
		r.fds = append(r.fds, fds...)
	}
	if len(r.fds) > maxPendingFDs {
		return fmt.Errorf("Too many file descriptors pending: %d", len(r.fds))
	}
	return nil
}

// Takes n bytes out of the buffer; an emptied buffer is dropped and given back
func (r *reader) consume(n int) []byte {
	out := make([]byte, n)
	copy(out, r.data[:n])
	r.data = r.data[n:]
	if len(r.data) == 0 {
		r.resize(0)
	}
	return out
}

// Closes the file descriptors no message claimed and gives back the buffer
func (r *reader) close() {
	r.acct.closeFDs(r.fds)
	r.fds = nil
	r.resize(0)
}

// A SASL line without its CRLF, at most maxAuthLine long
func (r *reader) readLine() (string, error) {
	for {
		if i := bytes.Index(r.data, []byte("\r\n")); i >= 0 {
			return string(r.consume(i + 2)[:i]), nil
		}
		if len(r.data) >= maxAuthLine {
			return "", errors.New("SASL line too long")
		}
		if err := r.fill(len(r.data) + 1); err != nil {
			return "", err
		}
	}
}

func align8(n uint64) uint64 { return (n + 7) &^ 7 }

// Reads one message. Its length is checked before it's read, the decoded header fields are what the message is
// forwarded with, and the file descriptors it claims must have arrived
func (r *reader) readMessage() (*message, error) {
	if err := r.fill(16); err != nil {
		return nil, err
	}
	var order binary.ByteOrder
	switch r.data[0] {
	case 'l':
		order = binary.LittleEndian
	case 'B':
		order = binary.BigEndian
	default:
		return nil, errors.New("Invalid byte order")
	}
	if r.data[3] != 1 {
		return nil, fmt.Errorf("Unsupported protocol version %d", r.data[3])
	}
	bodyLen := uint64(order.Uint32(r.data[4:8]))
	bodyStart := align8(16 + uint64(order.Uint32(r.data[12:16])))
	if bodyStart+bodyLen > maxMessageSize {
		return nil, fmt.Errorf("Message too long: %d bytes", bodyStart+bodyLen)
	}
	if err := r.fill(int(bodyStart + bodyLen)); err != nil {
		return nil, err
	}
	total := int(bodyStart + bodyLen)
	if err := r.acct.take(total, 0); err != nil {
		return nil, err
	}
	raw := r.consume(total)
	m := &message{Message: &dbus.Message{Type: dbus.Type(raw[1]), Flags: dbus.Flags(raw[2])}, order: order,
		serial: order.Uint32(raw[8:12]), raw: raw, body: raw[bodyStart:], acct: r.acct}
	if err := r.parse(m, 16+int(order.Uint32(raw[12:16]))); err != nil {
		m.release()
		return nil, err
	}
	return m, nil
}

// The checks on a message's header, and the file descriptors it claims
func (r *reader) parse(m *message, headerEnd int) error {
	headers, err := parseHeader(m.raw, m.order, headerEnd)
	if err != nil {
		return fmt.Errorf("Parse header: %w", err)
	}
	m.Headers = headers
	// godbus checks the type, flags, required fields and names
	if err := (&dbus.Message{Type: m.Type, Flags: m.Flags, Headers: headers}).IsValid(); err != nil {
		return fmt.Errorf("Invalid message: %w", err)
	}
	if m.serial == 0 {
		return errors.New("Message without a serial")
	}
	var nfds uint32
	if v, ok := headers[dbus.FieldUnixFDs]; ok {
		nfds, _ = v.Value().(uint32)
	}
	if nfds > maxMessageFDs {
		return fmt.Errorf("Message claims %d file descriptors", nfds)
	}
	if int(nfds) > len(r.fds) {
		return fmt.Errorf("Message claims %d file descriptors, %d arrived", nfds, len(r.fds))
	}
	m.fds = append([]int(nil), r.fds[:nfds]...)
	r.fds = r.fds[nfds:]
	return nil
}
