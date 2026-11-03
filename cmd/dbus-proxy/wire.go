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
	// The D-Bus specification's maximum, which dbus-daemon's session bus allows
	maxMessageSize = 1 << 27
	// The most file descriptors one sendmsg carries (the kernel's SCM_MAX_FD), so the most a message can pass on
	maxMessageFDs = 253
	// File descriptors received ahead of the message that claims them
	maxPendingFDs = 4 * maxMessageFDs
	// What one read takes in, and the longest SASL line (dbus-daemon's and xdg-dbus-proxy's limit)
	readChunk   = 64 << 10
	maxAuthLine = 16 << 10
)

// One D-Bus message as read: the decoded header (and body), the byte order, the body's bytes as they came and the
// file descriptors it carries, which the holder closes or passes on
type message struct {
	*dbus.Message
	order binary.ByteOrder
	body  []byte
	fds   []int
}

func (m *message) closeFDs() {
	for _, fd := range m.fds {
		unix.Close(fd)
	}
	m.fds = nil
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

// The first argument when it's a string
func (m *message) arg0() (string, bool) {
	if len(m.Body) == 0 {
		return "", false
	}
	s, ok := m.Body[0].(string)
	return s, ok
}

// Reads a connection's bytes and the file descriptors that come with them, bounded throughout
type reader struct {
	conn *net.UnixConn
	data []byte // Read and not consumed yet
	fds  []int  // Received and not claimed by a message yet
	oob  []byte
}

func newReader(conn *net.UnixConn) *reader {
	return &reader{conn: conn, oob: make([]byte, unix.CmsgSpace(maxMessageFDs*4))}
}

// Reads until n bytes are buffered
func (r *reader) fill(n int) error {
	for len(r.data) < n {
		if cap(r.data)-len(r.data) < readChunk {
			grown := make([]byte, len(r.data), len(r.data)+max(readChunk, len(r.data)))
			copy(grown, r.data)
			r.data = grown
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
		r.fds = append(r.fds, fds...)
	}
	if len(r.fds) > maxPendingFDs {
		return fmt.Errorf("Too many file descriptors pending: %d", len(r.fds))
	}
	return nil
}

func (r *reader) consume(n int) []byte {
	out := make([]byte, n)
	copy(out, r.data[:n])
	r.data = r.data[n:]
	if len(r.data) == 0 {
		r.data = nil
	}
	return out
}

// Closes the file descriptors no message claimed
func (r *reader) close() {
	for _, fd := range r.fds {
		unix.Close(fd)
	}
	r.fds = nil
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
	raw := r.consume(int(bodyStart + bodyLen))
	msg, err := decode(raw)
	if err != nil {
		return nil, fmt.Errorf("Decode message: %w", err)
	}
	if msg.Serial() == 0 {
		return nil, errors.New("Message without a serial")
	}
	m := &message{Message: msg, order: order, body: raw[bodyStart:]}
	var nfds uint32
	if v, ok := msg.Headers[dbus.FieldUnixFDs]; ok {
		nfds, _ = v.Value().(uint32)
	}
	if nfds > maxMessageFDs {
		return nil, fmt.Errorf("Message claims %d file descriptors", nfds)
	}
	if int(nfds) > len(r.fds) {
		return nil, fmt.Errorf("Message claims %d file descriptors, %d arrived", nfds, len(r.fds))
	}
	m.fds = append([]int(nil), r.fds[:nfds]...)
	r.fds = r.fds[nfds:]
	return m, nil
}

// godbus's decoder, which recovers its own panics; this guards against any it doesn't
func decode(raw []byte) (msg *dbus.Message, err error) {
	defer func() {
		if p := recover(); p != nil {
			msg, err = nil, fmt.Errorf("Decoder panic: %v", p)
		}
	}()
	return dbus.DecodeMessageWithFDs(bytes.NewReader(raw), nil)
}

// Encodes a message as forwarded: the header fields godbus decoded, in the original byte order, then the body as it
// came, so the bus routes by exactly the fields the proxy checked
func (m *message) encode() ([]byte, error) {
	hdr := &dbus.Message{Type: m.Type, Flags: m.Flags, Headers: m.Headers}
	return encodeWith(hdr, m.order, m.Serial(), m.body)
}

// Encodes msg with the given serial; a non-nil body replaces msg's (empty) one
func encodeWith(msg *dbus.Message, order binary.ByteOrder, serial uint32, body []byte) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := msg.EncodeToWithFDs(&buf, order); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	order.PutUint32(out[8:12], serial)
	if body != nil {
		if len(msg.Body) != 0 {
			return nil, errors.New("Message has a body already")
		}
		order.PutUint32(out[4:8], uint32(len(body)))
		out = append(out, body...)
	}
	if len(out) > maxMessageSize {
		return nil, fmt.Errorf("Message too long: %d bytes", len(out))
	}
	return out, nil
}
