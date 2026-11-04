// Package wire reads and writes the proxy's D-Bus messages: each read bounded, its header fields parsed and checked,
// its body decoded only where the proxy looks into it; the write queue of each side; and the budget of bytes and file
// descriptors the clients share
package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/godbus/dbus/v5"
)

const (
	// The longest message either side may send. The sandbox's traffic is small: portal calls, notifications and the
	// tray, whose largest payloads are icons (a 512x512 ARGB pixmap is 1 MiB). 4 MiB leaves room for a 1024x1024
	// one, an eighth of dbus-daemon's own default of 32 MiB, and keeps what a client can make the proxy hold small
	MaxMessageSize = 4 << 20
	// The most file descriptors one sendmsg carries (the kernel's SCM_MAX_FD), so the most a message can pass on
	MaxMessageFDs = 253
	// File descriptors received ahead of the message that claims them
	MaxPendingFDs = 4 * MaxMessageFDs
	// The longest SASL line (dbus-daemon's and xdg-dbus-proxy's limit)
	MaxAuthLine = 16 << 10
)

// One D-Bus message as read: the parsed header, the byte order, its bytes as they came (the body is raw's tail) and
// the file descriptors it carries, which the holder closes or passes on. The body is decoded only where the proxy
// looks into it (DecodeBody)
type Message struct {
	*dbus.Message
	serial  uint32
	order   binary.ByteOrder
	raw     []byte
	body    []byte
	decoded bool
	fds     []int
	acct    *Account
}

// Serial shadows godbus's, which a message parsed here doesn't set
func (m *Message) Serial() uint32 { return m.serial }

// FDs are the file descriptors the message carries
func (m *Message) FDs() []int { return m.fds }

// TakeFDs hands the file descriptors over to the caller
func (m *Message) TakeFDs() []int {
	fds := m.fds
	m.fds = nil
	return fds
}

// CloseFDs closes the file descriptors the message still holds
func (m *Message) CloseFDs() {
	m.acct.closeFDs(m.fds)
	m.fds = nil
}

// Release gives back what the message's bytes took from the budget, once it's handled
func (m *Message) Release() {
	if m.raw != nil {
		m.acct.give(len(m.raw), 0)
		m.raw, m.body = nil, nil
	}
}

// Header is a string or object path header field, "" when it's missing
func (m *Message) Header(f dbus.HeaderField) string {
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

func (m *Message) ReplySerial() (uint32, bool) {
	v, ok := m.Headers[dbus.FieldReplySerial]
	if !ok {
		return 0, false
	}
	s, ok := v.Value().(uint32)
	return s, ok
}

// DecodeBody decodes the body into Body, for a body no larger than limit, so a client can't make the proxy spend more
// on decoding than what it looks for takes, and only one that holds valid values of its signature (canonical).
// Whether Body holds it
func (m *Message) DecodeBody(limit int) bool {
	if m.decoded {
		return m.Body != nil
	}
	m.decoded = true
	if len(m.body) > limit || len(m.raw) == 0 {
		return false
	}
	msg, err := decode(m.raw)
	if err != nil {
		return false
	}
	sig, _ := m.Headers[dbus.FieldSignature].Value().(dbus.Signature)
	if !canonical(m.order, sig, msg.Body, m.body) {
		return false
	}
	m.Body = msg.Body
	return m.Body != nil
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

// Encode encodes the message as forwarded: the header fields parsed and checked here, re-encoded by godbus in the
// original byte order, then the body as it came, so the bus routes by exactly the fields the proxy checked
func (m *Message) Encode() ([]byte, error) {
	hdr := &dbus.Message{Type: m.Type, Flags: m.Flags, Headers: m.Headers}
	return encodeWith(hdr, m.order, m.serial, m.body)
}

// Encode encodes a message of the proxy's own, little-endian, with the given serial
func Encode(m *dbus.Message, serial uint32) ([]byte, error) {
	return encodeWith(m, binary.LittleEndian, serial, nil)
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
	if len(out) > MaxMessageSize {
		return nil, fmt.Errorf("Message too long: %d bytes", len(out))
	}
	return out, nil
}
