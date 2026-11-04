package wire

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

// What one read takes in
const readChunk = 64 << 10

// Reads a connection's bytes and the file descriptors that come with them, bounded throughout
type Reader struct {
	acct *Account
	conn *net.UnixConn
	data []byte // Read and not consumed yet
	fds  []int  // Received and not claimed by a Message yet
	oob  []byte
	held int // The buffer's capacity, taken from the Account
}

func NewReader(conn *net.UnixConn, acct *Account) *Reader {
	return &Reader{conn: conn, acct: acct, oob: make([]byte, unix.CmsgSpace(MaxMessageFDs*4))}
}

// Swaps the buffer for one of the given capacity, holding what's unread, and accounts for the difference
func (r *Reader) resize(capacity int) error {
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
func (r *Reader) fill(n int) error {
	for len(r.data) < n {
		if cap(r.data)-len(r.data) < readChunk {
			// Grow toward what's needed, a chunk at least, never past the largest Message
			want := max(len(r.data)+readChunk, min(2*len(r.data), n), n)
			want = min(want, MaxMessageSize+readChunk)
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
			return errors.New("Control Message truncated: too many file descriptors at once")
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

func (r *Reader) takeFDs(oob []byte) error {
	scms, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return fmt.Errorf("Parse control Message: %w", err)
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
	if len(r.fds) > MaxPendingFDs {
		return fmt.Errorf("Too many file descriptors pending: %d", len(r.fds))
	}
	return nil
}

// Takes n bytes out of the buffer; an emptied buffer is dropped and given back
func (r *Reader) consume(n int) []byte {
	out := make([]byte, n)
	copy(out, r.data[:n])
	r.data = r.data[n:]
	if len(r.data) == 0 {
		r.resize(0)
	}
	return out
}

// Closes the file descriptors no Message claimed and gives back the buffer
func (r *Reader) Close() {
	r.acct.closeFDs(r.fds)
	r.fds = nil
	r.resize(0)
}

// ReadByte reads one byte, for SASL's leading nul
func (r *Reader) ReadByte() (byte, error) {
	if err := r.fill(1); err != nil {
		return 0, err
	}
	return r.consume(1)[0], nil
}

// PendingFDs counts the file descriptors received and claimed by no message yet
func (r *Reader) PendingFDs() int { return len(r.fds) }

// ReadLine reads a SASL line without its CRLF, at most MaxAuthLine long
func (r *Reader) ReadLine() (string, error) {
	for {
		if i := bytes.Index(r.data, []byte("\r\n")); i >= 0 {
			return string(r.consume(i + 2)[:i]), nil
		}
		if len(r.data) >= MaxAuthLine {
			return "", errors.New("SASL line too long")
		}
		if err := r.fill(len(r.data) + 1); err != nil {
			return "", err
		}
	}
}

func align8(n uint64) uint64 { return (n + 7) &^ 7 }

// The fixed part of a message's header: its byte order, and where its body starts and ends
func frame(fixed []byte) (binary.ByteOrder, int, int, error) {
	var order binary.ByteOrder
	switch fixed[0] {
	case 'l':
		order = binary.LittleEndian
	case 'B':
		order = binary.BigEndian
	default:
		return nil, 0, 0, errors.New("Invalid byte order")
	}
	if fixed[3] != 1 {
		return nil, 0, 0, fmt.Errorf("Unsupported protocol version %d", fixed[3])
	}
	bodyLen := uint64(order.Uint32(fixed[4:8]))
	bodyStart := align8(16 + uint64(order.Uint32(fixed[12:16])))
	if bodyStart+bodyLen > MaxMessageSize {
		return nil, 0, 0, fmt.Errorf("Message too long: %d bytes", bodyStart+bodyLen)
	}
	return order, int(bodyStart), int(bodyStart + bodyLen), nil
}

// ReadMessage reads one message. Its length is checked before it's read, the decoded header fields are what the
// message is forwarded with, and the file descriptors it claims must have arrived
func (r *Reader) ReadMessage() (*Message, error) {
	if err := r.fill(16); err != nil {
		return nil, err
	}
	order, bodyStart, total, err := frame(r.data[:16])
	if err != nil {
		return nil, err
	}
	if err := r.fill(total); err != nil {
		return nil, err
	}
	if err := r.acct.take(total, 0); err != nil {
		return nil, err
	}
	m, err := parse(r.consume(total), order, bodyStart, r.acct)
	if err != nil {
		return nil, err
	}
	nfds := m.unixFDs()
	if int(nfds) > len(r.fds) {
		m.Release()
		return nil, fmt.Errorf("Message claims %d file descriptors, %d arrived", nfds, len(r.fds))
	}
	m.fds = append([]int(nil), r.fds[:nfds]...)
	r.fds = r.fds[nfds:]
	return m, nil
}

// Parse parses one whole message that carries no file descriptors, as ReadMessage would read it, for tests
func Parse(raw []byte) (*Message, error) {
	if len(raw) < 16 {
		return nil, errors.New("Message shorter than its header")
	}
	order, bodyStart, total, err := frame(raw[:16])
	if err != nil {
		return nil, err
	}
	if total != len(raw) {
		return nil, fmt.Errorf("Message of %d bytes, %d given", total, len(raw))
	}
	m, err := parse(raw, order, bodyStart, nil)
	if err == nil && m.unixFDs() > 0 {
		return nil, errors.New("Message claims file descriptors")
	}
	return m, err
}

// The checks on a message's header; on an error, what raw took from acct is given back
func parse(raw []byte, order binary.ByteOrder, bodyStart int, acct *Account) (*Message, error) {
	m := &Message{Message: &dbus.Message{Type: dbus.Type(raw[1]), Flags: dbus.Flags(raw[2])}, order: order,
		serial: order.Uint32(raw[8:12]), raw: raw, body: raw[bodyStart:], acct: acct}
	end := 16 + int(order.Uint32(raw[12:16]))
	headers, err := parseHeader(raw, order, end)
	if err == nil && skipPadding(raw, end, bodyStart, bodyStart) < 0 {
		err = errPadding
	}
	if err == nil {
		m.Headers = headers
		// godbus checks the type, flags, required fields and names
		if err = (&dbus.Message{Type: m.Type, Flags: m.Flags, Headers: headers}).IsValid(); err != nil {
			err = fmt.Errorf("Invalid message: %w", err)
		} else if err = checkNames(headers); err != nil {
			err = fmt.Errorf("Invalid message: %w", err)
		}
	} else {
		err = fmt.Errorf("Parse header: %w", err)
	}
	if err == nil && m.serial == 0 {
		err = errors.New("Message without a serial")
	}
	if err == nil && m.unixFDs() > MaxMessageFDs {
		err = fmt.Errorf("Message claims %d file descriptors", m.unixFDs())
	}
	if err != nil {
		m.Release()
		return nil, err
	}
	return m, nil
}

// The file descriptors the message claims
func (m *Message) unixFDs() uint32 {
	n, _ := m.Headers[dbus.FieldUnixFDs].Value().(uint32)
	return n
}
