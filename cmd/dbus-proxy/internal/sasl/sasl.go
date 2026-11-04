// Package sasl is the proxy's SASL: EXTERNAL toward the bus as the proxy's uid, and the server's half toward a client,
// EXTERNAL for the uid of the client's socket
package sasl

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
)

// Commands a client may send before BEGIN; real clients need a handful
const MaxCommands = 32

// Client authenticates to the bus with EXTERNAL as uid, the proxy's own, and returns the bus's GUID. The proxy's first
// byte goes without credentials: dbus-daemon takes them from SO_PEERCRED
func Client(conn io.Writer, r *wire.Reader, uid int) (string, error) {
	hexUID := hex.EncodeToString([]byte(strconv.Itoa(uid)))
	if _, err := conn.Write([]byte("\x00AUTH EXTERNAL " + hexUID + "\r\n")); err != nil {
		return "", err
	}
	line, err := r.ReadLine()
	if err != nil {
		return "", err
	}
	guid, ok := strings.CutPrefix(line, "OK ")
	if !ok || len(guid) != 32 {
		return "", fmt.Errorf("Bus refused EXTERNAL: %q", line)
	}
	if _, err := hex.DecodeString(guid); err != nil {
		return "", fmt.Errorf("Bus sent an invalid GUID: %q", guid)
	}
	return guid, nil
}

// NegotiateFDs asks the bus to pass file descriptors, once Client succeeded
func NegotiateFDs(conn io.Writer, r *wire.Reader) (bool, error) {
	if _, err := conn.Write([]byte("NEGOTIATE_UNIX_FD\r\n")); err != nil {
		return false, err
	}
	line, err := r.ReadLine()
	if err != nil {
		return false, err
	}
	return line == "AGREE_UNIX_FD", nil
}

// Serve is the server's half of SASL toward a client, after the D-Bus specification's state machine, up to BEGIN.
// EXTERNAL only, for peerUID, the uid the client's socket belongs to: what dbus-daemon would accept from the client
// through xdg-dbus-proxy, which passes the client's SASL on and the proxy's credentials with it. guid is the bus's;
// negotiate asks the bus for file descriptor passing when the client asks for it. Returns whether they're passed
func Serve(conn io.Writer, r *wire.Reader, peerUID int, guid string, negotiate func() (bool, error)) (bool, error) {
	return (&server{conn, r, peerUID, guid, negotiate}).run()
}

type server struct {
	conn      io.Writer
	r         *wire.Reader
	peerUID   int
	guid      string
	negotiate func() (bool, error)
}

func (s *server) reply(line string) error {
	_, err := s.conn.Write([]byte(line + "\r\n"))
	return err
}

// The authorization identity EXTERNAL carries, hex-encoded ASCII decimal; empty means the socket's
func (s *server) externalOK(hexID string) bool {
	if hexID == "" {
		return true
	}
	id, err := hex.DecodeString(hexID)
	if err != nil {
		return false
	}
	uid, err := strconv.Atoi(string(id))
	return err == nil && strconv.Itoa(uid) == string(id) && uid == s.peerUID
}

func (s *server) run() (bool, error) {
	if b, err := s.r.ReadByte(); err != nil {
		return false, err
	} else if b != 0 {
		return false, errors.New("Client's first byte is not nul")
	}
	const (
		waitAuth = iota
		waitData
		waitBegin
	)
	state := waitAuth
	unixFDs := false
	for i := 0; ; i++ {
		if i >= MaxCommands {
			return false, errors.New("Too many SASL commands")
		}
		line, err := s.r.ReadLine()
		if err != nil {
			return false, err
		}
		if !validAuthLine(line) {
			return false, fmt.Errorf("Invalid SASL line %q", line)
		}
		cmd, arg, _ := strings.Cut(line, " ")
		var out string
		switch {
		case cmd == "BEGIN" && state == waitBegin:
			return unixFDs, nil
		case cmd == "BEGIN":
			return false, errors.New("BEGIN before authentication")
		case cmd == "ERROR" || cmd == "CANCEL":
			if state == waitBegin || state == waitData || cmd == "ERROR" {
				state, unixFDs, out = waitAuth, false, "REJECTED EXTERNAL"
			} else {
				out = "ERROR"
			}
		case cmd == "AUTH" && state == waitAuth:
			mech, initial, hasInitial := strings.Cut(arg, " ")
			switch {
			case mech != "EXTERNAL":
				out = "REJECTED EXTERNAL"
			case !hasInitial:
				state, out = waitData, "DATA"
			case s.externalOK(initial):
				state, out = waitBegin, "OK "+s.guid
			default:
				out = "REJECTED EXTERNAL"
			}
		case cmd == "DATA" && state == waitData:
			if s.externalOK(arg) {
				state, out = waitBegin, "OK "+s.guid
			} else {
				state, out = waitAuth, "REJECTED EXTERNAL"
			}
		case cmd == "NEGOTIATE_UNIX_FD" && state == waitBegin:
			ok, err := s.negotiate()
			if err != nil {
				return false, err
			}
			unixFDs = ok
			out = "AGREE_UNIX_FD"
			if !ok {
				out = "ERROR"
			}
		default:
			out = "ERROR"
		}
		if err := s.reply(out); err != nil {
			return false, err
		}
	}
}

// Printable ASCII starting with a capital letter, as xdg-dbus-proxy requires: real SASL hex-encodes anything else
func validAuthLine(line string) bool {
	if line == "" || line[0] < 'A' || line[0] > 'Z' {
		return false
	}
	for i := 0; i < len(line); i++ {
		if line[i] < ' ' || line[i] > '~' {
			return false
		}
	}
	return true
}
