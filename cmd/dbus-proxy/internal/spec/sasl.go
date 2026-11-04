package spec

import (
	"encoding/hex"
	"strconv"
	"strings"
)

// The server's side of SASL ("Authentication Protocol", its state diagram for the server), with the proxy's rules on
// top (docs/permissions.md, D-Bus, and xdg-dbus-proxy's): EXTERNAL only, for the socket's uid; the first byte nul;
// lines of printable ASCII starting with a capital, at most 16 KiB; at most 32 commands before BEGIN

const (
	SASLMaxLine     = 16 << 10
	SASLMaxCommands = 32
)

// SASLOutcome is what the server makes of what a client sent: its replies in order, and whether it then ended the
// connection, finished at BEGIN (with file descriptors agreed or not), or waits for more
type SASLOutcome struct {
	Replies []string
	Closed  bool
	Begun   bool
	FDs     bool
}

// SASLServer runs the server over everything a client sent at once, for a client of uid; the bus agrees to pass file
// descriptors
func SASLServer(sent []byte, uid int) SASLOutcome {
	var out SASLOutcome
	if len(sent) == 0 {
		return out
	}
	if sent[0] != 0 {
		out.Closed = true
		return out
	}
	rest := string(sent[1:])
	const (
		waitAuth = iota
		waitData
		waitBegin
	)
	state, fds := waitAuth, false
	ok := func(id string) bool {
		if id == "" {
			return true
		}
		b, err := hex.DecodeString(id)
		return err == nil && string(b) == strconv.Itoa(uid)
	}
	for n := 0; ; n++ {
		i := strings.Index(rest, "\r\n")
		if i < 0 {
			out.Closed = len(rest) >= SASLMaxLine
			return out
		}
		line := rest[:i]
		rest = rest[i+2:]
		if n >= SASLMaxCommands || i > SASLMaxLine || !printable(line) {
			out.Closed = true
			return out
		}
		cmd, arg, _ := strings.Cut(line, " ")
		reply := "ERROR"
		switch {
		case cmd == "BEGIN" && state == waitBegin:
			out.Begun, out.FDs = true, fds
			return out
		case cmd == "BEGIN":
			out.Closed = true
			return out
		case cmd == "ERROR", cmd == "CANCEL" && state != waitAuth:
			state, fds, reply = waitAuth, false, "REJECTED EXTERNAL"
		case cmd == "AUTH" && state == waitAuth:
			mech, initial, has := strings.Cut(arg, " ")
			switch {
			case mech != "EXTERNAL":
				reply = "REJECTED EXTERNAL"
			case !has:
				state, reply = waitData, "DATA"
			case ok(initial):
				state, reply = waitBegin, "OK"
			default:
				reply = "REJECTED EXTERNAL"
			}
		case cmd == "DATA" && state == waitData:
			if ok(arg) {
				state, reply = waitBegin, "OK"
			} else {
				state, reply = waitAuth, "REJECTED EXTERNAL"
			}
		case cmd == "NEGOTIATE_UNIX_FD" && state == waitBegin:
			fds, reply = true, "AGREE_UNIX_FD"
		}
		out.Replies = append(out.Replies, reply)
	}
}

// Printable ASCII starting with a capital letter
func printable(line string) bool {
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
