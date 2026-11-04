package sasl

import (
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
	"golang.org/x/sys/unix"
)

func hexUID(uid int) string { return hex.EncodeToString([]byte(strconv.Itoa(uid))) }

// A client's end of a connection Serve answers on, for the test's uid, closed when Serve returns as the proxy does;
// then what Serve returned, as whether file descriptors are passed or the error
func dial(t *testing.T) (*net.UnixConn, <-chan any) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	conns := make([]*net.UnixConn, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "sasl")
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = c.(*net.UnixConn)
		conns[i].SetDeadline(time.Now().Add(3 * time.Second))
	}
	t.Cleanup(func() { conns[0].Close() })
	done := make(chan any, 1)
	go func() {
		r := wire.NewReader(conns[1], nil)
		fds, err := Serve(conns[1], r, os.Getuid(), strings.Repeat("0", 32), func() (bool, error) { return true, nil })
		r.Close()
		conns[1].Close()
		if err != nil {
			done <- err
		} else {
			done <- fds
		}
	}()
	return conns[0], done
}

// EXTERNAL for the socket's uid, with and without the initial response, and file descriptors as negotiated
func TestSASLAccepted(t *testing.T) {
	for send, want := range map[string]bool{
		"\x00AUTH EXTERNAL " + hexUID(os.Getuid()) + "\r\nBEGIN\r\n":                                                              false,
		"\x00AUTH EXTERNAL\r\nDATA\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n":                                                             true,
		"\x00AUTH EXTERNAL " + hexUID(os.Getuid()) + "\r\nNEGOTIATE_UNIX_FD\r\nCANCEL\r\n" + "AUTH EXTERNAL\r\nDATA\r\nBEGIN\r\n": false,
	} {
		conn, done := dial(t)
		conn.Write([]byte(send))
		if got := <-done; got != want {
			t.Errorf("%q: got %v, want %v", send, got, want)
		}
	}
}

// Another uid, a mechanism other than EXTERNAL and junk are refused
func TestSASLRefused(t *testing.T) {
	for _, tc := range []struct{ send, want string }{
		{"\x00AUTH EXTERNAL " + hexUID(os.Getuid()+1) + "\r\n", "REJECTED EXTERNAL"},
		{"\x00AUTH EXTERNAL\r\nDATA " + hexUID(os.Getuid()+1) + "\r\n", "DATA"},
		{"\x00AUTH ANONYMOUS\r\n", "REJECTED EXTERNAL"},
		{"\x00NEGOTIATE_UNIX_FD\r\n", "ERROR"},
	} {
		conn, _ := dial(t)
		conn.Write([]byte(tc.send))
		r := wire.NewReader(conn, nil)
		line, err := r.ReadLine()
		if err != nil || line != tc.want {
			t.Errorf("%q: got %q (%v), want %q", tc.send, line, err, tc.want)
		}
		if tc.want == "DATA" {
			if line, _ := r.ReadLine(); line != "REJECTED EXTERNAL" {
				t.Errorf("DATA with another uid: got %q", line)
			}
		}
	}
	// BEGIN before OK, and a line with control characters, end the connection
	for _, send := range []string{"\x00BEGIN\r\n", "\x00AUTH EXTERNAL\x01\r\n", "x"} {
		conn, _ := dial(t)
		conn.Write([]byte(send))
		if _, err := wire.NewReader(conn, nil).ReadLine(); err == nil {
			t.Errorf("%q: connection still open", send)
		}
	}
}

// SASL: at most MaxCommands commands, lines at most wire.MaxAuthLine long
func TestSASLLimits(t *testing.T) {
	conn, _ := dial(t)
	conn.Write([]byte("\x00" + strings.Repeat("ERROR\r\n", MaxCommands+8)))
	r := wire.NewReader(conn, nil)
	n := 0
	var err error
	for err == nil {
		_, err = r.ReadLine()
		if err == nil {
			n++
		}
	}
	if n > MaxCommands || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("%d SASL replies, connection ended: %v", n, err)
	}

	conn, _ = dial(t)
	conn.Write([]byte("\x00AUTH " + strings.Repeat("A", wire.MaxAuthLine)))
	if _, err := wire.NewReader(conn, nil).ReadLine(); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("A SASL line past the limit: %v", err)
	}
}
