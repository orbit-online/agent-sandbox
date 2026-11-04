package sasl

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/gen"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/spec"
	"pgregory.net/rapid"
)

// Serve against the specification's server (spec.SASLServer) for generated input sent at once: the same replies, then
// the same end: the connection closed, authenticated with or without file descriptors, or waiting for more
func TestSASLAgainstSpec(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		sent := gen.SASL(os.Getuid()).Draw(rt, "sent")
		want := spec.SASLServer(sent, os.Getuid())
		conn, done := dial(t)
		// Serve may close the connection before it has all of it
		_, _ = conn.Write(sent)
		r := bufio.NewReader(conn)
		for i, w := range want.Replies {
			line, err := r.ReadString('\n')
			if err != nil {
				rt.Fatalf("Reply %d: %v, want %q", i, err, w)
			}
			line = strings.TrimSuffix(line, "\r\n")
			if w == "OK" && strings.HasPrefix(line, "OK ") {
				line = "OK"
			}
			if line != w {
				rt.Fatalf("Reply %d: %q, want %q", i, line, w)
			}
		}
		select {
		case res := <-done:
			fds, begun := res.(bool)
			switch {
			case want.Closed && begun, !want.Closed && !want.Begun:
				rt.Fatalf("Serve returned %v, want %+v", res, want)
			case want.Begun && (!begun || fds != want.FDs):
				rt.Fatalf("Serve returned %v, want file descriptors %v", res, want.FDs)
			}
		case <-time.After(waitFor(want)):
			if want.Closed || want.Begun {
				rt.Fatalf("Serve still runs, want %+v", want)
			}
		}
		conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		if extra, err := r.ReadString('\n'); err == nil && extra != "" && !want.Begun {
			rt.Fatalf("A reply past the model's: %q", extra)
		} else if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) && extra != "" {
			rt.Fatalf("Reading past the replies: %q %v", extra, err)
		}
	})
}

// How long to wait for Serve's end: a moment when it's due, a little longer to see it doesn't come
func waitFor(want spec.SASLOutcome) time.Duration {
	if want.Closed || want.Begun {
		return 2 * time.Second
	}
	return 50 * time.Millisecond
}
