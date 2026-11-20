package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/notify"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
)

// heldAsker holds each question until the test answers it by its summary, or the broker takes it down
type heldAsker struct {
	mu     sync.Mutex
	held   map[string]chan string
	asked  chan string
	causes chan error
}

func newHeldAsker() *heldAsker {
	return &heldAsker{held: map[string]chan string{}, asked: make(chan string, 16), causes: make(chan error, 16)}
}

func (h *heldAsker) ask(ctx context.Context, p notify.Prompt) (string, error) {
	ch := make(chan string, 1)
	h.mu.Lock()
	h.held[p.Summary] = ch
	h.mu.Unlock()
	h.asked <- p.Summary
	select {
	case a := <-ch:
		return a, nil
	case <-ctx.Done():
		h.causes <- context.Cause(ctx)
		return "", nil
	}
}

func (h *heldAsker) answer(t *testing.T, summary, action string) {
	t.Helper()
	h.mu.Lock()
	ch := h.held[summary]
	h.mu.Unlock()
	if ch == nil {
		t.Fatalf("Not asked about %s", summary)
	}
	ch <- action
}

// waitAsked waits for the question about summary, failing on a result that came instead
func (h *heldAsker) waitAsked(t *testing.T, summary string, results <-chan error) {
	t.Helper()
	select {
	case got := <-h.asked:
		if got != summary {
			t.Fatalf("Asked about %s, want %s", got, summary)
		}
	case err := <-results:
		t.Fatalf("Not asked about %s: %v (%s)", summary, err, refusalOf(err))
	case <-time.After(5 * time.Second):
		t.Fatalf("Not asked about %s", summary)
	}
}

func pathSummary(path string) string { return fmt.Sprintf("use the test thing %q", path) }

// Requests of one capability with other parameters are questions of their own, each answered by its own answer;
// the same parameters again wait for the first; and at most maxAsking are open per capability
func TestAskedPerParams(t *testing.T) {
	b, _ := testBroker(t)
	h := newHeldAsker()
	b.ask = h.ask
	c := testCap(t, "command")
	b.caps[c.id()] = c
	type result struct {
		g   *grant
		err error
	}
	ask := func(path string) (chan result, chan error) {
		res, errs := make(chan result, 1), make(chan error, 1)
		go func() {
			g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), fmt.Sprintf(`{"path": %q}`, path), "PT2H"))
			res <- result{g, err}
			errs <- err
		}()
		return res, errs
	}
	mimir, mimirErr := ask("mimir")
	h.waitAsked(t, pathSummary("mimir"), mimirErr)
	loki, lokiErr := ask("loki")
	h.waitAsked(t, pathSummary("loki"), lokiErr)
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "mimir"}`, "PT2H")); refusalOf(err) != refAsking {
		t.Errorf("The same parameters again while asked: %v, want refused as %s", err, refAsking)
	}

	h.answer(t, pathSummary("loki"), "allow")
	if r := <-loki; r.err != nil || string(r.g.Params) != `{"path":"loki"}` {
		t.Errorf("loki allowed: %+v, %v", r.g, r.err)
	}
	h.answer(t, pathSummary("mimir"), "deny")
	if r := <-mimir; refusalOf(r.err) != refDenied {
		t.Errorf("mimir denied: %+v, %v", r.g, r.err)
	}

	var errs []chan error
	for i := range maxAsking {
		path := fmt.Sprint("p", i)
		_, e := ask(path)
		h.waitAsked(t, pathSummary(path), e)
		errs = append(errs, e)
	}
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "over"}`, "PT2H")); refusalOf(err) != refAsking {
		t.Errorf("Request past %d open ones: %v, want refused as %s", maxAsking, err, refAsking)
	}
	for i := range maxAsking {
		h.answer(t, pathSummary(fmt.Sprint("p", i)), "allow")
		if err := <-errs[i]; err != nil {
			t.Error(err)
		}
	}
}

// A caller that hangs up while the user is asked takes its question with it: the notification comes down, the
// request leaves the window, and the same request asks again at once. It counts as no refusal
func TestCallerHangUp(t *testing.T) {
	b, _ := testBroker(t)
	h := newHeldAsker()
	b.ask = h.ask
	c := testCap(t, "command")
	b.caps[c.id()] = c
	if err := os.MkdirAll(b.cfg.GrantDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(b.cfg.GrantDir, "request.sock")
	ln, err := listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go b.serveOn(ln, b.handleRequest)

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(conn).Encode(req(c.id(), `{"path": "mimir"}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	h.waitAsked(t, pathSummary("mimir"), nil)
	conn.Close()
	select {
	case cause := <-h.causes:
		if !errors.Is(cause, notify.ErrGone) {
			t.Errorf("Notification taken down with %v, want %v", cause, notify.ErrGone)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("The notification stayed up after the caller hung up")
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		b.mu.Lock()
		n := len(b.pending)
		b.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("The request stayed pending after the caller hung up")
		}
	}
	b.mu.Lock()
	refused := b.gates[c.id()].refused
	b.mu.Unlock()
	if refused != 0 {
		t.Errorf("A hang-up counted as %d refusals", refused)
	}
	errs := make(chan error, 1)
	go func() {
		_, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "mimir"}`, "PT1H"))
		errs <- err
	}()
	h.waitAsked(t, pathSummary("mimir"), errs)
	h.answer(t, pathSummary("mimir"), "allow")
	if err := <-errs; err != nil {
		t.Error(err)
	}
}

// No answer in time and a notification closed unanswered are refused as unanswered, not as the user's no; a deny on
// the notification's body is a no
func TestUnanswered(t *testing.T) {
	b, f := testBroker(t, "", "body", "foreign", "deny")
	c := testCap(t, "command")
	b.caps[c.id()] = c
	for _, want := range []refusal{refUnanswered, refDenied, refDenied, refDenied} {
		if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H")); refusalOf(err) != want {
			t.Errorf("Answer %d: %v (%s), want refused as %s", f.count(), err, refusalOf(err), want)
		}
		b.mu.Lock()
		b.gates[c.id()].refused = 0
		b.mu.Unlock()
	}

	clk := newFakeClock()
	b.clock = clk
	h := newHeldAsker()
	b.ask = h.ask
	errs := make(chan error, 1)
	go func() {
		_, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H"))
		errs <- err
	}()
	h.waitAsked(t, "use the test thing", errs)
	for clk.asked(wire.AskTimeout) == 0 {
		time.Sleep(time.Millisecond)
	}
	clk.advance(wire.AskTimeout)
	if err := <-errs; refusalOf(err) != refUnanswered {
		t.Errorf("Timed out: %v (%s), want refused as %s", err, refusalOf(err), refUnanswered)
	}
}

// syncBuffer is a log the broker's goroutines write to
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// The journal tells a morning's questions and answers apart: each request asked with its id, capability and summary,
// each answer by that id with how it came, each timeout, each refusal with its category. An opaque value shows only by
// digest, and the reason not at all
func TestAskLog(t *testing.T) {
	var log syncBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&log, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	b, _ := testBroker(t)
	h := newHeldAsker()
	b.ask = h.ask
	clk := newFakeClock()
	b.clock = clk
	c := testCap(t, "command")
	c.Params["token"] = json.RawMessage(`{"type": "string", "opaque": true, "description": "a token"}`)
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	b.caps[c.id()] = c
	ask := func(params string) chan error {
		errs := make(chan error, 1)
		go func() {
			r := req(c.id(), params, "PT2H")
			r.Reason = "the reason stays out"
			_, err := b.request(peerAt(t, os.Getpid()), r)
			errs <- err
		}()
		return errs
	}
	pendingID := func() string {
		b.mu.Lock()
		defer b.mu.Unlock()
		for id := range b.pending {
			return id
		}
		return ""
	}

	allowed := ask(`{"path": "loki", "token": "s3cret-value"}`)
	summary := <-h.asked
	id := pendingID()
	if res := b.handleRequest(nil, peerAt(t, os.Getpid()), req(c.id(), `{"path": "loki", "token": "s3cret-value"}`, "PT2H")); res.Refused != refAsking {
		t.Fatalf("Asked twice: %+v", res)
	}
	h.answer(t, summary, "allow")
	if err := <-allowed; err != nil {
		t.Fatal(err)
	}
	body := ask(`{"path": "mimir"}`)
	summary = <-h.asked
	bodyID := pendingID()
	h.answer(t, summary, notify.Body)
	<-body
	timedOut := ask(`{"path": "tempo"}`)
	<-h.asked
	timeoutID := pendingID()
	for clk.asked(wire.AskTimeout) == 0 {
		time.Sleep(time.Millisecond)
	}
	clk.advance(wire.AskTimeout)
	<-timedOut

	got := log.String()
	for _, want := range []string{
		`msg=Asking pending=` + id + ` capability=thing summary=`,
		`msg=Refused op=request refused=asking capability=thing err="The user hasn't answered your last request for this yet"`,
		`msg=Answered pending=` + id + ` capability=thing allow=true via=button lease=PT2H narrowed=false`,
		`msg=Answered pending=` + bodyID + ` capability=thing allow=false via=body`,
		`msg="Timed out" pending=` + timeoutID + ` capability=thing waiting=notification`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("No %q in the log:\n%s", want, got)
		}
	}
	for _, leak := range []string{"s3cret-value", "the reason stays out"} {
		if strings.Contains(got, leak) {
			t.Errorf("%q in the log:\n%s", leak, got)
		}
	}
}
