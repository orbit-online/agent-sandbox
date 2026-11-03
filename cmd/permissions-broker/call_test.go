package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// commandBroker is a broker with the test command capability, its run replaced by script
func commandBroker(t *testing.T, script string, answers ...string) (*broker, *capability, *fakeAsker) {
	t.Helper()
	b, f := testBroker(t, answers...)
	c := testCap(t, "command")
	path := filepath.Join(t.TempDir(), "run")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.Commands["run"].Run = []string{path}
	b.caps[c.id()] = c
	return b, c, f
}

// Everything a call carries is checked before the user is asked
func TestCallChecksFirst(t *testing.T) {
	b, c, f := commandBroker(t, "cat", "allow")
	c.Commands["run"].Arguments = map[string]json.RawMessage{
		"n": json.RawMessage(`{"type": "integer", "maximum": 9, "description": "a number"}`)}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	for _, r := range []request{
		{Command: "other", Arguments: json.RawMessage(`{"n": 1}`)},
		{Command: "run", Arguments: json.RawMessage(`{"n": 10}`)},
		{Command: "run", Arguments: json.RawMessage(`{}`)},
		{Command: "run", Arguments: json.RawMessage(`{"n": 1, "m": 2}`)},
		{Command: "run", Arguments: json.RawMessage(`{"n": 1}`), Params: json.RawMessage(`{"other": 1}`)},
		{Command: "run", Arguments: json.RawMessage(`{"n": 1}`), Reason: "\n"},
		{Command: "run", Arguments: json.RawMessage(`{"n": 1}`), Lease: "forever"},
	} {
		r.Op, r.Capability = "call", c.id()
		if r.Reason == "" {
			r.Reason = "testing"
		}
		if _, err := b.call(peerAt(t, os.Getpid()), r); err == nil {
			t.Errorf("%+v called", r)
		}
	}
	if f.count() != 0 {
		t.Errorf("Asked %d times", f.count())
	}
	if _, err := b.call(peerAt(t, os.Getpid()), request{Op: "call", Capability: c.id(), Command: "run",
		Arguments: json.RawMessage(`{"n": 9}`), Reason: "testing"}); err != nil || f.count() != 1 {
		t.Errorf("A valid call: %v, asked %d times", err, f.count())
	}
	// The user was told what the grant covers
	if f.asked[0].Scope != c.scope() || f.asked[0].Lease != defaultLease {
		t.Errorf("Asked %+v", f.asked[0])
	}
}

// A once grant covers the call it was made for, not one running beside it, and ends with it
func TestCallOnce(t *testing.T) {
	// A third allow, for the request that mustn't get a once grant
	b, c, f := commandBroker(t, "sleep 0.5; cat", "allow", "allow", "allow")
	first := make(chan error, 1)
	go func() {
		_, err := callRun(b, peerAt(t, os.Getpid()), `{}`, "once")
		first <- err
	}()
	time.Sleep(200 * time.Millisecond)
	if gs := b.liveGrants(); len(gs) != 1 || gs[0].Lease != "once" {
		t.Fatalf("Grants while the first call runs: %v", gs)
	}
	if _, err := callRun(b, peerAt(t, os.Getpid()), `{}`, "once"); err != nil || f.count() != 2 {
		t.Errorf("A second call beside it: %v, asked %d times", err, f.count())
	}
	if err := <-first; err != nil {
		t.Error(err)
	}
	if gs := b.liveGrants(); len(gs) != 0 {
		t.Errorf("Once grants left: %v", gs)
	}
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "once")); err == nil || f.count() != 2 {
		t.Errorf("A request for a once grant: %v, asked %d times", err, f.count())
	}
}

// A failing command is an error carrying its exit and stderr, recorded with the call. Opaque arguments are recorded by
// digest
func TestCallFails(t *testing.T) {
	b, c, _ := commandBroker(t, "echo broken >&2; exit 3", "allow")
	c.Commands["run"].Arguments = map[string]json.RawMessage{
		"csr": json.RawMessage(`{"type": "string", "opaque": true, "description": "a CSR"}`)}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	_, err := b.call(peerAt(t, os.Getpid()), request{Op: "call", Capability: c.id(), Command: "run",
		Arguments: json.RawMessage(`{"csr": "MIIBsecret"}`), Reason: "testing"})
	if err == nil || !strings.Contains(err.Error(), "exit 3") || !strings.Contains(err.Error(), "broken") {
		t.Errorf("Failed call: %v", err)
	}
	gs := b.grantViews()
	calls := b.handleControl(nil, peerAt(t, os.Getpid()), request{Op: "state"}).Calls
	if len(gs) != 1 || len(calls) != 1 {
		t.Fatalf("Grants %+v, calls %+v", gs, calls)
	}
	rec := calls[0]
	if rec.Exit != 3 || rec.Error != "broken" || rec.Grant != gs[0].ID || strings.Contains(string(rec.Arguments), "secret") ||
		!strings.Contains(string(rec.Arguments), "sha256:") {
		t.Errorf("Recorded %+v", rec)
	}
}

// Results: text must be text, an image comes back as data of its type, too much output fails and stops the unit
func TestCallResults(t *testing.T) {
	b, c, _ := commandBroker(t, `printf '\211PNG'`, "allow")
	c.Commands["run"].Result = "image/png"
	res, err := callRun(b, peerAt(t, os.Getpid()), `{}`, "")
	if err != nil || res.Mime != "image/png" || string(res.Data) != "\x89PNG" || res.Output != "" {
		t.Errorf("Image: %+v, %v", res, err)
	}
	c.Commands["run"].Result = "text"
	if _, err := callRun(b, peerAt(t, os.Getpid()), `{}`, ""); err == nil {
		t.Error("Not text passed as text")
	}
	b, _, _ = commandBroker(t, "head -c "+strconv.Itoa(maxOutput+1)+" /dev/zero", "allow")
	log := fakeSystemd(t)
	if _, err := callRun(b, peerAt(t, os.Getpid()), `{}`, ""); err == nil {
		t.Error("More than maxOutput passed")
	}
	if data, _ := os.ReadFile(log); !strings.Contains(string(data), "systemctl --user stop perm-test_call-") {
		t.Errorf("The unit wasn't stopped: %s", data)
	}
}

// The unit: the user's, collected, bounded by the timeout, bound to the daemon's. A revoke stops a running call's
// unit, and its output isn't handed out
func TestCallUnit(t *testing.T) {
	b, c, _ := commandBroker(t, "sleep 1; cat", "allow")
	b.cfg.Unit = "permissions.service"
	c.Commands["run"].Timeout = "PT90S"
	log := fakeSystemd(t)
	done := make(chan error, 1)
	go func() {
		_, err := callRun(b, peerAt(t, os.Getpid()), `{}`, "")
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	gs := b.liveGrants()
	if len(gs) != 1 {
		t.Fatalf("Grants %v", gs)
	}
	if _, err := b.revoke(gs[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Error("Output handed out after a revoke")
	}
	data, _ := os.ReadFile(log)
	for _, want := range []string{"--user --quiet --pipe --collect --unit=perm-test_call-",
		"--property=RuntimeMaxSec=90 --property=BindsTo=permissions.service --property=After=permissions.service -- /",
		"systemctl --user stop perm-test_call-"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("No %q in %s", want, data)
		}
	}
}

// Validity: the grant's time left, capped by maxValidity; none when neither bounds it
func TestCallValidity(t *testing.T) {
	b, c, _ := commandBroker(t, "cat", "allow", "allow")
	c.Commands["run"].MaxValidity = ""
	res, err := callRun(b, peerAt(t, os.Getpid()), `{"path": "/a"}`, "lock")
	if b.lockOK {
		t.Fatal("The lock is watched")
	}
	if err == nil {
		t.Fatal("A lock lease without the lock watched")
	}
	res, err = callRun(b, peerAt(t, os.Getpid()), `{"path": "/a"}`, "once")
	if err != nil || calledWith(t, res).Validity != "" {
		t.Errorf("Once without maxValidity: %+v, %v", res, err)
	}
	c.Commands["run"].MaxValidity = "PT10M"
	res, err = callRun(b, peerAt(t, os.Getpid()), `{"path": "/b"}`, "PT1H")
	if err != nil || calledWith(t, res).Validity != "PT600S" {
		t.Errorf("An hour's lease, ten minutes' maxValidity: %+v, %v", res, err)
	}
}

// A grant whose instance went away ends; a call on an instance that isn't there is refused without asking
func TestInstanceGone(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VMS", dir)
	if err := os.WriteFile(filepath.Join(dir, "win11.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	b, c, f := commandBroker(t, "cat", "allow")
	clk := newFakeClock()
	b.clock = clk
	c.Params = map[string]json.RawMessage{"vm": json.RawMessage(`{"type": "string", "description": "the VM",
		"instances": "$VMS/*.sock"}`)}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	if _, err := callRun(b, peerAt(t, os.Getpid()), `{"vm": "win10"}`, ""); err == nil || f.count() != 0 {
		t.Errorf("No such VM: %v, asked %d times", err, f.count())
	}
	if _, err := callRun(b, peerAt(t, os.Getpid()), `{"vm": "win11"}`, ""); err != nil {
		t.Fatal(err)
	}
	g := b.liveGrants()[0]
	if err := os.Remove(filepath.Join(dir, "win11.sock")); err != nil {
		t.Fatal(err)
	}
	c.listedAt = time.Time{}
	clk.advance(instanceEvery)
	select {
	case <-g.ended:
	case <-time.After(settle):
		t.Error("The grant outlived its instance")
	}
}

// The MCP server lists every host command from its start, and a call runs it
func TestCommandTools(t *testing.T) {
	b, c, _ := commandBroker(t, "cat", "allow")
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
	cfg := commandConfig{Name: c.Name, Description: c.Description, Bounding: c.Params, Commands: c.Commands}
	server := newMCPServer(sock, nil)
	addCommandTools(server, sock, nil, []commandConfig{cfg})
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var tool *mcp.Tool
	for _, tl := range tools.Tools {
		if tl.Name == "thing_run" {
			tool = tl
		}
	}
	schema, _ := json.Marshal(tool.InputSchema)
	if tool == nil || !strings.Contains(string(schema), `"required":["path","reason","ro"]`) ||
		!strings.Contains(string(schema), `"lease"`) {
		t.Fatalf("Tool %+v, schema %s", tool, schema)
	}
	out, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "thing_run",
		Arguments: map[string]any{"path": "/a", "ro": true, "reason": "testing"}})
	if err != nil || out.IsError {
		t.Fatalf("Call: %+v, %v", out, err)
	}
	var in callInput
	if err := json.Unmarshal([]byte(out.Content[0].(*mcp.TextContent).Text), &in); err != nil ||
		string(in.Bounding) != `{"path":"/a","ro":true}` || string(in.Arguments) != `{}` {
		t.Errorf("Ran with %+v, %v", in, err)
	}
	out, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "thing_run", Arguments: map[string]any{"reason": "x",
		"path": "/b", "lease": "forever"}})
	if err != nil || !out.IsError {
		t.Errorf("A bad lease: %+v, %v", out, err)
	}
}

// A call made before the daemon listens waits for it
func TestCallWaitsForBroker(t *testing.T) {
	b, c, _ := commandBroker(t, "cat", "allow")
	if err := os.MkdirAll(b.cfg.GrantDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(b.cfg.GrantDir, "request.sock")
	go func() {
		time.Sleep(time.Second)
		ln, err := listen(sock)
		if err != nil {
			t.Error(err)
			return
		}
		t.Cleanup(func() { ln.Close() })
		b.serveOn(ln, b.handleRequest)
	}()
	cfg := commandConfig{Name: c.Name, Bounding: c.Params, Commands: c.Commands}
	args, _ := json.Marshal(map[string]any{"reason": "testing"})
	out, err := commandHandler(sock, nil, cfg, "run")(context.Background(),
		&mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "thing_run", Arguments: args}})
	if err != nil || out.IsError {
		t.Errorf("Call before the daemon listened: %+v, %v", out, err)
	}
}

// What a call can't do: carry an array or multiline bounding value, and run once its grant ended while it waited
func TestCallParamsRefused(t *testing.T) {
	for _, schema := range []string{`{"type": "array", "items": {"type": "string"}, "description": "d"}`,
		`{"type": "string", "multiline": true, "description": "d"}`} {
		c := testCap(t, "command")
		c.Params["hosts"] = json.RawMessage(schema)
		if err := c.check(); err == nil {
			t.Errorf("Bounding %s accepted", schema)
		}
	}
}

// A grant ending while its call waits for a slot: the command never starts
func TestCallEndedBeforeStart(t *testing.T) {
	b, _, _ := commandBroker(t, "cat", "allow")
	log := fakeSystemd(t)
	g, err := b.request(peerAt(t, os.Getpid()), req("thing", `{}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	for range cap(callSlots) {
		callSlots <- struct{}{}
	}
	done := make(chan error, 1)
	go func() {
		_, err := callRun(b, peerAt(t, os.Getpid()), `{}`, "")
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	if _, err := b.revoke(g.ID); err != nil {
		t.Fatal(err)
	}
	for range cap(callSlots) {
		<-callSlots
	}
	if err := <-done; err == nil {
		t.Error("Ran after the grant ended")
	}
	if data, _ := os.ReadFile(log); strings.Contains(string(data), "--pipe") {
		t.Errorf("The command started: %s", data)
	}
}

// Calls with the same bounding values run one at a time, and one waits callWait at most
func TestCallSlot(t *testing.T) {
	b, _, _ := commandBroker(t, "sleep 1; cat", "allow")
	old := callWait
	callWait = 300 * time.Millisecond
	t.Cleanup(func() { callWait = old })
	if _, err := b.request(peerAt(t, os.Getpid()), req("thing", `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() {
		_, err := callRun(b, peerAt(t, os.Getpid()), `{}`, "")
		first <- err
	}()
	time.Sleep(100 * time.Millisecond)
	if _, err := callRun(b, peerAt(t, os.Getpid()), `{}`, ""); err == nil || !strings.Contains(err.Error(), "still running") {
		t.Errorf("A second call beside the first: %v", err)
	}
	if err := <-first; err != nil {
		t.Error(err)
	}
}

// A call past its timeout fails with what it printed on stderr, and its unit is stopped
func TestCallTimeout(t *testing.T) {
	b, c, _ := commandBroker(t, "echo started >&2; sleep 5", "allow")
	old := runSlack
	runSlack = 0
	t.Cleanup(func() { runSlack = old })
	c.Commands["run"].Timeout = "PT1S"
	log := fakeSystemd(t)
	_, err := callRun(b, peerAt(t, os.Getpid()), `{}`, "")
	if err == nil || !strings.Contains(err.Error(), "timed out") || !strings.Contains(err.Error(), "started") {
		t.Errorf("Past its timeout: %v", err)
	}
	if data, _ := os.ReadFile(log); !strings.Contains(string(data), "systemctl --user stop perm-test_call-") {
		t.Errorf("The unit wasn't stopped: %s", data)
	}
}

// The log keeps the last maxCalls calls, long arguments cut and stderr's tail
func TestCallLog(t *testing.T) {
	b, c, _ := commandBroker(t, `head -c 10000 /dev/zero | tr '\0' x >&2; exit 1`, "allow")
	c.Commands["run"].Arguments = map[string]json.RawMessage{"text": json.RawMessage(`{"type": "string", "description": "t"}`)}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("y", maxRecorded+50)
	for range maxCalls + 2 {
		_, _ = b.call(peerAt(t, os.Getpid()), request{Op: "call", Capability: c.id(), Command: "run",
			Arguments: json.RawMessage(`{"text": "` + long + `"}`), Reason: "testing"})
	}
	calls := b.handleControl(nil, peerAt(t, os.Getpid()), request{Op: "state"}).Calls
	if len(calls) != maxCalls {
		t.Fatalf("%d calls kept", len(calls))
	}
	if strings.Contains(string(calls[0].Arguments), long) || !strings.Contains(string(calls[0].Arguments), "(250 characters)") ||
		len(calls[0].Error) != maxStderr || calls[0].Capability != c.id() {
		t.Errorf("Recorded %s, error of %d bytes", calls[0].Arguments, len(calls[0].Error))
	}
}

// Once grants of an exclusive capability beside each other: the lock is the launcher's, held by both
func TestCallOnceExclusive(t *testing.T) {
	b, c, f := commandBroker(t, "sleep 0.5; cat", "allow", "allow")
	c.Exclusive = true
	first := make(chan error, 1)
	go func() {
		_, err := callRun(b, peerAt(t, os.Getpid()), `{}`, "once")
		first <- err
	}()
	time.Sleep(200 * time.Millisecond)
	if _, err := callRun(b, peerAt(t, os.Getpid()), `{}`, "once"); err != nil || f.count() != 2 {
		t.Errorf("A second once call: %v, asked %d times", err, f.count())
	}
	if err := <-first; err != nil {
		t.Error(err)
	}
	if locks := lockHolders(); len(locks) != 0 {
		t.Errorf("Locks left: %v", locks)
	}
}

// The window may change a host command grant's lease, not its bounding values
func TestWindowKeepsBounding(t *testing.T) {
	b, c, _ := commandBroker(t, "cat", "options")
	go func() {
		for {
			b.mu.Lock()
			var id string
			for _, p := range b.pending {
				if p.Options {
					id = p.ID
				}
			}
			b.mu.Unlock()
			if id != "" {
				_ = b.answer(request{Pending: id, Allow: true, Lease: "PT8H", Params: json.RawMessage(`{"path": "/b"}`)})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	if g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H")); err == nil {
		t.Errorf("Granted %+v", g)
	}
}
