package main

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
)

// A call's run: its unit, output, failures, validity, slots and log (call.go runCall)

// A failing command is an error carrying its exit and stderr, recorded with the call. Opaque arguments are recorded by
// digest
func TestCallFails(t *testing.T) {
	b, c, _ := commandBroker(t, "echo broken >&2; exit 3", "allow")
	c.Commands["run"].Arguments = map[string]json.RawMessage{
		"csr": json.RawMessage(`{"type": "string", "opaque": true, "description": "a CSR"}`)}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	_, err := b.call(peerAt(t, os.Getpid()), wire.Request{Op: "call", Capability: c.id(), Command: "run",
		Arguments: json.RawMessage(`{"csr": "MIIBsecret"}`), Reason: "testing"})
	if err == nil || !strings.Contains(err.Error(), "exit 3") || !strings.Contains(err.Error(), "broken") {
		t.Errorf("Failed call: %v", err)
	}
	gs := b.grantViews()
	calls := b.handleControl(nil, peerAt(t, os.Getpid()), wire.Request{Op: "state"}).Calls
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
		_, _ = b.call(peerAt(t, os.Getpid()), wire.Request{Op: "call", Capability: c.id(), Command: "run",
			Arguments: json.RawMessage(`{"text": "` + long + `"}`), Reason: "testing"})
	}
	calls := b.handleControl(nil, peerAt(t, os.Getpid()), wire.Request{Op: "state"}).Calls
	if len(calls) != maxCalls {
		t.Fatalf("%d calls kept", len(calls))
	}
	if strings.Contains(string(calls[0].Arguments), long) || !strings.Contains(string(calls[0].Arguments), "(250 characters)") ||
		len(calls[0].Error) != maxStderr || calls[0].Capability != c.id() {
		t.Errorf("Recorded %s, error of %d bytes", calls[0].Arguments, len(calls[0].Error))
	}
}
