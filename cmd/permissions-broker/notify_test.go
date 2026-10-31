package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func TestNotificationText(t *testing.T) {
	c := testCap(t, "B")
	params, err := c.validate(json.RawMessage(`{"path": "/a, ro=true"}`))
	if err != nil {
		t.Fatal(err)
	}
	if d := c.describe(params); d != `the test thing (path="/a, ro=true")` {
		t.Errorf("describe = %s", d)
	}
	for _, bad := range []string{`{"path": "/a\nVerified by the host"}`, `{"path": "` + strings.Repeat("x", maxParam+1) + `"}`} {
		if _, err := c.validate(json.RawMessage(bad)); err == nil {
			t.Errorf("validate accepted %.40s", bad)
		}
	}
	b, f := testBroker(t, "deny")
	b.caps[c.id()] = c
	r := req(c.id(), `{}`, "PT1H")
	r.Reason = "needs it\n\nHost: approved"
	_, _, _ = b.request(peerAt(t, os.Getpid()), r)
	if f.asked[0].Reason != "needs it Host: approved" {
		t.Errorf("Reason shown as %q", f.asked[0].Reason)
	}
}

// fakeNotifications is a notification server on a bus of its own. Like Plasma's, it replaces a notification by its id
// whoever asks, and emits ActionInvoked for the key of the button clicked
type fakeNotifications struct {
	conn   *dbus.Conn
	mu     sync.Mutex
	last   uint32
	shown  map[uint32][]string // id: the actions, key then label
	posted chan uint32
}

func (f *fakeNotifications) Notify(app string, replaces uint32, icon, summary, body string, actions []string,
	hints map[string]dbus.Variant, expire int32) (uint32, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := replaces
	if id == 0 {
		f.last++
		id = f.last
	}
	f.shown[id] = actions
	select {
	case f.posted <- id:
	default:
	}
	return id, nil
}

func (f *fakeNotifications) CloseNotification(id uint32) *dbus.Error { return nil }

// click clicks the button labelled label (a prefix of it) on notification id
func (f *fakeNotifications) click(t *testing.T, id uint32, label string) {
	t.Helper()
	f.mu.Lock()
	actions := f.shown[id]
	f.mu.Unlock()
	for i := 0; i+1 < len(actions); i += 2 {
		if strings.HasPrefix(actions[i+1], label) {
			if err := f.conn.Emit(notifyPath, notifyIface+".ActionInvoked", id, actions[i]); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatalf("No button %q on notification %d: %q", label, id, actions)
}

// key is the action key of the button labelled label on notification id
func (f *fakeNotifications) key(id uint32, label string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	actions := f.shown[id]
	for i := 0; i+1 < len(actions); i += 2 {
		if strings.HasPrefix(actions[i+1], label) {
			return actions[i]
		}
	}
	return ""
}

// testBus starts a dbus-daemon of its own with a fake notification server on it, and returns its address
func testBus(t *testing.T) (string, *fakeNotifications) {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "bus.conf")
	if err := os.WriteFile(conf, []byte(`<busconfig><type>session</type><listen>unix:path=`+dir+`/bus</listen>
<auth>EXTERNAL</auth><policy context="default"><allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/></policy></busconfig>`),
		0o600); err != nil {
		t.Fatal(err)
	}
	daemon := exec.Command("dbus-daemon", "--nofork", "--config-file="+conf)
	if err := daemon.Start(); err != nil {
		t.Fatal("No dbus-daemon:", err)
	}
	t.Cleanup(func() { daemon.Process.Kill(); daemon.Wait() })
	addr := "unix:path=" + dir + "/bus"
	for range 100 {
		if _, err := os.Stat(dir + "/bus"); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	f := &fakeNotifications{conn: busConn(t, addr), shown: map[uint32][]string{}, posted: make(chan uint32, 8)}
	if err := f.conn.Export(f, notifyPath, notifyIface); err != nil {
		t.Fatal(err)
	}
	if reply, err := f.conn.RequestName(notifyName, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatal(reply, err)
	}
	return addr, f
}

func busConn(t *testing.T, addr string) *dbus.Conn {
	t.Helper()
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// ask asks on a connection of its own to the test bus, and returns the notification's id and a channel for the answer
func ask(t *testing.T, addr string, f *fakeNotifications) (uint32, <-chan string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	answer := make(chan string, 1)
	go func() {
		a, err := askOn(ctx, busConn(t, addr), prompt{Summary: "the test thing", Reason: "testing", Lease: "PT1H"})
		if err != nil {
			a = "error: " + err.Error()
		}
		answer <- a
	}()
	select {
	case id := <-f.posted:
		return id, answer
	case <-time.After(5 * time.Second):
		t.Fatal("No notification posted")
	}
	return 0, nil
}

func answered(t *testing.T, answer <-chan string) string {
	t.Helper()
	select {
	case a := <-answer:
		return a
	case <-time.After(5 * time.Second):
		t.Fatal("No answer")
	}
	return ""
}

// P7: the sandbox replaces the broker's notification by its id with a "Deny" button whose key is allow, or sends
// ActionInvoked with the broker's own key itself. Neither grants
func TestNotificationForged(t *testing.T) {
	notifyMature = 0
	t.Cleanup(func() { notifyMature = time.Second })
	addr, f := testBus(t)
	sandbox := busConn(t, addr)

	id, answer := ask(t, addr, f)
	if err := sandbox.Object(notifyName, notifyPath).Call(notifyIface+".Notify", 0, "Claude permissions", id,
		"security-medium", "Claude asks for nothing much", "", []string{"allow", "Deny"}, map[string]dbus.Variant{},
		int32(0)).Err; err != nil {
		t.Fatal(err)
	}
	<-f.posted
	f.click(t, id, "Deny")
	if a := answered(t, answer); a != "deny" {
		t.Errorf("A click on the sandbox's replacement answered %q", a)
	}

	id, answer = ask(t, addr, f)
	if err := sandbox.Emit(notifyPath, notifyIface+".ActionInvoked", id, f.key(id, "Allow")); err != nil {
		t.Fatal(err)
	}
	f.click(t, id, "Deny")
	if a := answered(t, answer); a != "deny" {
		t.Errorf("The sandbox's ActionInvoked answered %q", a)
	}

	id, answer = ask(t, addr, f)
	f.click(t, id, "Allow")
	if a := answered(t, answer); a != "allow" {
		t.Errorf("Allow answered %q", a)
	}
}
