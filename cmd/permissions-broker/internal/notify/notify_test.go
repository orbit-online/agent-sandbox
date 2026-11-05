package notify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// fakeNotifications is a notification server on a bus of its own. Like Plasma's, it replaces a notification by its id
// whoever asks, and emits ActionInvoked for the key of the button clicked. Its name in GetServerInformation is name
type fakeNotifications struct {
	conn   *dbus.Conn
	name   string
	mu     sync.Mutex
	last   uint32
	shown  map[uint32][]string // id: the actions, key then label
	bodies map[uint32]string
	sums   map[uint32]string
	posted chan uint32
}

func (f *fakeNotifications) GetServerInformation() (string, string, string, string, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.name, "test", "1", "1.3", nil
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
	f.bodies[id] = body
	f.sums[id] = summary
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

// clickBody clicks the body of notification id as cosmic-notifications does: the action named default, or without one
// the first
func (f *fakeNotifications) clickBody(t *testing.T, id uint32) {
	t.Helper()
	f.mu.Lock()
	actions := f.shown[id]
	f.mu.Unlock()
	if len(actions) < 2 {
		t.Fatalf("No actions on notification %d", id)
	}
	key := actions[0]
	for i := 0; i+1 < len(actions); i += 2 {
		if actions[i] == "default" {
			key = actions[i]
		}
	}
	if err := f.conn.Emit(notifyPath, notifyIface+".ActionInvoked", id, key); err != nil {
		t.Fatal(err)
	}
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
	f := &fakeNotifications{conn: busConn(t, addr), name: "fake", shown: map[uint32][]string{},
		bodies: map[uint32]string{}, sums: map[uint32]string{}, posted: make(chan uint32, 8)}
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
	return askWith(t, addr, f, Prompt{Summary: "the test thing", Reason: "testing", Lease: "PT1H"})
}

func askWith(t *testing.T, addr string, f *fakeNotifications, p Prompt) (uint32, <-chan string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	answer := make(chan string, 1)
	go func() {
		a, err := askOn(ctx, busConn(t, addr), p)
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

// A click on the body sends the default action, first in the list: it denies, and on COSMIC, which draws no buttons and
// would otherwise send the first action, it opens the window when there is one
func TestNotificationDefault(t *testing.T) {
	notifyMature = 0
	t.Cleanup(func() { notifyMature = time.Second })
	addr, f := testBus(t)
	window := Prompt{Summary: "the test thing", Reason: "testing", Lease: "PT1H", Options: true}
	for _, c := range []struct {
		server string
		p      Prompt
		want   string
	}{{"fake", window, "deny"}, {cosmicServer, window, "options"}, {cosmicServer, Prompt{Summary: "x", Reason: "y"}, "deny"}} {
		f.mu.Lock()
		f.name = c.server
		f.mu.Unlock()
		id, answer := askWith(t, addr, f, c.p)
		f.mu.Lock()
		first, body := f.shown[id][0], f.bodies[id]
		f.mu.Unlock()
		if first != "default" {
			t.Errorf("%s: the first action is %q", c.server, first)
		}
		if hinted := strings.Contains(body, "Permissions window"); hinted != (c.want == "options") {
			t.Errorf("%s: the body %q", c.server, body)
		}
		f.clickBody(t, id)
		if a := answered(t, answer); a != c.want {
			t.Errorf("%s, options %v: a click on the body answered %q", c.server, c.p.Options, a)
		}
	}
}

// The sandbox's own ActionInvoked of default is ignored, and a default within notifyMature asks again
func TestNotificationDefaultGuards(t *testing.T) {
	notifyMature = 0
	t.Cleanup(func() { notifyMature = time.Second })
	addr, f := testBus(t)
	sandbox := busConn(t, addr)

	id, answer := ask(t, addr, f)
	if err := sandbox.Emit(notifyPath, notifyIface+".ActionInvoked", id, "default"); err != nil {
		t.Fatal(err)
	}
	f.click(t, id, "Allow")
	if a := answered(t, answer); a != "allow" {
		t.Errorf("The sandbox's default answered %q", a)
	}

	notifyMature = 300 * time.Millisecond
	id, answer = ask(t, addr, f)
	f.clickBody(t, id)
	select {
	case again := <-f.posted:
		time.Sleep(notifyMature)
		f.clickBody(t, again)
	case a := <-answer:
		t.Fatalf("A click on the body at once answered %q", a)
	case <-time.After(5 * time.Second):
		t.Fatal("Not asked again")
	}
	if a := answered(t, answer); a != "deny" {
		t.Errorf("A click on the body later answered %q", a)
	}
}

// A host command's notification says what Claude wants to do and for how long in its summary, and what the grant
// covers ahead of the reason. The lease is said in hours and minutes
func TestNotificationCovers(t *testing.T) {
	addr, f := testBus(t)
	id, _ := askWith(t, addr, f, Prompt{Summary: `control the VM "win<11>"`, Reason: "testing", Lease: "PT1H30M",
		Scope: "⚠ Run any PowerShell; Take screenshots"})
	f.mu.Lock()
	summary, body := f.sums[id], f.bodies[id]
	f.mu.Unlock()
	if want := `Claude wants to control the VM "win&lt;11&gt;" for 1 h 30 min`; summary != want {
		t.Errorf("Summary %q", summary)
	}
	if want := "For 1 h 30 min: ⚠ Run any PowerShell; Take screenshots\nClaude's reason"; !strings.HasPrefix(body, want) {
		t.Errorf("Body %q", body)
	}
	if _, body := Text(Prompt{Summary: "x", Lease: "lock", Scope: "Take screenshots", Bounds: `vm "a", n 1`}, ""); !strings.HasPrefix(body, `On vm "a", n 1 until the screen locks: Take screenshots`+"\n") {
		t.Errorf("Body %q", body)
	}
	if f.key(id, "Allow for 1 h 30 min") == "" {
		t.Errorf("Actions %q", f.shown[id])
	}
	for d, want := range map[time.Duration]string{time.Hour: "1 h", 8 * time.Hour: "8 h", 30 * time.Minute: "30 min",
		90 * time.Minute: "1 h 30 min", 20 * time.Second: "20 s"} {
		if got := spokenDuration(d); got != want {
			t.Errorf("spokenDuration(%s) = %q", d, got)
		}
	}
}
