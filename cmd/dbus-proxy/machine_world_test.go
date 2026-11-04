package main

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
	"golang.org/x/sys/unix"
	"pgregory.net/rapid"
)

// The world the state machine runs in (machine_test.go): a dbus-daemon of its own, a proxy with static rules,
// scripted services straight on the bus, clients speaking the wire through the proxy, an observer asking the bus who
// owns what

// How long a step may take to settle, and a connection to close
const (
	settle    = 5 * time.Second
	closeWait = time.Second
)

// The bus as startBus's, with an activatable name whose start stays pending until someone takes the name: its Exec is
// the test binary as lazyHelper, which never connects
const machineBusConfig = `<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path=%s</listen>
  <auth>EXTERNAL</auth>
  <servicedir>%s</servicedir>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
    <allow send_requested_reply="false" send_type="method_return"/>
    <allow send_requested_reply="false" send_type="error"/>
    <allow receive_requested_reply="false" receive_type="method_return"/>
    <allow receive_requested_reply="false" receive_type="error"/>
  </policy>
  <limit name="service_start_timeout">3600000</limit>
  <limit name="reply_timeout">3600000</limit>
</busconfig>
`

// lazyHelper is what the bus starts for org.test.Lazy: it waits for the bus to end and takes no name
func lazyHelper() {
	_ = unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0)
	if os.Getppid() == 1 {
		os.Exit(0)
	}
	for {
		time.Sleep(time.Hour)
	}
}

type world struct {
	t    *rapid.T
	dir  string
	bus  string // the bus's address
	addr string // the proxy's
	obs  *party
	svcs []*party
	// Each connection's role by its unique name, and the tokens of generated calls by sender and serial
	mu       sync.Mutex
	roles    map[string]string
	callToks map[string]string
}

func newWorld(t *rapid.T) *world {
	dir, err := os.MkdirTemp("", "proxy-machine")
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, dir: dir, roles: map[string]string{}, callToks: map[string]string{}}
	t.Cleanup(func() { os.RemoveAll(dir) })
	w.startBus()
	w.startProxy()
	w.obs = w.direct("obs")
	for i := range 2 {
		w.svcs = append(w.svcs, w.direct(fmt.Sprintf("svc%d", i)))
	}
	return w
}

func (w *world) startBus() {
	sock := filepath.Join(w.dir, "bus")
	services := filepath.Join(w.dir, "services")
	exe, err := os.Executable()
	if err != nil {
		w.t.Fatal(err)
	}
	if err := os.Mkdir(services, 0o700); err != nil {
		w.t.Fatal(err)
	}
	unit := fmt.Sprintf("[D-BUS Service]\nName=%s\nExec=%s\n", lazyName, exe)
	if err := os.WriteFile(filepath.Join(services, lazyName+".service"), []byte(unit), 0o600); err != nil {
		w.t.Fatal(err)
	}
	conf := filepath.Join(w.dir, "bus.conf")
	if err := os.WriteFile(conf, []byte(fmt.Sprintf(machineBusConfig, sock, services)), 0o600); err != nil {
		w.t.Fatal(err)
	}
	cmd := exec.Command("dbus-daemon", "--config-file="+conf, "--nofork", "--nopidfile")
	cmd.Env = append(os.Environ(), "DBUS_PROXY_LAZY=1")
	if err := cmd.Start(); err != nil {
		w.t.Fatalf("Start dbus-daemon: %v", err)
	}
	w.t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	w.waitFor("the bus's socket", func() bool { _, err := os.Stat(sock); return err == nil })
	w.bus = "unix:path=" + sock
}

// The proxy, in the test's process, with the static rules
func (w *world) startProxy() {
	sock := filepath.Join(w.dir, "proxy")
	opts, err := docopt.ParseArgs(usage, append([]string{w.bus, sock, "--filter"}, staticArgs...), "")
	if err != nil {
		w.t.Fatal(err)
	}
	rs, err := parseRules(opts)
	if err != nil {
		w.t.Fatal(err)
	}
	p, err := NewProxy(w.bus, rules.New(rs))
	if err != nil {
		w.t.Fatal(err)
	}
	p.log = slog.New(slog.DiscardHandler)
	l, err := listen(sock)
	if err != nil {
		w.t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { p.Serve(l); close(done) }()
	w.t.Cleanup(func() {
		l.Close()
		<-done
	})
	w.addr = sock
}

func (w *world) waitFor(what string, ok func() bool) {
	for deadline := time.Now().Add(settle); !ok(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			w.t.Fatalf("Waited for %s", what)
		}
	}
}

// A connection straight to the bus, registered
func (w *world) direct(role string) *party {
	p := w.dial(role, filepath.Join(w.dir, "bus"))
	p.hello(w)
	// The bus's NameAcquired for its unique name, which the model doesn't count
	p.waitUntil(func() bool { return len(p.got) > 0 && p.got[0].member == "NameAcquired" })
	p.drain()
	return p
}

// The role of a unique name, or the name itself when it's no party's
func (w *world) role(name string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if r, ok := w.roles[name]; ok {
		return r
	}
	return name
}

// One connection, speaking the wire: what it receives is collected in order until the connection ends
type party struct {
	role   string
	conn   *net.UnixConn
	serial uint32
	unique string
	// The tokens of the calls it sent, by serial
	tokens map[uint32]string

	mu     sync.Mutex
	got    []*inMsg
	closed bool
	wake   chan struct{}
}

// A message as a party received it
type inMsg struct {
	typ                    dbus.Type
	sender, dest, path     string
	iface, member, errName string
	serial, replySerial    uint32
	body                   []any
}

func (w *world) dial(role, path string) *party {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		w.t.Fatalf("Dial %s: %v", path, err)
	}
	w.t.Cleanup(func() { conn.Close() })
	p := &party{role: role, conn: conn, tokens: map[uint32]string{}, wake: make(chan struct{}, 1)}
	if _, err := conn.Write([]byte("\x00AUTH EXTERNAL " + hexUID(os.Getuid()) + "\r\n")); err != nil {
		w.t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(settle))
	line, err := br.ReadString('\n')
	if err != nil || len(line) < 3 || line[:3] != "OK " {
		w.t.Fatalf("SASL for %s: %q %v", role, line, err)
	}
	conn.SetReadDeadline(time.Time{})
	if _, err := conn.Write([]byte("BEGIN\r\n")); err != nil {
		w.t.Fatal(err)
	}
	if br.Buffered() > 0 {
		w.t.Fatalf("SASL for %s: bytes after OK", role)
	}
	go p.read()
	return p
}

func (p *party) read() {
	r := wire.NewReader(p.conn, nil)
	defer r.Close()
	for {
		m, err := r.ReadMessage()
		if err != nil {
			p.mu.Lock()
			p.closed = true
			p.mu.Unlock()
			p.notify()
			return
		}
		m.DecodeBody(wire.MaxMessageSize)
		in := &inMsg{typ: m.Type, sender: m.Header(dbus.FieldSender), dest: m.Header(dbus.FieldDestination),
			path: m.Header(dbus.FieldPath), iface: m.Header(dbus.FieldInterface), member: m.Header(dbus.FieldMember),
			errName: m.Header(dbus.FieldErrorName), serial: m.Serial(), body: m.Body}
		in.replySerial, _ = m.ReplySerial()
		m.CloseFDs()
		m.Release()
		p.mu.Lock()
		p.got = append(p.got, in)
		p.mu.Unlock()
		p.notify()
	}
}

func (p *party) notify() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Sends a message with the given serial
func (p *party) sendAs(serial uint32, m *dbus.Message) error {
	data, err := wire.Encode(m, serial)
	if err != nil {
		return err
	}
	_, err = p.conn.Write(data)
	return err
}

// Sends a message with the next serial, returning it
func (p *party) send(m *dbus.Message) uint32 {
	p.serial++
	_ = p.sendAs(p.serial, m)
	return p.serial
}

// waitUntil waits for cond over what the party got, until it closed or settle passed
func (p *party) waitUntil(cond func() bool) bool {
	return p.waitFor(settle, cond)
}

func (p *party) waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.After(d)
	for {
		p.mu.Lock()
		ok, closed := cond(), p.closed
		p.mu.Unlock()
		if ok {
			return true
		}
		if closed {
			return false
		}
		select {
		case <-p.wake:
		case <-deadline:
			return false
		}
	}
}

// takeReply removes and returns the reply to serial, waiting for it
func (p *party) takeReply(serial uint32) *inMsg {
	var out *inMsg
	p.waitUntil(func() bool {
		for i, m := range p.got {
			if (m.typ == dbus.TypeMethodReply || m.typ == dbus.TypeError) && m.replySerial == serial {
				out = m
				p.got = append(p.got[:i:i], p.got[i+1:]...)
				return true
			}
		}
		return false
	})
	return out
}

// hello registers the connection and records its role. Called on direct connections and by the machine's Hello
func (p *party) hello(w *world) *inMsg {
	r := p.takeReply(p.send(busCall("Hello")))
	if r == nil || r.typ != dbus.TypeMethodReply || len(r.body) == 0 {
		return r
	}
	p.unique, _ = r.body[0].(string)
	w.mu.Lock()
	w.roles[p.unique] = p.role
	w.mu.Unlock()
	return r
}

// barrier makes sure everything the bus sent the party before now has arrived: a GetId's reply comes after it.
// Reports false when the connection is closed
func (p *party) barrier() bool {
	return p.takeReply(p.send(busCall("GetId"))) != nil
}

// isClosed reports whether the connection ended, waiting up to settle for it when want
func (p *party) isClosed(want bool) bool {
	if !want {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.closed
	}
	// The proxy ends a connection as it reads the message or the removal that ends it; shorter than settle, as a
	// connection kept open waits this long on each of rapid's attempts to shrink a failure
	p.waitFor(closeWait, func() bool { return false })
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

// drain takes what the party got so far
func (p *party) drain() []*inMsg {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.got
	p.got = nil
	return out
}

// The bus's owner of a name, asked by the observer: a role, "" for none
func (w *world) owner(name string) string {
	r := w.obs.takeReply(w.obs.send(busCall("GetNameOwner", name)))
	if r == nil {
		w.t.Fatalf("GetNameOwner %s: no reply", name)
	}
	if r.typ == dbus.TypeError {
		return ""
	}
	s, _ := r.body[0].(string)
	return w.role(s)
}

// waitGone waits until the bus dropped a unique name: the bus sent what its leaving causes by then
func (w *world) waitGone(unique string) {
	w.waitFor("the bus to drop "+unique, func() bool {
		r := w.obs.takeReply(w.obs.send(busCall("NameHasOwner", unique)))
		return r != nil && len(r.body) == 1 && r.body[0] == false
	})
}
