package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"golang.org/x/sys/unix"
)

// With DBUS_PROXY_MAIN set the test binary is the proxy, for the tests of its command line; with DBUS_PROXY_LAZY
// the activatable service the state machine's bus starts (machine_world_test.go)
func TestMain(m *testing.M) {
	if os.Getenv("DBUS_PROXY_LAZY") != "" {
		lazyHelper()
	}
	if os.Getenv("DBUS_PROXY_MAIN") != "" {
		if n, err := strconv.ParseUint(os.Getenv("DBUS_PROXY_NOFILE"), 10, 64); err == nil {
			rl := unix.Rlimit{Cur: n, Max: n}
			if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
				panic(err)
			}
		}
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// A dbus-daemon of the test's own. It lets anyone send unrequested replies, so the proxy is what refuses them
const busConfig = `<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path=%s</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
    <allow send_requested_reply="false" send_type="method_return"/>
    <allow send_requested_reply="false" send_type="error"/>
    <allow receive_requested_reply="false" receive_type="method_return"/>
    <allow receive_requested_reply="false" receive_type="error"/>
  </policy>
  <limit name="max_replies_per_connection">50000</limit>
  <limit name="max_message_unix_fds">253</limit>
  <limit name="max_incoming_unix_fds">100000</limit>
  <limit name="max_outgoing_unix_fds">100000</limit>
</busconfig>
`

// Starts a dbus-daemon and returns its address
func startBus(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "bus")
	conf := filepath.Join(dir, "bus.conf")
	if err := os.WriteFile(conf, []byte(fmt.Sprintf(busConfig, sock)), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("dbus-daemon", "--config-file="+conf, "--nofork", "--nopidfile")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start dbus-daemon: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	waitFor(t, func() bool { _, err := os.Stat(sock); return err == nil })
	return "unix:path=" + sock
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Timed out waiting")
}

// A config's entry giving name a policy, for startProxy
func policy(name, p string) string { return fmt.Sprintf(`%q: {"policy": %q}`, name, p) }

// A config's entry giving name one rule of kind, "call" or "broadcast"
func ruled(name, kind, rule string) string { return fmt.Sprintf(`%q: {%q: [%q]}`, name, kind, rule) }

// A config of the entries given
func config(entries ...string) string { return "{" + strings.Join(entries, ", ") + "}" }

// A config file of the entries given, for the proxy run as a command
func configFile(t *testing.T, entries ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(config(entries...)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Starts a proxy in the test's process with a config of the entries given, returning the address clients connect to
func startProxy(t *testing.T, bus string, entries ...string) string {
	t.Helper()
	return startProxyWith(t, bus, nil, entries...)
}

// startProxy, with tweak applied to the proxy before it serves
func startProxyWith(t *testing.T, bus string, tweak func(*Proxy), entries ...string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "proxy")
	rs, err := rules.Decode([]byte(config(entries...)))
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProxy(bus, rules.New(rs))
	if err != nil {
		t.Fatal(err)
	}
	if tweak != nil {
		tweak(p)
	}
	l, err := listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { p.Serve(l); close(done) }()
	t.Cleanup(func() { l.Close(); <-done })
	return "unix:path=" + sock
}

// A godbus connection, authenticated and registered
func connect(t *testing.T, addr string) *dbus.Conn {
	t.Helper()
	conn, err := dbus.Dial(addr)
	if err != nil {
		t.Fatalf("Dial %s: %v", addr, err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.Auth(nil); err != nil {
		t.Fatalf("Auth: %v", err)
	}
	if err := conn.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}
	return conn
}

// The test service: org.test.Svc on the bus exporting testObj at /org/test and /org/test/sub/obj
type testObj struct{}

func (testObj) Echo(s string) (string, *dbus.Error) { return s, nil }
func (testObj) Other(string) (string, *dbus.Error)  { return "other", nil }

// Reads what the fd it's given holds
func (testObj) ReadFD(fd dbus.UnixFD) (string, *dbus.Error) {
	f := os.NewFile(uintptr(fd), "fd")
	defer f.Close()
	b := make([]byte, 64)
	n, _ := f.Read(b)
	return string(b[:n]), nil
}

// Returns a pipe's read end holding "from service"
func (testObj) GiveFD() (dbus.UnixFD, *dbus.Error) {
	r, w, err := os.Pipe()
	if err != nil {
		return 0, dbus.MakeFailedError(err)
	}
	w.Write([]byte("from service"))
	w.Close()
	return dbus.UnixFD(r.Fd()), nil
}

const (
	svcName  = "org.test.Svc"
	svcIface = "org.test.Iface"
)

func startService(t *testing.T, bus string, names ...string) *dbus.Conn {
	t.Helper()
	conn := connect(t, bus)
	for _, p := range []dbus.ObjectPath{"/org/test", "/org/test/sub/obj", "/other"} {
		if err := conn.Export(testObj{}, p, svcIface); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range append([]string{svcName}, names...) {
		if r, err := conn.RequestName(n, dbus.NameFlagDoNotQueue); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
			t.Fatalf("RequestName %s: %v %v", n, r, err)
		}
	}
	return conn
}

func call(conn *dbus.Conn, dest string, path dbus.ObjectPath, method string, args ...any) (*dbus.Call, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c := conn.Object(dest, path).CallWithContext(ctx, method, 0, args...)
	return c, c.Err
}

// The D-Bus error name of err, or "" for none
func errName(err error) string {
	var de dbus.Error
	if errors.As(err, &de) {
		return de.Name
	}
	if err != nil {
		return "other: " + err.Error()
	}
	return ""
}

func wantErr(t *testing.T, what string, err error, name string) {
	t.Helper()
	if got := errName(err); got != name {
		t.Errorf("%s: got error %q, want %q", what, got, name)
	}
}

func busCallOn(conn *dbus.Conn, method string, args ...any) error {
	_, err := call(conn, busName, busPath, busIface+"."+method, args...)
	return err
}

func hasOwner(t *testing.T, conn *dbus.Conn, name string) bool {
	t.Helper()
	var ok bool
	c, err := call(conn, busName, busPath, busIface+".NameHasOwner", name)
	if err != nil {
		t.Fatalf("NameHasOwner: %v", err)
	}
	c.Store(&ok)
	return ok
}

func listNames(t *testing.T, conn *dbus.Conn) string {
	t.Helper()
	var names []string
	c, err := call(conn, busName, busPath, busIface+".ListNames")
	if err != nil {
		t.Fatalf("ListNames: %v", err)
	}
	c.Store(&names)
	return " " + strings.Join(names, " ") + " "
}

// The signals a connection gets within a short wait
func signals(conn *dbus.Conn, wait time.Duration) func() []*dbus.Signal {
	ch := make(chan *dbus.Signal, 64)
	conn.Signal(ch)
	return func() []*dbus.Signal {
		var out []*dbus.Signal
		deadline := time.After(wait)
		for {
			select {
			case s := <-ch:
				out = append(out, s)
			case <-deadline:
				return out
			}
		}
	}
}

func dialRaw(t *testing.T, addr string) *net.UnixConn {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: strings.TrimPrefix(addr, "unix:path="), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}
