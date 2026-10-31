package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	qt "github.com/mappu/miqt/qt6"
)

var state = map[string]any{
	"pending": []any{map[string]any{"id": "p1", "capability": "folders/folder",
		"params": map[string]any{"path": "/srv/notes", "ro": true}, "summary": `a folder (path="/srv/notes", ro=true)`,
		"reason": "read the notes", "lease": "PT1H", "options": true}},
	"grants": []any{map[string]any{"id": "g1", "capability": "test/thing", "params": map[string]any{},
		"summary": "the test thing", "lease": "session", "granted": "2026-10-31T10:00:00Z"}},
	"always": []any{map[string]any{"capability": "test/thing", "params": map[string]any{"x": "y"},
		"granted": "2026-10-31T10:00:00Z"}},
	"log": []any{map[string]any{"time": "2026-10-31T10:00:00Z", "summary": "the test thing",
		"decision": "allowed (session)"}},
	"held": []any{map[string]any{"grant": "g0", "summary": "a folder", "why": "released from inside",
		"holders": []any{map[string]any{"pid": 42, "comm": "cat", "start": 1}}}},
	"capabilities": []any{map[string]any{"id": "folders/folder", "type": "attach", "description": "a folder",
		"params": map[string]any{"path": map[string]any{"type": "string"}, "ro": map[string]any{"type": "boolean"}}}},
}

// fakeBroker serves control.sock: state answers with state, and every other request is recorded
type fakeBroker struct {
	path     string
	mu       sync.Mutex
	requests []map[string]any
}

func newFakeBroker(t testing.TB) *fakeBroker {
	dir, err := os.MkdirTemp("", "window")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeBroker{path: filepath.Join(dir, "control.sock")}
	ln, err := net.Listen("unix", f.path)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(conn)
		}
	}()
	return f
}

func (f *fakeBroker) handle(conn net.Conn) {
	defer conn.Close()
	var req map[string]any
	if json.NewDecoder(conn).Decode(&req) != nil {
		return
	}
	switch req["op"] {
	case "watch":
		_, _ = conn.Read(make([]byte, 1)) // held open until the window goes
		return
	case "state":
		_ = json.NewEncoder(conn).Encode(state)
		return
	}
	delete(req, "seq")
	f.mu.Lock()
	f.requests = append(f.requests, req)
	f.mu.Unlock()
	_ = json.NewEncoder(conn).Encode(map[string]any{})
}

func (f *fakeBroker) recorded() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.requests...)
}

// Qt runs on the main thread, which the tests don't: the window's check runs in TestMain, before them
func init() { runtime.LockOSThread() }

var qmlErrors []string

func TestMain(m *testing.M) {
	os.Setenv("QT_QPA_PLATFORM", "offscreen")
	qmlErrors = qmlCheck()
	os.Exit(m.Run())
}

// TestQML reports the check of the Qt glue: the window loads without QML warnings, the broker's state reaches it, and
// an action in it reaches the broker through the property map. What each action sends is tst_permissions.qml's
func TestQML(t *testing.T) {
	for _, e := range qmlErrors {
		t.Error(e)
	}
}

func qmlCheck() (errs []string) {
	fail := func(format string, args ...any) { errs = append(errs, sprintf(format, args...)) }
	f := newFakeBroker(nilTB{})
	qt.NewQGuiApplication([]string{"test"})
	var warnings []string
	engine, broker := load(&window{socket: f.path}, "test", "Main.qml", func(w string) { warnings = append(warnings, w) })
	roots := engine.RootObjects()
	if len(roots) == 0 {
		return append(warnings, "The window didn't load")
	}
	pump := func(until func() bool) bool {
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
			qt.QCoreApplication_ProcessEvents()
			if until() {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}
	// Static items are QObject children of their parents; delegates aren't, hence the QML test for those
	find := func(name string) *qt.QObject {
		var walk func(o *qt.QObject) *qt.QObject
		walk = func(o *qt.QObject) *qt.QObject {
			if o.ObjectName() == name {
				return o
			}
			for _, c := range o.Children() {
				if found := walk(c); found != nil {
					return found
				}
			}
			return nil
		}
		return walk(roots[0])
	}
	if !pump(func() bool { return strings.Contains(broker.Value("state").ToString(), `"p1"`) }) {
		fail("The state never arrived")
	}
	end := find("end")
	if end == nil {
		return append(append(warnings, errs...), "No end button in the window")
	}
	if !qt.QMetaObject_InvokeMethod4(end, "click") {
		fail("Clicking end failed")
	}
	if !pump(func() bool {
		r := f.recorded()
		return len(r) > 0 && reflect.DeepEqual(normalize(r[len(r)-1]), normalize(map[string]any{"op": "end", "grants": []any{"g0"}}))
	}) {
		fail("End sent %v", f.recorded())
	}
	return append(warnings, errs...)
}

// normalize compares through JSON, as the broker sees requests
func normalize(v any) any {
	data, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(data, &out)
	return out
}

func TestOperations(t *testing.T) {
	f := newFakeBroker(t)
	w := &window{socket: f.path}
	w.refresh()
	if st, err := w.view(); err != "" || !strings.Contains(st, `"p1"`) {
		t.Fatalf("State %s, error %s", st, err)
	}
	w.do(`{"op": "forget", "capability": "test/thing", "params": {"x": "y"}, "seq": 1}`)
	w.do(`{"op": "revoke", "grant": "g1"}`)
	w.do(`{"op": "end", "grants": ["g0"]}`)
	want := []map[string]any{
		{"op": "forget", "capability": "test/thing", "params": map[string]any{"x": "y"}},
		{"op": "revoke", "grant": "g1"},
		{"op": "end", "grants": []any{"g0"}},
	}
	if got := f.recorded(); !reflect.DeepEqual(normalize(got), normalize(want)) {
		t.Errorf("Requests %v, want %v", got, want)
	}
}

func TestNoBroker(t *testing.T) {
	w := &window{socket: filepath.Join(t.TempDir(), "missing.sock")}
	w.refresh()
	if _, err := w.view(); !strings.Contains(err, "isn't running") {
		t.Errorf("Error %q", err)
	}
}

// nilTB stands in for a testing.TB outside a test
type nilTB struct{ testing.TB }

func (nilTB) Fatal(args ...any) { panic(sprintf("%v", args...)) }

func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }
