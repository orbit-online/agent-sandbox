package main

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/docopt/docopt-go"
	qt "github.com/mappu/miqt/qt6"
)

// Qt runs on the main thread, which the tests don't: the QML check runs in TestMain, before them
func init() { runtime.LockOSThread() }

var qmlErrors []string

func TestMain(m *testing.M) {
	os.Setenv("QT_QPA_PLATFORM", "offscreen")
	qmlErrors = qmlCheck()
	os.Exit(m.Run())
}

// The splash loads without QML warnings, through a start and a failure, the logos missing too
func qmlCheck() []string {
	qt.NewQGuiApplication([]string{"test"})
	var warnings []string
	opts := docopt.Opts{"--title": "Claude", "--logo": "", "--logo-dark": "", "--agent-logo": "", "--title-font": ""}
	engine, splash := load(opts, "Splash.qml", func(w string) { warnings = append(warnings, w) })
	if len(engine.RootObjects()) == 0 {
		return append(warnings, "The splash didn't load")
	}
	// Abort, once it shows, writes the command for the launcher
	root := engine.RootObjects()[0]
	var find func(o *qt.QObject, name string) *qt.QObject
	find = func(o *qt.QObject, name string) *qt.QObject {
		if o.ObjectName() == name {
			return o
		}
		for _, c := range o.Children() {
			if f := find(c, name); f != nil {
				return f
			}
		}
		return nil
	}
	root.SetProperty("canAbort", qt.NewQVariant8(true))
	qt.QCoreApplication_ProcessEvents()
	if abort := find(root, "abort"); abort == nil {
		warnings = append(warnings, "No Abort button")
	} else if !qt.QMetaObject_InvokeMethod4(abort, "click") {
		warnings = append(warnings, "Clicking Abort failed")
	}
	qt.QCoreApplication_ProcessEvents()
	if got := splash.Value("command").ToString(); got != "abort" {
		warnings = append(warnings, "Abort sent "+got)
	}
	if !root.Property("aborting").ToBool() {
		warnings = append(warnings, "Not aborting after the click")
	}
	st := newState()
	for _, line := range []string{`{"dark":true}`, `{"text":"Copying","progress":0.5}`, `{"error":"No","log":"a\nb"}`} {
		if err := st.apply([]byte(line)); err != nil {
			warnings = append(warnings, err.Error())
		}
		publish(splash, st)
		qt.QCoreApplication_ProcessEvents()
	}
	// An activation with the error up: the token where Qt's requestActivate looks, the window told
	os.Unsetenv("XDG_ACTIVATION_TOKEN")
	take(splash, st, []byte(`{"activate":"token-1"}`))
	qt.QCoreApplication_ProcessEvents()
	if got := os.Getenv("XDG_ACTIVATION_TOKEN"); got != "token-1" {
		warnings = append(warnings, "Activation token "+got)
	}
	if got := root.Property("activations").ToInt(); got != 1 {
		warnings = append(warnings, fmt.Sprintf("The window heard of %d activations", got))
	}
	return warnings
}

func TestQML(t *testing.T) {
	for _, e := range qmlErrors {
		t.Error(e)
	}
}

// A line sets what it names; a new step's progress is unknown until it says
func TestApply(t *testing.T) {
	s := newState()
	for _, line := range []string{`{"dark":true}`, `{"text":"Copying","progress":0.5}`, `{"progress":2}`} {
		if err := s.apply([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	if !s.Dark || s.Text != "Copying" || s.Progress != 1 {
		t.Errorf("State %+v", s)
	}
	if err := s.apply([]byte(`{"text":"Starting"}`)); err != nil || s.Progress != -1 || !s.Dark {
		t.Errorf("A new step: %+v, %v", s, err)
	}
	if err := s.apply([]byte(`{"activate":"t"}`)); err != nil || s.Token != "t" || s.Activations != 1 || s.Text != "Starting" {
		t.Errorf("An activation: %+v, %v", s, err)
	}
	if err := s.apply([]byte(`not json`)); err == nil {
		t.Error("Took a broken line")
	}
}
