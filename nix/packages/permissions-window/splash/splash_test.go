package main

import (
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
	st := newState()
	for _, line := range []string{`{"dark":true}`, `{"text":"Copying","progress":0.5}`, `{"error":"No","log":"a\nb"}`} {
		if err := st.apply([]byte(line)); err != nil {
			warnings = append(warnings, err.Error())
		}
		publish(splash, st)
		qt.QCoreApplication_ProcessEvents()
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
	if err := s.apply([]byte(`not json`)); err == nil {
		t.Error("Took a broken line")
	}
}
