package main

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/docopt/docopt-go"
	qt "github.com/mappu/miqt/qt6"
	"github.com/mappu/miqt/qt6/mainthread"
	"github.com/mappu/miqt/qt6/qml"
)

const usage = `permissions-window - The Permissions window of a sandbox's permissions broker

Usage:
  permissions-window --app-id=<id> <control-socket> [<title>]

A client of the broker's control.sock (docs/permissions.md): shows pending
requests to answer, what the configuration gives the sandbox (read-only), live
grants to revoke and the recent decisions, and refreshes on the broker's watch
events. Without a running broker it says so.

Options:
  --app-id=<id>  The window's Wayland app ID and X11 WM_CLASS: the sandbox's
                 app ID, so the window shows under its launcher's .desktop file
`

func main() {
	opts, err := docopt.ParseDoc(usage)
	if err != nil {
		slog.Error("Parse arguments", "err", err)
		os.Exit(2)
	}
	socket, _ := opts.String("<control-socket>")
	title, _ := opts.String("<title>")
	if title == "" {
		title = "Permissions"
	}
	// The package installs the QML in share/, beside the bin/ the binary runs from (its wrapper execs it there)
	exe, err := os.Executable()
	if err != nil {
		slog.Error("Find the executable", "err", err)
		os.Exit(1)
	}
	qmlPath := filepath.Join(filepath.Dir(exe), "../share/permissions-window/Main.qml")
	qt.NewQGuiApplication(os.Args)
	appID, _ := opts.String("--app-id")
	qt.QGuiApplication_SetDesktopFileName(appID)
	engine, _ := load(&window{socket: socket}, title, qmlPath, func(w string) { slog.Warn("QML", "warning", w) })
	if len(engine.RootObjects()) == 0 {
		slog.Error("The window didn't load")
		os.Exit(1)
	}
	os.Exit(qt.QGuiApplication_Exec())
}

// load shows w in the QML at path. The QML reads the property map brokerMap: state (the broker's state as JSON) and
// error, and writes its actions to command as JSON. Qt has no moc here to make a QObject with properties
// and slots, hence the map. QML warnings go to warn. Returns the engine and the map
func load(w *window, title, path string, warn func(string)) (*qml.QQmlApplicationEngine, *qml.QQmlPropertyMap) {
	broker := qml.NewQQmlPropertyMap()
	publish := func() {
		state, err := w.view()
		broker.Insert("state", qt.NewQVariant14(state))
		broker.Insert("error", qt.NewQVariant14(err))
	}
	// Calls to control.sock off the GUI thread, the map updated on it
	refresh := func() {
		go func() {
			w.refresh()
			mainthread.Start(publish)
		}()
	}
	broker.OnValueChanged(func(key string, value *qt.QVariant) {
		if key != "command" {
			return
		}
		cmd := value.ToString()
		go func() {
			w.do(cmd)
			mainthread.Start(publish)
		}()
	})
	publish()
	refresh()
	go w.watch(refresh, func() { mainthread.Start(publish) })

	engine := qml.NewQQmlApplicationEngine()
	engine.OnWarnings(func(warnings []qml.QQmlError) {
		for _, e := range warnings {
			warn(e.ToString())
		}
	})
	engine.RootContext().SetContextProperty("brokerMap", broker.QObject)
	engine.RootContext().SetContextProperty2("windowTitle", qt.NewQVariant14(title))
	engine.Load(qt.QUrl_FromLocalFile(path))
	return engine, broker
}
