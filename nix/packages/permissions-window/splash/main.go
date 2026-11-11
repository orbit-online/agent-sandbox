package main

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/docopt/docopt-go"
	qt "github.com/mappu/miqt/qt6"
	"github.com/mappu/miqt/qt6/mainthread"
	"github.com/mappu/miqt/qt6/qml"
)

const usage = `sandbox-splash - What a sandbox's launcher shows while the sandbox starts

Usage:
  sandbox-splash --app-id=<id> [--title=<title>] [--logo=<file>] [--logo-dark=<file>] [--agent-logo=<file>]
                 [--title-font=<file>]

Reads JSON lines on stdin, each setting what it names: dark (the desktop's
colour scheme), text (the step, with progress from 0 to 1 when known), error
and log (why the start failed and the app's last output). Closes when stdin
does, unless it shows an error: then when the user closes it. After 10 seconds
it offers Abort, which prints "abort" on stdout for the launcher.

Options:
  --app-id=<id>        The window's Wayland app ID: the sandbox's, so it shows
                       under its launcher's .desktop file
  --title=<title>      The window's title [default: Claude]
  --logo=<file>        The main logo, beside the agent's, on a light background
  --logo-dark=<file>   The main logo on a dark background [default: the --logo]
  --agent-logo=<file>  The agent's logo, smaller
  --title-font=<file>  The font of the "Agent Sandbox" title, a font file
`

func main() {
	opts, err := docopt.ParseDoc(usage)
	if err != nil {
		slog.Error("Parse arguments", "err", err)
		os.Exit(2)
	}
	exe, err := os.Executable()
	if err != nil {
		slog.Error("Find the executable", "err", err)
		os.Exit(1)
	}
	qmlPath := filepath.Join(filepath.Dir(exe), "../share/sandbox-splash/Splash.qml")
	qt.NewQGuiApplication(os.Args)
	appID, _ := opts.String("--app-id")
	qt.QGuiApplication_SetDesktopFileName(appID)
	engine, splash := load(opts, qmlPath, func(w string) { slog.Warn("QML", "warning", w) })
	if len(engine.RootObjects()) == 0 {
		slog.Error("The splash didn't load")
		os.Exit(1)
	}
	st := newState()
	go func() {
		in := bufio.NewScanner(os.Stdin)
		in.Buffer(make([]byte, 64<<10), 1<<20)
		for in.Scan() {
			line := append([]byte(nil), in.Bytes()...)
			mainthread.Start(func() {
				if err := st.apply(line); err != nil {
					slog.Warn("Splash", "err", err)
				}
				publish(splash, st)
			})
		}
		// The launcher closed it: the app is up, or the launcher ended. An error stays until the user closes it
		mainthread.Start(func() {
			if st.Error == "" {
				qt.QCoreApplication_Quit()
			}
		})
	}()
	os.Exit(qt.QGuiApplication_Exec())
}

// load shows the QML at path with the property map splash (see state) and the logos as context properties.
// QML warnings go to warn
func load(opts docopt.Opts, path string, warn func(string)) (*qml.QQmlApplicationEngine, *qml.QQmlPropertyMap) {
	splash := qml.NewQQmlPropertyMap()
	publish(splash, newState())
	// The QML writes command; abort goes to the launcher as a line on stdout
	splash.OnValueChanged(func(key string, value *qt.QVariant) {
		if key == "command" && value.ToString() == "abort" {
			fmt.Println("abort")
		}
	})
	engine := qml.NewQQmlApplicationEngine()
	engine.OnWarnings(func(warnings []qml.QQmlError) {
		for _, e := range warnings {
			warn(e.ToString())
		}
	})
	ctx := engine.RootContext()
	ctx.SetContextProperty("splash", splash.QObject)
	title, _ := opts.String("--title")
	logo, _ := opts.String("--logo")
	logoDark, _ := opts.String("--logo-dark")
	if logoDark == "" {
		logoDark = logo
	}
	agentLogo, _ := opts.String("--agent-logo")
	titleFont, _ := opts.String("--title-font")
	for name, v := range map[string]string{"windowTitle": title, "logo": fileURL(logo), "logoDark": fileURL(logoDark),
		"agentLogo": fileURL(agentLogo), "titleFont": fileURL(titleFont)} {
		ctx.SetContextProperty2(name, qt.NewQVariant14(v))
	}
	engine.Load(qt.QUrl_FromLocalFile(path))
	return engine, splash
}

func publish(m *qml.QQmlPropertyMap, s *state) {
	m.Insert("dark", qt.NewQVariant8(s.Dark))
	m.Insert("text", qt.NewQVariant14(s.Text))
	m.Insert("progress", qt.NewQVariant9(s.Progress))
	m.Insert("error", qt.NewQVariant14(s.Error))
	m.Insert("log", qt.NewQVariant14(s.Log))
}

func fileURL(path string) string {
	if path == "" {
		return ""
	}
	return qt.QUrl_FromLocalFile(path).ToString()
}
