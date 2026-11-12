package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/godbus/dbus/v5"

	"github.com/orbit-online/agent-sandbox/internal/journal"
)

// supervise is the app's unit: it prepares the sandbox under a splash, runs nixpak's launcher, follows the desktop's
// colour scheme and tells systemd (Type=notify) once the app is up, or why it didn't start, which it leaves for start
// in the result file first. Its stdout and stderr are the unit's, the journal
func supervise(cfg *config, vars, args []string) error {
	// A launch while the unit runs without a sandbox asks for the splash at the front (activateUnit). First, as
	// SIGUSR1 ends the process until it's caught
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)
	defer signal.Stop(usr1)
	var shown atomic.Pointer[splash]
	sp := showSplash(cfg)
	shown.Store(sp)
	go func() {
		for range usr1 {
			activate(cfg, shown.Load())
		}
	}()
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		slog.Warn("No session bus", "err", err)
	} else {
		defer conn.Close()
		if s, err := readScheme(conn); err == nil {
			sp.dark(s == 1)
		}
	}
	prepared := make(chan error, 1)
	go func() { prepared <- prepare(cfg, sp) }()
	select {
	case err := <-prepared:
		if err != nil {
			return failStart(cfg, sp, err.Error(), "")
		}
	case <-sp.aborted:
		// What prepare still runs ends with the unit; a store sync cut off goes on at the next start (store.go)
		return abortStart(cfg, sp, nil)
	}
	// The GTK theme, now and on every change, until the app ends
	if conn != nil {
		if err := watchScheme(conn, func(s uint32) {
			sp.dark(s == 1)
			if err := applyScheme(cfg, strconv.Itoa(int(s))); err != nil {
				slog.Warn("GTK theme", "err", err)
			}
		}); err != nil {
			slog.Warn("No colour scheme from the portal", "err", err)
		}
	}

	sp.step("Starting the app", nil)
	cmd := exec.Command(cfg.NixpakLauncher, append([]string{"--password-store=basic"}, args...)...)
	// nixpak's sloth.env panics on unset variables, so it gets the sandbox's environment the wrapper filtered
	cmd.Env = vars
	tail := &tail{max: 64 << 10}
	ready := make(chan struct{})
	var once sync.Once
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return failStart(cfg, sp, fmt.Sprintf("Start nixpak's launcher: %v", err), "")
	}
	out, endLog := appLog(cfg)
	defer endLog()
	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() {
		defer pumps.Done()
		pump(stdout, out, tail, func(line string) {
			if line == cfg.Ready {
				once.Do(func() { close(ready) })
			}
		})
	}()
	go func() {
		defer pumps.Done()
		pump(stderr, out, tail, nil)
	}()
	exited := make(chan struct{})
	go func() {
		pumps.Wait()
		close(exited)
	}()
	select {
	case <-ready:
		sp.close()
		daemon.SdNotify(false, daemon.SdNotifyReady)
	case <-exited:
	case <-sp.aborted:
		return abortStart(cfg, sp, cmd)
	}
	<-exited
	err = cmd.Wait()
	var exit *exec.ExitError
	if err == nil {
		return nil
	}
	if !errors.As(err, &exit) {
		return err
	}
	code := exit.ExitCode()
	select {
	case <-ready:
		// It ran: the error window on its own, as the app's
		slog.Error("The app ended", "status", exit)
		failed := showSplash(cfg)
		shown.Store(failed)
		failed.fail(fmt.Sprintf("Claude ended with an error (%s).", exit), tail.String())
	default:
		failStart(cfg, sp, fmt.Sprintf("The app didn't start (%s).", exit), tail.String())
	}
	if code <= 0 {
		code = 1
	}
	return exitError(code)
}

// prepare readies the sandbox's state where a refusal reaches the caller, before nixpak's launcher runs
func prepare(cfg *config, sp *splash) error {
	sp.step("Preparing the sandbox", nil)
	// The sandbox can write its home and plant links there, so the files it expects (resolv.conf, user-dirs.dirs, the
	// app's config) are written confined, see confine.sh. The directories themselves are bind sources, on paths it
	// can't write
	for _, d := range cfg.HomeDirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	// Bind source for Claude Code's temp dir, which it wants private. Its parent, the state dir, exists from the home's
	// mkdir
	if err := os.Mkdir(cfg.Scratchpad, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	state := exec.Command(cfg.State, append(append([]string{}, cfg.HomeDirs...), "--", "home")...)
	if out, err := state.CombinedOutput(); err != nil {
		return fmt.Errorf("Prepare the sandbox's home: %w: %s", err, out)
	}
	sp.step("Copying the sandbox's programs", nil)
	if err := syncStore(cfg, func(f float64) { sp.step("Copying the sandbox's programs", &f) }); err != nil {
		return err
	}
	// nixpak binds the closure from the host store, where a GC would empty it under the running sandbox once a rebuild
	// dropped its generation. The runtime dir goes at logout, the next launch replaces the root
	runtime := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "claude-desktop")
	if err := os.MkdirAll(runtime, 0o700); err != nil {
		return err
	}
	root := exec.Command(cfg.Tools.NixStore, "--add-root", filepath.Join(runtime, cfg.StoreRootsLink), "--realise",
		cfg.StoreRoots)
	if out, err := root.CombinedOutput(); err != nil {
		return fmt.Errorf("Root the sandbox closure: %w: %s", err, out)
	}
	// nixpak only passes bwrap the --*-bind-try variants, which skip a missing source
	for _, src := range cfg.RequiredBinds {
		if _, err := os.Stat(src); err != nil {
			return fmt.Errorf("Bind source %s is missing", src)
		}
	}
	if p := cfg.Permissions; p != nil {
		// The permissions broker, a unit of its own that finds the sandbox once it runs (docs/permissions.md)
		if err := os.MkdirAll(filepath.Join(runtime, p.Dir), 0o700); err != nil {
			return err
		}
		if exec.Command(cfg.Tools.Systemctl, "--user", "-q", "is-active", p.Unit).Run() != nil {
			// ExecStopPost ends its grants when it stops, a crash included: service units are bound to it, folder
			// grants are detached. It fails when it finds no sandbox within a minute: the start limit ends the restarts
			// then
			args := append([]string{"--user", "--quiet", "--collect", "--unit=" + p.Unit, "--slice=" + cfg.Slice,
				"-p", "Restart=on-failure", "-p", "StartLimitIntervalSec=10min", "-p", "StartLimitBurst=3",
				"-p", "ExecStopPost=" + p.Broker + " cleanup " + p.Config, "--"},
				journal.Wrap(cfg.Tools.SystemdCat, cfg.Journal, "permissions-broker", p.Broker, "serve", p.Config)...)
			out, err := exec.Command(cfg.Tools.SystemdRun, args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("Start the permissions broker: %w: %s", err, out)
			}
		}
	}
	return nil
}

// Aborting the start takes at least this long to show, so the click is seen to do something; nixpak's launcher gets
// abortGrace after SIGTERM before SIGKILL
const (
	abortShown = time.Second
	abortGrace = 5 * time.Second
)

// abortStart ends a start the user aborted from the splash, which says so already: nixpak's launcher, when it runs,
// stopped and waited for (its process, not its output: what it started may hold that until the unit ends), the result
// left for start, systemd told. Exiting ends the unit, and the rest of its cgroup with it
func abortStart(cfg *config, sp *splash, cmd *exec.Cmd) error {
	shown := time.After(abortShown)
	slog.Info("Startup aborted from the splash")
	if cmd != nil {
		done := make(chan struct{})
		go func() {
			cmd.Wait()
			close(done)
		}()
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(abortGrace):
			cmd.Process.Kill()
			<-done
		}
	}
	<-shown
	if err := os.WriteFile(resultFile(cfg), []byte("Startup aborted\n"), 0o600); err != nil {
		slog.Error("Write the result file", "err", err)
	}
	daemon.SdNotify(false, daemon.SdNotifyReady)
	sp.close()
	return exitError(1)
}

// failStart leaves why the app didn't start for start, tells systemd, and shows it until the user closes the splash
func failStart(cfg *config, sp *splash, msg, log string) error {
	fmt.Fprintf(os.Stderr, "%s: %s\n", progName(cfg), msg)
	if err := os.WriteFile(resultFile(cfg), []byte(msg+"\n"), 0o600); err != nil {
		slog.Error("Write the result file", "err", err)
	}
	daemon.SdNotify(false, daemon.SdNotifyReady)
	sp.fail(msg, log)
	return exitError(1)
}

// activate hands the token a launch left to sp, which brings its window to the front with it
func activate(cfg *config, sp *splash) {
	token, err := os.ReadFile(activationFile(cfg))
	os.Remove(activationFile(cfg))
	if err != nil || len(token) == 0 {
		slog.Warn("Asked to bring the splash to the front without a token", "err", err)
		return
	}
	sp.send(splashState{Activate: string(token)})
}

// appLog is where nixpak's launcher's output goes, the app's among it: the sandbox's journal namespace, which the app
// can write to anyway, so a flood of it can't push the host side's entries out of theirs (models/journal.als). Its
// own stdout and stderr when systemd-cat doesn't start. end closes it and waits for systemd-cat
func appLog(cfg *config) (w io.Writer, end func()) {
	if cfg.SandboxJournal == "" {
		return os.Stderr, func() {}
	}
	cat := exec.Command(cfg.Tools.SystemdCat, "--namespace="+cfg.SandboxJournal, "--identifier="+progName(cfg))
	in, err := cat.StdinPipe()
	if err == nil {
		err = cat.Start()
	}
	if err != nil {
		slog.Warn("The app's output goes to the launcher's journal", "err", err)
		return os.Stderr, func() {}
	}
	return &lockedWriter{w: in}, func() {
		in.Close()
		cat.Wait()
	}
}

// Both pumps write whole lines to it, longer than a pipe takes in one write
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

// pump copies r to w line by line, keeping the lines in tail and handing each to line
func pump(r io.Reader, w io.Writer, tail *tail, line func(string)) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64<<10), 1<<20)
	for s.Scan() {
		t := s.Text()
		fmt.Fprintln(w, t)
		tail.add(t)
		if line != nil {
			line(t)
		}
	}
	// A line past the buffer: the rest still goes through, unsplit
	io.Copy(w, r)
}

// tail keeps the last max bytes of lines
type tail struct {
	mu    sync.Mutex
	max   int
	lines []string
	size  int
}

func (t *tail) add(line string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lines = append(t.lines, line)
	t.size += len(line) + 1
	for t.size > t.max && len(t.lines) > 1 {
		t.size -= len(t.lines[0]) + 1
		t.lines = t.lines[1:]
	}
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.Join(t.lines, "\n")
}
