package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/godbus/dbus/v5"
)

// supervise is the app's unit: it prepares the sandbox under a splash, runs nixpak's launcher, follows the desktop's
// colour scheme and tells systemd (Type=notify) once the app is up, or why it didn't start, which it leaves for start
// in the result file first. Its stdout and stderr are the unit's, the journal
func supervise(cfg *config, vars, args []string) error {
	sp := showSplash(cfg)
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		slog.Warn("No session bus", "err", err)
	} else {
		defer conn.Close()
		if s, err := readScheme(conn); err == nil {
			sp.dark(s == 1)
		}
	}
	if err := prepare(cfg, sp); err != nil {
		return failStart(cfg, sp, err.Error(), "")
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
	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() {
		defer pumps.Done()
		pump(stdout, os.Stdout, tail, func(line string) {
			if line == cfg.Ready {
				once.Do(func() { close(ready) })
			}
		})
	}()
	go func() {
		defer pumps.Done()
		pump(stderr, os.Stderr, tail, nil)
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
		showSplash(cfg).fail(fmt.Sprintf("Claude ended with an error (%s).", exit), tail.String())
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
			out, err := exec.Command(cfg.Tools.SystemdRun, "--user", "--quiet", "--collect", "--unit="+p.Unit,
				"--slice="+cfg.Slice, "-p", "Restart=on-failure", "-p", "StartLimitIntervalSec=10min",
				"-p", "StartLimitBurst=3", "-p", "ExecStopPost="+p.Broker+" cleanup "+p.Config, "--",
				p.Broker, "serve", p.Config).CombinedOutput()
			if err != nil {
				return fmt.Errorf("Start the permissions broker: %w: %s", err, out)
			}
		}
	}
	return nil
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
