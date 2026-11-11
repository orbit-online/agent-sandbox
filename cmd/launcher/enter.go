package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/orbit-online/agent-sandbox/internal/sandbox"
)

// start is the launcher the user runs: the Permissions window, a shell in the sandbox, a re-entry into the running
// app, or the app's unit started
func start(cfg *config, cfgPath string, vars, args []string) error {
	first := ""
	if len(args) > 0 {
		first = args[0]
	}
	switch first {
	case "--permissions":
		// On the host, ahead of the running sandbox's lookup, which would hand the flag to the app
		if cfg.Permissions == nil {
			return errors.New("This launcher has no permissions broker")
		}
		argv := make([]string, len(cfg.Permissions.Window))
		for i, a := range cfg.Permissions.Window {
			argv[i] = os.ExpandEnv(a)
		}
		return syscall.Exec(argv[0], argv, os.Environ())
	case "--shell":
		return shell(cfg, cfgPath, vars)
	}
	if app, running, err := runningApp(cfg, 30); running {
		if err != nil {
			return err
		}
		// Joins the app's namespaces, its pid ns included, so Electron's single-instance lock finds the first instance
		// and checks its pid where it lives. /init is the FHS env's, which the FHS env's bwrap would otherwise run
		return enter(cfg, app, vars, append([]string{"/init", "--password-store=basic"}, args...))
	}
	return startUnit(cfg, cfgPath, vars, args)
}

// shell runs a login shell where the app runs, so it gets the Code tab's environment, starting the app first if need
// be. The .desktop file's terminal action
func shell(cfg *config, cfgPath string, vars []string) error {
	app, running, err := runningApp(cfg, 30)
	if !running {
		fmt.Println("Starting Claude")
		if err := startUnit(cfg, cfgPath, vars, nil); err != nil {
			return err
		}
		app, _, err = runningApp(cfg, 30)
	}
	if err != nil {
		return err
	}
	// The terminal's. Ghostty points TERMINFO at its own entry, which the sandbox's store lacks: xterm-256color then
	for _, v := range []string{"TERM", "TERMINFO", "COLORTERM"} {
		if val := os.Getenv(v); val != "" {
			vars = append(vars, v+"="+val)
		}
	}
	return enter(cfg, app, vars, []string{"/bin/sh", "-c",
		`[ -z "${TERMINFO-}" ] || [ -d "$TERMINFO" ] || { TERM=xterm-256color; unset TERMINFO; }; exec "$SHELL" -l`})
}

// runningApp finds the app's main process (sandbox.AppPid) in the running sandbox, waiting up to tries seconds for it.
// running is false when no sandbox runs
func runningApp(cfg *config, tries int) (app int, running bool, err error) {
	runtime := os.Getenv("XDG_RUNTIME_DIR")
	for i := range tries {
		pid, fd, ferr := sandbox.Find(runtime, cfg.AppID)
		if ferr != nil {
			if i == 0 {
				return 0, false, nil
			}
		} else {
			app, err = sandbox.AppPid(pid, cfg.AppPid)
			unix.Close(fd)
			if err == nil || errors.Is(err, sandbox.ErrAmbiguous) {
				return app, true, err
			}
		}
		time.Sleep(time.Second)
	}
	if err == nil {
		err = errors.New("The running sandbox has no app")
	}
	return 0, true, err
}

// enter joins the app's cgroup, then its namespaces, as cmd with the sandbox's environment. It stays the caller's
// child, on its terminal, in the sandbox's cgroup namespace's subtree, so cgrun works there. Not nsenter -a: that also
// joins the time ns, still the host's, which needs CAP_SYS_ADMIN in the init userns. no_new_privs first, on the host,
// as bwrap sets it for everything inside: nsenter holds every capability in U2 until it execs a path the sandbox
// controls, whose file capabilities would otherwise count
func enter(cfg *config, app int, vars, cmd []string) error {
	if err := joinCgroup(cfg); err != nil {
		return err
	}
	env := append(vars, "DBUS_SESSION_BUS_ADDRESS=unix:path="+os.Getenv("XDG_RUNTIME_DIR")+"/nixpak-bus")
	argv := append([]string{cfg.Tools.Setpriv, "--no-new-privs", cfg.Tools.Nsenter, "-U", "-m", "-p", "-n", "-i", "-u",
		"-C", "-r", "-w", "--preserve-credentials", "-t", strconv.Itoa(app)}, cmd...)
	return syscall.Exec(argv[0], argv, env)
}

// joinCgroup moves the launcher into the app's cgroup, sandbox/app/ in the app's unit (see bwrap-subid.sh)
func joinCgroup(cfg *config) error {
	out, err := exec.Command(cfg.Tools.Systemctl, "--user", "show", "-P", "ControlGroup", cfg.Unit).Output()
	cg := strings.TrimSpace(string(out))
	if err == nil && cg != "" {
		err = os.WriteFile(filepath.Join("/sys/fs/cgroup", cg, "sandbox/app/cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0)
	}
	if err != nil || cg == "" {
		return fmt.Errorf("The running sandbox isn't in %s's cgroups: quit the app and start it again", cfg.Unit)
	}
	return nil
}

// Variables systemd sets per unit and the shell's own, which the app's unit doesn't take from the caller
var unitOwn = []string{"INVOCATION_ID", "JOURNAL_STREAM", "SYSTEMD_EXEC_PID", "MANAGERPID", "MAINPID", "NOTIFY_SOCKET",
	"LISTEN_*", "WATCHDOG_*", "MEMORY_PRESSURE_*", "TRIGGER_*", "MONITOR_*", "EXIT_*", "SERVICE_RESULT", "PIDFILE",
	"SHLVL", "PWD", "OLDPWD", "_"}

// startUnit starts the app's unit, supervise, with the caller's environment, not only the user manager's, and the
// sandbox's the wrapper expanded from it. The unit outlives the caller's terminal or the desktop's app scope. Its cgroup is
// delegated, so the sandbox can run jobs in cgroups of their own (cgrun); its processes start in supervisor/, the
// cgroup root holds none. With Delegate=, OOMPolicy= defaults to continue: an OOM kill below it ends the process the
// kernel picked, not the unit. Type=notify: systemd-run returns once supervise says the app is up or why it isn't,
// which it leaves in the result file first; a store sync may take a while, hence no start timeout
func startUnit(cfg *config, cfgPath string, vars, args []string) error {
	result := resultFile(cfg)
	if err := os.MkdirAll(filepath.Dir(result), 0o700); err != nil {
		return err
	}
	if running, err := activateUnit(cfg); running {
		return err
	}
	if err := os.Remove(result); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// The sandbox's environment for the unit's supervise, which deletes it once read
	varsFile := filepath.Join(filepath.Dir(result), cfg.Unit+".vars")
	if err := os.WriteFile(varsFile, []byte(strings.Join(vars, "\x00")), 0o600); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	argv := []string{cfg.Tools.SystemdRun, "--user", "--quiet", "--collect", "--unit=" + cfg.Unit, "--slice=" + cfg.Slice,
		"-p", "Delegate=yes", "-p", "DelegateSubgroup=supervisor", "-p", "Type=notify", "-p", "TimeoutStartSec=infinity"}
	for _, kv := range os.Environ() {
		if !unitOwnVar(strings.SplitN(kv, "=", 2)[0]) {
			argv = append(argv, "--setenv="+kv)
		}
	}
	argv = append(append(argv, "--", self, "supervise", "--config="+cfgPath, "--vars-file="+varsFile, "--"), args...)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	// Ctrl-C, or the terminal going away, while the app starts stops its unit: the whole start, as the splash's Abort
	// does. Once it's up, this has returned
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	go func() {
		if _, ok := <-signals; ok {
			exec.Command(cfg.Tools.Systemctl, "--user", "stop", cfg.Unit).Run()
			fmt.Fprintf(os.Stderr, "%s: Startup aborted\n", progName(cfg))
			os.Exit(130)
		}
	}()
	runErr := cmd.Run()
	if msg, err := os.ReadFile(result); err == nil && len(msg) > 0 {
		fmt.Fprintf(os.Stderr, "%s: %s\n", progName(cfg), strings.TrimSpace(string(msg)))
		return exitError(1)
	}
	if runErr != nil {
		return fmt.Errorf("The app didn't start, see journalctl --user -u %s", cfg.Unit)
	}
	return nil
}

// activateUnit brings the splash of the app's unit to the front when the unit runs without a sandbox: it starts, or it
// shows why the start failed or the app ended. The caller's activation token goes to supervise in a file, which
// SIGUSR1 tells it to read. Without one, as from a terminal, it says so instead. running is false when the unit
// doesn't run, or systemctl fails and systemd-run will say what's wrong
func activateUnit(cfg *config) (running bool, err error) {
	out, _ := exec.Command(cfg.Tools.Systemctl, "--user", "show", "-P", "ActiveState", cfg.Unit).Output()
	switch strings.TrimSpace(string(out)) {
	case "", "inactive", "failed":
		return false, nil
	}
	token := os.Getenv("XDG_ACTIVATION_TOKEN")
	if token == "" {
		return true, errors.New("The app is starting, or its window shows why it didn't start or ended: switch to that window")
	}
	if err := os.WriteFile(activationFile(cfg), []byte(token), 0o600); err != nil {
		return true, err
	}
	if out, err := exec.Command(cfg.Tools.Systemctl, "--user", "kill", "--kill-whom=main", "--signal=SIGUSR1",
		cfg.Unit).CombinedOutput(); err != nil {
		return true, fmt.Errorf("Bring %s's window to the front: %w: %s", cfg.Unit, err, out)
	}
	return true, nil
}

// activationFile is where start leaves its activation token for supervise, next to the result file
func activationFile(cfg *config) string {
	return filepath.Join(filepath.Dir(resultFile(cfg)), cfg.Unit+".activate")
}

func unitOwnVar(name string) bool {
	for _, v := range unitOwn {
		if p, ok := strings.CutSuffix(v, "*"); ok && strings.HasPrefix(name, p) || v == name {
			return true
		}
	}
	return false
}

// resultFile is where supervise leaves why the app didn't start, for startUnit to tell the caller. The runtime dir's
// claude-desktop/, which no sandbox reaches
func resultFile(cfg *config) string {
	return filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "claude-desktop", cfg.Unit+".error")
}
