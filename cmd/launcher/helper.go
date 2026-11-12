package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/orbit-online/agent-sandbox/internal/journal"
)

// The helper bwrap.go starts before it execs into bwrap, with bwrap's info pipe on fd 3, its user namespace's block
// pipe on fd 4 and, on the host, nixpak's info fd on 5. Unblocked without maps, bwrap's child would run as the
// overflow uid: when anything fails, it takes bwrap and the child down instead

// What the host sets up in the sandbox's netns, in nixpak's place of pasta (its slot is a no-op): the macvlan
// (netns-macvlan --help), its link up and the DHCP client in a mount namespace of its own (dhcp-root.sh), all before
// nixpak's launcher hears the sandbox is there and lets the app start
type netSetup struct {
	NetnsMacvlan string `json:"netnsMacvlan"`
	DHCPRoot     string `json:"dhcpRoot"`
	Nsenter      string `json:"nsenter"`
	Unshare      string `json:"unshare"`
	IP           string `json:"ip"`
	Name         string `json:"name,omitempty"` // The launcher's, which salts the macvlan's MAC; empty for the default one
}

// The host's units for the sandbox's daemons, in the launcher's slice and bound to the app's unit, so they stop with
// it and log to the journal as units of their own
type hostUnits struct {
	SystemdRun string `json:"systemdRun"`
	Systemctl  string `json:"systemctl"`
	App        string `json:"app"`    // The app's unit
	Prefix     string `json:"prefix"` // Their names', claude-desktop[-<name>]
	Slice      string `json:"slice"`
	SystemdCat string `json:"systemdCat"`
	Journal    string `json:"journal"` // The journal namespace they log to
}

// Stops the unit <prefix>-<name>, whatever it's doing
func (u *hostUnits) stop(name string) {
	_ = exec.Command(u.Systemctl, "--user", "stop", u.Prefix+"-"+name).Run()
}

// Starts the unit <prefix>-<name> running argv, logging as identifier, and returns once it started. Not After= the
// app's unit: that one is still starting, and waits for this
func (u *hostUnits) start(name, identifier string, props []string, argv ...string) error {
	args := []string{"--user", "--quiet", "--collect", "--unit=" + u.Prefix + "-" + name, "--slice=" + u.Slice,
		"-p", "BindsTo=" + u.App}
	for _, p := range props {
		args = append(args, "-p", p)
	}
	argv = journal.Wrap(u.SystemdCat, u.Journal, identifier, argv...)
	out, err := exec.Command(u.SystemdRun, append(append(args, "--"), argv...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Start %s-%s: %w: %s", u.Prefix, name, err, out)
	}
	return nil
}

var childPidRe = regexp.MustCompile(`"child-pid":\s*([0-9]+)`)

func runHelper(specJSON string) error {
	var spec helperSpec
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		return err
	}
	// Not for what the helper runs: udhcpc stays in the background, and holding nixpak's info fd it would keep nixpak's
	// launcher waiting for the info's end until it renews its lease
	for fd := 3; fd <= 5; fd++ {
		unix.CloseOnExec(fd)
	}
	info, block := os.NewFile(3, "info"), os.NewFile(4, "block")
	bwrapPid := os.Getppid()
	data, err := io.ReadAll(info)
	m := childPidRe.FindSubmatch(data)
	if err != nil || m == nil {
		syscall.Kill(bwrapPid, syscall.SIGKILL)
		return fmt.Errorf("No child pid from bwrap: %q", data)
	}
	pid, _ := strconv.Atoi(string(m[1]))
	if err := helperSteps(spec, data, pid, bwrapPid, block); err != nil {
		syscall.Kill(pid, syscall.SIGKILL)
		syscall.Kill(bwrapPid, syscall.SIGKILL)
		return err
	}
	return nil
}

func helperSteps(spec helperSpec, info []byte, pid, bwrapPid int, block *os.File) error {
	if spec.CgRoot != "" {
		for path, p := range map[string]int{"/supervisor/cgroup.procs": bwrapPid, "/sandbox/app/cgroup.procs": pid} {
			if err := os.WriteFile(spec.CgRoot+path, []byte(strconv.Itoa(p)), 0); err != nil {
				return err
			}
		}
		if len(spec.Ctl) > 0 {
			err := os.WriteFile(spec.CgRoot+"/sandbox/cgroup.subtree_control", []byte(strings.Join(spec.Ctl, " ")), 0)
			if err != nil {
				return err
			}
		}
	}
	for _, m := range []struct {
		tool string
		m    []int
	}{{spec.NewUIDMap, spec.UIDMap}, {spec.NewGIDMap, spec.GIDMap}} {
		cmd := exec.Command(m.tool, append([]string{strconv.Itoa(pid)}, mapArgs(m.m)...)...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", m.tool, err)
		}
	}
	if _, err := block.Write([]byte("\n")); err != nil {
		return err
	}
	if spec.Net != nil {
		if err := spec.Net.run(pid, spec.Units); err != nil {
			return err
		}
	}
	if spec.Forward {
		forward := os.NewFile(5, "forward")
		if _, err := forward.Write(info); err != nil {
			return err
		}
		forward.Close()
	}
	return nil
}

func (n *netSetup) run(pid int, u *hostUnits) error {
	// bwrap's parent reports the pid while the child is still building the mount tree; nixpak binds /.flatpak-info
	// last, so once it shows up the sandbox's root is final
	marker := fmt.Sprintf("/proc/%d/root/.flatpak-info", pid)
	for i := 0; ; i++ {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if i == 50 {
			return errors.New("Sandbox root not ready after 5s")
		}
		time.Sleep(100 * time.Millisecond)
	}
	args := []string{strconv.Itoa(pid)}
	if n.Name != "" {
		args = append(args, n.Name)
	}
	if err := runCmd(n.NetnsMacvlan, args...); err != nil {
		return err
	}
	// The sandbox's userns owns its netns. --keep-caps: exec would otherwise drop the caps setns granted
	ns := []string{"-t", strconv.Itoa(pid), "-U", "-n", "--preserve-credentials", "--keep-caps"}
	for _, link := range []string{"lo", "eth0"} {
		if err := runCmd(n.Nsenter, append(ns, n.IP, "link", "set", link, "up")...); err != nil {
			return err
		}
	}
	// udhcpc in a mount namespace of its own, made from the host's (see dhcp-root.sh), in the sandbox's pid ns so it
	// dies with it. It goes to the background once it has a lease or gives up, which ends the unit's start
	return u.start("dhcp", "udhcpc", []string{"Type=forking"},
		append(append([]string{n.Nsenter}, ns...), "-p", n.Unshare, "--mount", "--propagation", "private", n.DHCPRoot)...)
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}
