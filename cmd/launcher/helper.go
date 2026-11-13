package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

// What the host sets up in the sandbox's netns, in nixpak's place of pasta (its slot is a no-op): the netkit pair
// (netns-netkit --help) and, as the owner of the sandbox's user namespace, its addresses and routes, all before nixpak's
// launcher hears the sandbox is there and lets the app start
type netSetup struct {
	NetnsNetkit string `json:"netnsNetkit"`
	Nsenter     string `json:"nsenter"`
	IP          string `json:"ip"`
	Name        string `json:"name,omitempty"` // The launcher's, which its addresses derive from; empty for the default one
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
	Journal    string `json:"journal"`        // The host side's journal namespace, subid-broker's
	Sandbox    string `json:"sandboxJournal"` // The sandbox's
}

// Stops the unit <prefix>-<name>, whatever it's doing
func (u *hostUnits) stop(name string) {
	_ = exec.Command(u.Systemctl, "--user", "stop", u.Prefix+"-"+name).Run()
}

// Starts the unit <prefix>-<name> running argv, logging to the journal namespace as identifier, and returns once it
// started. Not After= the app's unit: that one is still starting, and waits for this
func (u *hostUnits) start(name, namespace, identifier string, props []string, argv ...string) error {
	args := []string{"--user", "--quiet", "--collect", "--unit=" + u.Prefix + "-" + name, "--slice=" + u.Slice,
		"-p", "BindsTo=" + u.App}
	for _, p := range props {
		args = append(args, "-p", p)
	}
	argv = journal.Wrap(u.SystemdCat, namespace, identifier, argv...)
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
	// Not for what the helper runs: holding nixpak's info fd, it would keep nixpak's launcher waiting for the info's end
	for fd := 3; fd <= 5; fd++ {
		unix.CloseOnExec(fd)
	}
	if spec.Units != nil {
		hostLog(spec.Units)
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
		cmd.Stdout, cmd.Stderr = hostOut, hostOut
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", m.tool, err)
		}
	}
	if _, err := block.Write([]byte("\n")); err != nil {
		return err
	}
	// The host's: the FHS env's bwrap inside runs this helper too
	if spec.Units != nil {
		slog.Info("Step", "step", stepSandbox)
	}
	if spec.Net != nil {
		if err := spec.Net.run(pid); err != nil {
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

func (n *netSetup) run(pid int) error {
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
	args := []string{"up", strconv.Itoa(pid)}
	if n.Name != "" {
		args = append(args, "--name="+n.Name)
	}
	cmd := exec.Command(n.NetnsNetkit, args...)
	cmd.Stderr = hostOut
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("%s: %w", n.NetnsNetkit, err)
	}
	addrs := strings.Fields(string(out))
	if len(addrs) != 2 {
		return fmt.Errorf("%s: addresses %q", n.NetnsNetkit, out)
	}
	// The sandbox's userns owns its netns. --keep-caps: exec would otherwise drop the caps setns granted
	ip := exec.Command(n.Nsenter, "-t", strconv.Itoa(pid), "-U", "-n", "--preserve-credentials", "--keep-caps", n.IP, "-batch", "-")
	ip.Stdin = strings.NewReader(ipBatch(addrs[0], addrs[1]))
	ip.Stdout, ip.Stderr = hostOut, hostOut
	if err := ip.Run(); err != nil {
		return fmt.Errorf("Address the sandbox: %w", err)
	}
	slog.Info("Step", "step", stepNetwork)
	return nil
}

// ipBatch is what eth0 in the sandbox gets: its addresses, up, and the default routes through it. No neighbours: netkit
// in L3 mode has no ARP
func ipBatch(v4, v6 string) string {
	return "link set lo up\n" +
		"addr add " + v4 + "/32 dev eth0\n" +
		"addr add " + v6 + "/128 dev eth0 nodad\n" +
		"link set eth0 up\n" +
		"route add default dev eth0\n" +
		"route add ::/0 dev eth0\n"
}
