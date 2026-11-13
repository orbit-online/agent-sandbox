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
	"github.com/orbit-online/agent-sandbox/internal/proc"
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
	Mdns        bool   `json:"mdns,omitempty"` // mDNS queries out and responses in (network.mdns)
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
	if n.Mdns {
		args = append(args, "--mdns")
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
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return fmt.Errorf("Open the sandbox: %w", err)
	}
	defer unix.Close(pidfd)
	ns, err := openNs(pid, pidfd)
	if err != nil {
		return err
	}
	defer closeNs(ns)
	ip := ipIn(n.Nsenter, n.IP, ns)
	ip.Stdin = strings.NewReader(ipBatch(addrs[0], addrs[1]))
	ip.Stdout, ip.Stderr = hostOut, hostOut
	if err := ip.Run(); err != nil {
		return fmt.Errorf("Address the sandbox: %w", err)
	}
	if err := sandboxRoutes(n.NetnsNetkit, n.Nsenter, n.IP, ns); err != nil {
		return err
	}
	slog.Info("Step", "step", stepNetwork)
	return nil
}

// ipBatch is what eth0 in the sandbox gets: its addresses and up (sandboxRoutes adds the default routes). No
// neighbours: netkit in L3 mode has no ARP
func ipBatch(v4, v6 string) string {
	return "link set lo up\n" +
		"addr add " + v4 + "/32 dev eth0\n" +
		"addr add " + v6 + "/128 dev eth0 nodad\n" +
		"link set eth0 up\n"
}

// defaultUplinks asks netns-netkit for the ifindexes of the uplinks with the default route of IPv4 and of IPv6, 0 for
// none, which only its group reads
func defaultUplinks(netnsNetkit string) ([2]int, error) {
	var ups [2]int
	out, err := exec.Command(netnsNetkit, "uplinks").Output()
	if err != nil {
		return ups, fmt.Errorf("Run netns-netkit uplinks: %w", err)
	}
	if _, err := fmt.Sscan(string(out), &ups[0], &ups[1]); err != nil {
		return ups, fmt.Errorf("Read netns-netkit uplinks %q: %w", out, err)
	}
	return ups, nil
}

// openNs opens the user and net namespaces of pid, the process of pidfd, which must still run after: a pid that was
// reused in between would name the namespaces of another process
func openNs(pid, pidfd int) ([]*os.File, error) {
	var ns []*os.File
	for _, kind := range []string{"user", "net"} {
		f, err := os.Open(fmt.Sprintf("/proc/%d/ns/%s", pid, kind))
		if err != nil {
			closeNs(ns)
			return nil, fmt.Errorf("Open the %s namespace of the sandbox: %w", kind, err)
		}
		ns = append(ns, f)
	}
	if !proc.Alive(pidfd) {
		closeNs(ns)
		return nil, errors.New("The sandbox exited")
	}
	return ns, nil
}

func closeNs(ns []*os.File) {
	for _, f := range ns {
		f.Close()
	}
}

// ipIn runs ip in ns (openNs) as the owner of the user namespace, which owns the netns. --keep-caps: exec would
// otherwise drop the caps setns granted
func ipIn(nsenter, ipTool string, ns []*os.File) *exec.Cmd {
	ip := exec.Command(nsenter, "--user=/proc/self/fd/3", "--net=/proc/self/fd/4", "--preserve-credentials", "--keep-caps",
		ipTool, "-batch", "-")
	ip.ExtraFiles = ns
	return ip
}

// sandboxRoutes gives eth0 in the netns of ns (openNs) a default route for each family the host has an uplink with a default
// route of, and none for the others: peer drops what no uplink takes, and with a default route there a connection to a
// dual-stack name would wait on IPv6, which glibc prefers, instead of failing over to IPv4 at once. As the owner of the
// user namespace of the sandbox: netns-netkit has no CAP_SYS_ADMIN to enter its netns
func sandboxRoutes(netnsNetkit, nsenter, ipTool string, ns []*os.File) error {
	ups, err := defaultUplinks(netnsNetkit)
	if err != nil {
		return err
	}
	var batch strings.Builder
	for i, dst := range []string{"0.0.0.0/0", "::/0"} {
		fmt.Fprintf(&batch, "route replace %s dev eth0\n", dst)
		// Replaced first, so the delete succeeds whether the route was there or not
		if ups[i] == 0 {
			fmt.Fprintf(&batch, "route del %s dev eth0\n", dst)
		}
	}
	ip := ipIn(nsenter, ipTool, ns)
	ip.Stdin = strings.NewReader(batch.String())
	if out, err := ip.CombinedOutput(); err != nil {
		return fmt.Errorf("Route the sandbox: %w: %s", err, out)
	}
	return nil
}
