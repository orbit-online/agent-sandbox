package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// bwrap for the sandbox: maps a range of ids into bwrap's user namespace through newuidmap and newgidmap, which bwrap
// can't do itself (unprivileged, it only writes one-id maps). It execs into bwrap, after starting itself as a helper
// (helper.go) that writes the maps once bwrap made the namespace, and on the host lays out the cgroups and sets up the
// network before it passes bwrap's info on to nixpak's launcher.
// Mode subid, nixpak's bwrap on the host: the user's /etc/subuid and /etc/subgid range, inner id x is host start+x
//   except the user's own uid and gid, which stay themselves. Starts subid-broker, whose socket the sandbox gets at
//   /run/subid-broker.sock.
// Mode parent, the FHS env's bwrap inside: every id of the parent user namespace as itself, through the broker's
//   shims, and /etc/subuid and /etc/subgid listing those ids minus the user's own for rootless tools (on fds 22 and 23).

// The fds bwrap gets for its info and the user namespace's block, from 20 up: nixpak's launcher passes 3 and 4
const (
	bwrapInfoFd  = 20
	bwrapBlockFd = 21
)

type bwrapOpts struct {
	mode, bwrap, newuidmap, newgidmap, subidBroker, permissionsBroker string
	net                                                               *netSetup
}

// What the helper does, as its argument
type helperSpec struct {
	NewUIDMap string    `json:"newuidmap"`
	NewGIDMap string    `json:"newgidmap"`
	UIDMap    []int     `json:"uidMap"`
	GIDMap    []int     `json:"gidMap"`
	CgRoot    string    `json:"cgRoot,omitempty"` // The app's unit's cgroup, on the host
	Ctl       []string  `json:"ctl,omitempty"`    // The controllers for sandbox/
	Forward   bool      `json:"forward"`          // Whether fd 5 is nixpak's info fd, to pass the info on to
	Net       *netSetup `json:"net,omitempty"`
}

func runBwrap(o bwrapOpts, args []string) error {
	// subid-broker's death signal is armed against the thread that forked it, and execve ends every other thread:
	// forked from any thread but the one that execs into bwrap, it would die at once. So this goroutine keeps one
	// thread, which forks the broker and the helper and execs
	runtime.LockOSThread()
	uid, gid := os.Getuid(), os.Getgid()
	u, err := user.Current()
	if err != nil {
		return err
	}
	spec := helperSpec{NewUIDMap: o.newuidmap, NewGIDMap: o.newgidmap}
	var forward *os.File
	var pass []string
	switch o.mode {
	case "subid":
		// nixpak's launcher puts --info-fd first for the app; its D-Bus proxy runs in a plain bwrap
		if len(args) == 0 || args[0] != "--info-fd" {
			return syscall.Exec(o.bwrap, append([]string{o.bwrap}, args...), os.Environ())
		}
		if spec.UIDMap, err = readSubid("/etc/subuid", u.Username, uid); err == nil {
			spec.GIDMap, err = readSubid("/etc/subgid", u.Username, gid)
		}
		if err != nil {
			return fmt.Errorf("%w in /etc/subuid and /etc/subgid", err)
		}
		// nixpak's options, up to the --: its --info-fd is ours to forward, --unshare-user-try becomes --unshare-user
		rest := []string{}
		for i := 0; i < len(args); i++ {
			if args[i] == "--" {
				rest = args[i:]
				break
			}
			switch args[i] {
			case "--unshare-user-try":
			case "--info-fd":
				fd, err := strconv.Atoi(args[i+1])
				if err != nil {
					return fmt.Errorf("--info-fd %q", args[i+1])
				}
				// Not for bwrap, nor the broker: the caller reads it to EOF
				unix.CloseOnExec(fd)
				forward = os.NewFile(uintptr(fd), "info")
				spec.Forward = true
				i++
			default:
				pass = append(pass, args[i])
			}
		}
		sock, err := startSubidBroker(o.subidBroker)
		if err != nil {
			return err
		}
		pass = append(pass, "--bind", sock, "/run/subid-broker.sock")
		cgBind, err := layOutCgroups(&spec)
		if err != nil {
			return err
		}
		pass = append(append(pass, cgBind, spec.CgRoot+"/sandbox", "/sys/fs/cgroup"), rest...)
		spec.Net = o.net
	case "parent":
		if err := parentMaps(&spec, u.Username, uid, gid); err != nil {
			return err
		}
		pass = args
		// With the permissions broker, its grant directory turns shared here, before this bwrap copies the mount
		// namespace, so grants mounted there later reach the app (docs/permissions.md)
		if fi, err := os.Stat("/run/permissions"); err == nil && fi.IsDir() {
			if err := exec.Command(o.permissionsBroker, "share").Run(); err != nil {
				fmt.Fprintln(os.Stderr, "claude-desktop: No folder grants: the permissions broker didn't share /run/permissions")
			}
		}
	default:
		return fmt.Errorf("Unknown mode %s", o.mode)
	}
	return execBwrap(o.bwrap, spec, forward, pass)
}

// execBwrap starts the helper with bwrap's info and block pipes, then execs into bwrap
func execBwrap(bwrap string, spec helperSpec, forward *os.File, args []string) error {
	infoR, infoW, err := os.Pipe()
	if err != nil {
		return err
	}
	blockR, blockW, err := os.Pipe()
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	js, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	helper := exec.Command(self, "bwrap-helper", string(js))
	helper.Stdout, helper.Stderr = os.Stdout, os.Stderr
	helper.ExtraFiles = []*os.File{infoR, blockW}
	if forward != nil {
		helper.ExtraFiles = append(helper.ExtraFiles, forward)
	}
	if err := helper.Start(); err != nil {
		return fmt.Errorf("Start the helper: %w", err)
	}
	infoR.Close()
	blockW.Close()
	if forward != nil {
		forward.Close()
	}
	// Where the child's cgroup namespace is rooted, see layOutCgroups
	if spec.CgRoot != "" {
		if err := os.WriteFile(spec.CgRoot+"/sandbox/cgroup.procs", []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
			return err
		}
	}
	// Without close-on-exec at their fixed numbers, for bwrap
	if err := unix.Dup2(int(infoW.Fd()), bwrapInfoFd); err != nil {
		return err
	}
	if err := unix.Dup2(int(blockR.Fd()), bwrapBlockFd); err != nil {
		return err
	}
	argv := append([]string{bwrap, "--unshare-user", "--info-fd", strconv.Itoa(bwrapInfoFd), "--userns-block-fd",
		strconv.Itoa(bwrapBlockFd)}, args...)
	return syscall.Exec(bwrap, argv, os.Environ())
}

func readSubid(path, user string, own int) ([]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return subidMap(f, user, own)
}

// startSubidBroker starts subid-broker on a socket of this process, which becomes bwrap. Its parent death signal fires
// when bwrap exits; it ends at once if this process is gone by then
func startSubidBroker(broker string) (string, error) {
	sock := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "claude-desktop", fmt.Sprintf("subid-broker-%d.sock", os.Getpid()))
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		return "", err
	}
	cmd := exec.Command(broker, sock, strconv.Itoa(os.Getpid()))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("Start subid-broker: %w", err)
	}
	for range 50 {
		if fi, err := os.Stat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return sock, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", errors.New("subid-broker didn't start")
}

// parentMaps maps the parent user namespace as itself, and puts the subuid and subgid lines on fds 22 and 23: the FHS
// env's /etc comes from its rootfs and a fixed list of host entries, so these go in as data, which the module's
// extraBwrapArgs bind after the FHS env's /etc tmpfs
func parentMaps(spec *helperSpec, user string, uid, gid int) error {
	for _, m := range []struct {
		path string
		into *[]int
		own  int
		fd   int
	}{{"/proc/self/uid_map", &spec.UIDMap, uid, 22}, {"/proc/self/gid_map", &spec.GIDMap, gid, 23}} {
		f, err := os.Open(m.path)
		if err != nil {
			return err
		}
		*m.into, err = identityMap(f)
		f.Close()
		if err != nil {
			return err
		}
		if err := dataFd(subidLines(*m.into, user, m.own), m.fd); err != nil {
			return err
		}
	}
	return nil
}

// dataFd puts data on a pipe at fd, without close-on-exec, for bwrap's --ro-bind-data. It fits the pipe's buffer
func dataFd(data string, fd int) error {
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	if _, err := w.WriteString(data); err != nil {
		return err
	}
	w.Close()
	defer r.Close()
	return unix.Dup2(int(r.Fd()), fd)
}

// layOutCgroups prepares the sandbox's cgroups below the app's unit's (Delegate=yes), which systemd started in
// supervisor/ (DelegateSubgroup=), where this process and nixpak's launcher stay, and returns how the sandbox's
// cgroup is bound. The sandbox gets sandbox/, the root of its cgroup namespace, with its processes in sandbox/app/:
// bwrap's parent sits in sandbox/ while it clones the child, whose new cgroup namespace is rooted where its parent
// is, then the helper moves the parent back to supervisor/ and the child, still blocked, into app/. sandbox/ holds no
// process, so controllers can be enabled for its children (cgrun), and the kernel's nsdelegate keeps the sandbox from
// writing its root's files (memory.max, cgroup.max.*) or moving a process out of it. It sees sandbox/ alone at
// /sys/fs/cgroup. nsdelegate guards only the root of the writer's own cgroup namespace: from a nested one, rooted at
// app/, the sandbox writes sandbox/'s files. So the caps on its cgroups go on the unit's cgroup, which it has no path to
func layOutCgroups(spec *helperSpec) (string, error) {
	// cgroup v2 alone: one line, 0::PATH
	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	cg := strings.TrimPrefix(strings.TrimSpace(string(self)), "0::")
	parent, ok := strings.CutSuffix(cg, "/supervisor")
	if !ok {
		return "", fmt.Errorf("Not in the app's unit's supervisor cgroup but in %s", cg)
	}
	spec.CgRoot = "/sys/fs/cgroup" + parent
	// Without end, the sandbox's cgroups would cost the kernel memory without end: 64 below sandbox/, app/ included, 4
	// deep, which are 66 and 5 from the unit's cgroup (supervisor/ and sandbox/ besides)
	for f, v := range map[string]string{"cgroup.max.descendants": "66", "cgroup.max.depth": "5"} {
		if err := os.WriteFile(filepath.Join(spec.CgRoot, f), []byte(v), 0); err != nil {
			return "", err
		}
	}
	if err := os.Mkdir(spec.CgRoot+"/sandbox", 0o755); err != nil {
		return "", err
	}
	if err := os.Mkdir(spec.CgRoot+"/sandbox/app", 0o755); err != nil {
		return "", err
	}
	bind, err := cgroupBind()
	if err != nil {
		return "", err
	}
	// The controllers the unit got, for sandbox/ and below: cpu for cgrun's weights (systemd's user@.service
	// delegates pids, memory and cpu to the user's manager)
	have, err := os.ReadFile(spec.CgRoot + "/cgroup.controllers")
	if err != nil {
		return "", err
	}
	for _, c := range []string{"memory", "pids", "cpu"} {
		for _, h := range strings.Fields(string(have)) {
			if h == c {
				spec.Ctl = append(spec.Ctl, "+"+c)
			}
		}
	}
	if len(spec.Ctl) > 0 {
		if err := os.WriteFile(spec.CgRoot+"/cgroup.subtree_control", []byte(strings.Join(spec.Ctl, " ")), 0); err != nil {
			return "", err
		}
	}
	return bind, nil
}

// cgroupBind is --bind, or --ro-bind without nsdelegate. Without it the kernel neither keeps the sandbox from its
// root's files nor checks moves against its namespace (any cgroup2 mount in the host's cgroup namespace without the
// option clears it for all, as cilium's does): the sandbox gets its cgroup bound read-only, which stops writes through
// /sys/fs/cgroup, and no cgrun. The bind doesn't keep it from its subtree: a cgroup2 mount of its own in nested user
// and cgroup namespaces (FS_USERNS_MOUNT) is writable, rooted at the new namespace's root, the cgroup the process is
// in. So the sandbox can change its own cgroups' limits and freeze or kill its own processes, and nothing outside
// sandbox/: not supervisor/, not the caps on the unit's cgroup. Nor can it clear nsdelegate: a cgroup2 mount sets the
// superblock's options only from the host's cgroup namespace (apply_cgroup_root_flags in kernel/cgroup/cgroup.c).
// systemd mounts it with nsdelegate
func cgroupBind() (string, error) {
	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	// The superblock's options, last on a cgroup2 mount's line: the same on every one
	flags := ""
	for line := range strings.SplitSeq(string(mi), "\n") {
		if strings.Contains(line, " - cgroup2 ") {
			f := strings.Fields(line)
			flags = f[len(f)-1]
			break
		}
	}
	if strings.Contains(","+flags+",", ",nsdelegate,") {
		return "--bind", nil
	}
	if flags == "" {
		flags = "none"
	}
	fmt.Fprintf(os.Stderr, "claude-desktop: cgroup2 is mounted without nsdelegate (options: %s), so the sandbox's "+
		"cgroup is bound read-only and cgrun won't work in it. The sandbox can still write its own cgroups through "+
		"a cgroup2 mount of its own, though nothing outside them. A cgroup2 mount in the host's cgroup namespace "+
		"without the option clears it (cilium's at /run/cilium/cgroupv2 does). As root, 'mount -o "+
		"remount,nsdelegate,memory_recursiveprot,memory_hugetlb_accounting /sys/fs/cgroup' restores systemd's "+
		"options; then start the app again\n", flags)
	return "--ro-bind", nil
}
