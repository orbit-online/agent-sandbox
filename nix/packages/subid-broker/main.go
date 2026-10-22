package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/docopt/docopt-go"
	"golang.org/x/sys/unix"
)

const usage = `subid-broker - Write uid and gid maps for user namespaces inside a sandbox

Usage:
  subid-broker <socket>

Listens on <socket> for map requests from inside the sandbox, which reaches it
at /run/subid-broker.sock. The client and the target process must belong to
the client's uid, the client must be in a user namespace other than the
broker's, and the target's user namespace must be below the client's. The
broker writes the map from the target's parent user namespace, where the kernel
checks that the outer ids are mapped. Exits when its parent does.

Called as newuidmap or newgidmap, it takes shadow's arguments
(<pid> <inner> <outer> <count>...) and sends the request to
$SUBID_BROKER_SOCKET, by default /run/subid-broker.sock.
`

const defaultSocket = "/run/subid-broker.sock"

// Set to a store path at build time
var nsenter = "nsenter"

func main() {
	switch filepath.Base(os.Args[0]) {
	case "newuidmap":
		os.Exit(client("uid", os.Args[1:]))
	case "newgidmap":
		os.Exit(client("gid", os.Args[1:]))
	}
	// The broker's helper, run through nsenter in the target's parent user namespace
	if len(os.Args) == 3 && os.Args[1] == "write-map" {
		if err := writeMap(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	opts, err := docopt.ParseDoc(usage)
	if err != nil {
		slog.Error("Parse arguments", "err", err)
		os.Exit(2)
	}
	socket, _ := opts.String("<socket>")
	if err := serve(socket); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

// Parses newuidmap's arguments into the map file's lines
func parseMap(args []string) (int, string, error) {
	if len(args) < 4 || (len(args)-1)%3 != 0 {
		return 0, "", fmt.Errorf("Usage: <pid> <inner> <outer> <count> [<inner> <outer> <count>]...")
	}
	pid, err := strconv.Atoi(args[0])
	if err != nil {
		return 0, "", fmt.Errorf("Parse pid %q: %w", args[0], err)
	}
	var lines []string
	for i := 1; i < len(args); i += 3 {
		var ids [3]uint32
		for j := range ids {
			n, err := strconv.ParseUint(args[i+j], 10, 32)
			if err != nil {
				return 0, "", fmt.Errorf("Parse id %q: %w", args[i+j], err)
			}
			ids[j] = uint32(n)
		}
		lines = append(lines, fmt.Sprintf("%d %d %d", ids[0], ids[1], ids[2]))
	}
	return pid, strings.Join(lines, "\n") + "\n", nil
}

func client(kind string, args []string) int {
	fail := func(err error) int {
		fmt.Fprintf(os.Stderr, "new%smap: %s\n", kind, err)
		return 1
	}
	pid, idMap, err := parseMap(args)
	if err != nil {
		return fail(err)
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return fail(fmt.Errorf("Open pidfd for %d: %w", pid, err))
	}
	socket := os.Getenv("SUBID_BROKER_SOCKET")
	if socket == "" {
		socket = defaultSocket
	}
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: socket, Net: "unixpacket"})
	if err != nil {
		return fail(fmt.Errorf("Connect to the broker: %w", err))
	}
	defer conn.Close()
	if _, _, err := conn.WriteMsgUnix([]byte(kind+"\n"+idMap), unix.UnixRights(pidfd), nil); err != nil {
		return fail(fmt.Errorf("Send request: %w", err))
	}
	reply := make([]byte, 4096)
	n, err := conn.Read(reply)
	if err != nil {
		return fail(fmt.Errorf("Read reply: %w", err))
	}
	if r := string(reply[:n]); r != "ok" {
		return fail(fmt.Errorf("%s", r))
	}
	return 0
}

func serve(socket string) error {
	// Started by the wrapper that execs into bwrap, so this fires when bwrap exits
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGTERM), 0, 0, 0); err != nil {
		return fmt.Errorf("Set parent death signal: %w", err)
	}
	unix.Umask(0o077)
	l, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: socket, Net: "unixpacket"})
	if err != nil {
		return fmt.Errorf("Listen on %s: %w", socket, err)
	}
	// Close unlinks the socket
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, unix.SIGTERM, unix.SIGINT)
	go func() {
		<-sig
		l.Close()
	}()
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("Accept: %w", err)
		}
		go func() {
			defer conn.Close()
			reply := "ok"
			if err := handle(conn); err != nil {
				slog.Warn("Refused", "err", err)
				reply = err.Error()
			}
			_, _ = conn.Write([]byte(reply))
		}()
	}
}

func handle(conn *net.UnixConn) error {
	buf := make([]byte, 16384)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return fmt.Errorf("Read request: %w", err)
	}
	var fds []int
	if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil && len(msgs) == 1 {
		fds, _ = unix.ParseUnixRights(&msgs[0])
	}
	if len(fds) != 1 {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return fmt.Errorf("Request carries no pidfd")
	}
	targetPidfd := fds[0]
	defer unix.Close(targetPidfd)
	kind, idMap, _ := strings.Cut(string(buf[:n]), "\n")
	if kind != "uid" && kind != "gid" {
		return fmt.Errorf("Unknown map kind %q", kind)
	}
	// Re-parsed so only well-formed lines reach the kernel
	if _, idMap, err = parseMap(append([]string{"0"}, strings.Fields(idMap)...)); err != nil {
		return err
	}

	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("Get client socket: %w", err)
	}
	var cred *unix.Ucred
	peerPidfd := -1
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		if cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); credErr == nil {
			peerPidfd, credErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD)
		}
	}); err != nil || credErr != nil {
		return fmt.Errorf("Get client credentials: %w", errors.Join(err, credErr))
	}
	defer unix.Close(peerPidfd)

	parent, dir, pid, err := authorize(peerPidfd, int(cred.Uid), targetPidfd)
	if err != nil {
		return err
	}
	defer parent.Close()
	defer dir.Close()
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("Find own executable: %w", err)
	}
	// The Go runtime is multithreaded and can't setns into a user namespace; nsenter can. Without
	// --preserve-credentials it becomes uid 0 there, which keeps the capabilities setns granted through the exec
	cmd := exec.Command(nsenter, "--user=/proc/self/fd/3", "--", self, "write-map", kind)
	cmd.ExtraFiles = []*os.File{parent, dir}
	cmd.Stdin = strings.NewReader(idMap)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Write %s map of %d: %s", kind, pid, strings.TrimSpace(string(out)))
	}
	return nil
}

// Checks that the client may have the target's map written: both belong to uid, the client is in a user namespace
// other than the broker's, and the target's is below the client's. Returns the target's parent user namespace, its
// /proc directory and its pid
func authorize(clientPidfd, uid, targetPidfd int) (*os.File, *os.File, int, error) {
	clientNs, _, err := openUserns(clientPidfd, uid)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("Client: %w", err)
	}
	defer unix.Close(clientNs)
	if same, err := sameNs(clientNs, "/proc/self/ns/user"); err != nil || same {
		return nil, nil, 0, fmt.Errorf("Client isn't in a sandbox")
	}
	targetNs, pid, err := openUserns(targetPidfd, uid)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("Target: %w", err)
	}
	defer unix.Close(targetNs)
	dir, err := unix.Open("/proc/"+strconv.Itoa(pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("Open process %d: %w", pid, err)
	}
	dirF := os.NewFile(uintptr(dir), "proc")
	// As in openUserns: the directory is this process's only while its pidfd is alive
	if err := unix.PidfdSendSignal(targetPidfd, 0, nil, 0); err != nil {
		dirF.Close()
		return nil, nil, 0, fmt.Errorf("Process %d exited: %w", pid, err)
	}
	parent, err := unix.IoctlRetInt(targetNs, unix.NS_GET_PARENT)
	if err != nil {
		dirF.Close()
		return nil, nil, 0, fmt.Errorf("Get parent of process %d's user namespace: %w", pid, err)
	}
	parentF := os.NewFile(uintptr(parent), "parent")
	if !below(parent, clientNs) {
		dirF.Close()
		parentF.Close()
		return nil, nil, 0, fmt.Errorf("Process %d's user namespace isn't below the client's", pid)
	}
	return parentF, dirF, pid, nil
}

// Writes stdin to the uid_map or gid_map of the process whose /proc directory is fd 4, in the single write the
// kernel accepts
func writeMap(kind string) error {
	idMap, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("Read map: %w", err)
	}
	fd, err := unix.Openat(4, kind+"_map", unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("Open %s_map: %w", kind, err)
	}
	defer unix.Close(fd)
	if _, err := unix.Write(fd, idMap); err != nil {
		return fmt.Errorf("Write %s_map: %w", kind, err)
	}
	return nil
}

// Opens the user namespace of the process behind pidfd after checking it belongs to uid
func openUserns(pidfd, uid int) (int, int, error) {
	pid, err := pidfdPid(pidfd)
	if err != nil {
		return -1, 0, err
	}
	var st unix.Stat_t
	if err := unix.Stat("/proc/"+strconv.Itoa(pid), &st); err != nil {
		return -1, 0, fmt.Errorf("Stat process %d: %w", pid, err)
	}
	if int(st.Uid) != uid {
		return -1, 0, fmt.Errorf("Process %d belongs to uid %d, not %d", pid, st.Uid, uid)
	}
	fd, err := unix.Open("/proc/"+strconv.Itoa(pid)+"/ns/user", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, 0, fmt.Errorf("Open user namespace of %d: %w", pid, err)
	}
	// The pidfd outlives a recycled pid, so a successful signal 0 means the checks above were about this process
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		unix.Close(fd)
		return -1, 0, fmt.Errorf("Process %d exited: %w", pid, err)
	}
	return fd, pid, nil
}

// The pid behind pidfd, in the broker's pid namespace
func pidfdPid(pidfd int) (int, error) {
	f, err := os.Open("/proc/self/fdinfo/" + strconv.Itoa(pidfd))
	if err != nil {
		return 0, fmt.Errorf("Read pidfd info: %w", err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), "Pid:"); ok {
			pid, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || pid <= 0 {
				return 0, fmt.Errorf("Process has exited or is outside the broker's pid namespace")
			}
			return pid, nil
		}
	}
	return 0, fmt.Errorf("No pid in pidfd info")
}

func sameNs(fd int, path string) (bool, error) {
	var a, b unix.Stat_t
	if err := unix.Fstat(fd, &a); err != nil {
		return false, fmt.Errorf("Stat namespace: %w", err)
	}
	if err := unix.Stat(path, &b); err != nil {
		return false, fmt.Errorf("Stat %s: %w", path, err)
	}
	return a.Ino == b.Ino && a.Dev == b.Dev, nil
}

// Whether user namespace ancestor is ns or one of ns's ancestors
func below(ns, ancestor int) bool {
	cur, err := unix.Dup(ns)
	if err != nil {
		return false
	}
	for {
		same, err := sameNs(cur, "/proc/self/fd/"+strconv.Itoa(ancestor))
		if err != nil || same {
			unix.Close(cur)
			return same
		}
		next, err := unix.IoctlRetInt(cur, unix.NS_GET_PARENT)
		unix.Close(cur)
		if err != nil {
			return false
		}
		cur = next
	}
}
