package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Type C: binding host paths into the running sandbox and detaching them, as scripts/ns-inject-spike.py verified.
// The daemon checks the source against the ceiling, creates the mountpoint in the grant directory on the host, and
// runs helpers of its own binary through nsenter for what a multithreaded Go process can't do (enter a user
// namespace):
//   clone-tree, in the owner of the sandbox's mount namespace, unshares a mount namespace of its own, opens the
//     source beneath its ceiling root without following any link, checks it against the denied directories by
//     identity, clones it (open_tree, without its submounts) and passes the tree's fd back;
//   move-tree, in the sandbox's mount namespace, attaches that tree at the mountpoint (move_mount);
//   detach unmounts mount points there.
// The sandbox can't write the grant directory, but it can plant links and rename directories in its rw binds, which
// may lie under a ceiling root: hence no links followed at all, and identities rather than paths for what's denied.

// A source a type C grant may attach: a path beneath one of the ceiling's roots
type source struct {
	Path string `json:"path"`
	RW   bool   `json:"rw"`
}

// ceilingC is what a type C plugin's ceiling says the daemon may attach at all
type ceilingC struct {
	Sources []source `json:"sources"`
}

// resolved is what a type C plugin's resolve command prints
type resolved struct {
	Source string `json:"source"`
	RO     bool   `json:"ro"`
}

// checkSource finds the ceiling root src lies beneath, the longest that matches, and whether it may be read-write.
// Lexical, so it refuses early what the ceiling doesn't cover; clone-tree checks what the path is when it opens it
func checkSource(ceil ceilingC, denied []string, src string, ro bool) (root, rel string, err error) {
	if !filepath.IsAbs(src) {
		return "", "", fmt.Errorf("Not an absolute path: %q", src)
	}
	src = filepath.Clean(src)
	for _, d := range denied {
		if src == d || strings.HasPrefix(src, d+"/") || strings.HasPrefix(d, strings.TrimSuffix(src, "/")+"/") {
			return "", "", fmt.Errorf("%s is never granted", src)
		}
	}
	var best *source
	for i, s := range ceil.Sources {
		r := filepath.Clean(s.Path)
		if src != r && !strings.HasPrefix(src, strings.TrimSuffix(r, "/")+"/") {
			continue
		}
		if best == nil || len(r) > len(filepath.Clean(best.Path)) {
			best = &ceil.Sources[i]
		}
	}
	if best == nil {
		return "", "", fmt.Errorf("%s isn't beneath anything the ceiling allows", src)
	}
	if !ro && !best.RW {
		return "", "", fmt.Errorf("%s may only be granted read-only", src)
	}
	root = filepath.Clean(best.Path)
	rel, _ = filepath.Rel(root, src)
	return root, rel, nil
}

// checkDenied validates the denied directories from the config: absolute, non-empty after the environment's
// expansion, and as the system resolves them, so they compare by identity whatever path leads there
func checkDenied(denied []string) ([]string, error) {
	out := make([]string, 0, len(denied))
	for _, d := range denied {
		if !filepath.IsAbs(d) {
			return nil, fmt.Errorf("Denied directory %q isn't an absolute path (an unset variable?)", d)
		}
		if real, err := filepath.EvalSymlinks(d); err == nil {
			d = real
		}
		out = append(out, filepath.Clean(d))
	}
	return out, nil
}

// attach clones root/rel and mounts it at mountpoint in the sandbox's mount namespace. Returns the source as resolved
func (s *sandbox) attach(root, rel string, ro bool, denied []string, mountpoint string) (string, error) {
	mnt, owner, err := s.namespaces()
	if err != nil {
		return "", err
	}
	defer mnt.Close()
	defer owner.Close()
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("Find own executable: %w", err)
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	ours, theirs := os.NewFile(uintptr(pair[0]), "clone"), os.NewFile(uintptr(pair[1]), "clone-helper")
	defer ours.Close()
	mode := "rw"
	if ro {
		mode = "ro"
	}
	// The sandbox's uts namespace too, though the helper has no use for it: with --user alone, nsenter (util-linux
	// 2.42.3) enters the user namespace in its first pass, which then leaves --keep-caps without effect
	uts, err := os.Open(fmt.Sprintf("/proc/%d/ns/uts", s.pid))
	if err != nil {
		return "", fmt.Errorf("Open the sandbox's uts namespace: %w", err)
	}
	defer uts.Close()
	clone := exec.Command(nsenter, append([]string{"--user=/proc/self/fd/3", "--uts=/proc/self/fd/5",
		"--preserve-credentials", "--keep-caps", "--", self, "clone-tree", root, rel, mode}, denied...)...)
	clone.ExtraFiles = []*os.File{owner, theirs, uts}
	out, err := clone.CombinedOutput()
	theirs.Close()
	if err != nil {
		return "", fmt.Errorf("Clone %s: %s", filepath.Join(root, rel), strings.TrimSpace(string(out)))
	}
	tree, resolvedPath, err := recvTree(int(ours.Fd()))
	if err != nil {
		return "", err
	}
	defer tree.Close()
	move := exec.Command(nsenter, "--user=/proc/self/fd/3", "--mount=/proc/self/fd/4", "--preserve-credentials",
		"--keep-caps", "--", self, "move-tree", mountpoint)
	move.ExtraFiles = []*os.File{owner, mnt, tree}
	if out, err := move.CombinedOutput(); err != nil {
		return "", fmt.Errorf("Mount %s: %s", mountpoint, strings.TrimSpace(string(out)))
	}
	return resolvedPath, nil
}

// detach unmounts mount points in the sandbox's mount namespace. The daemon reads which from the host: in there
// /proc is the sandbox's, where the helper isn't
func (s *sandbox) detach(points ...string) error {
	if len(points) == 0 {
		return nil
	}
	mnt, owner, err := s.namespaces()
	if err != nil {
		return err
	}
	defer mnt.Close()
	defer owner.Close()
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("Find own executable: %w", err)
	}
	cmd := exec.Command(nsenter, append([]string{"--user=/proc/self/fd/3", "--mount=/proc/self/fd/4",
		"--preserve-credentials", "--keep-caps", "--", self, "detach"}, points...)...)
	cmd.ExtraFiles = []*os.File{owner, mnt}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Unmount %s: %s", strings.Join(points, ", "), strings.TrimSpace(string(out)))
	}
	return nil
}

// detachBelow unmounts every mount below dir in the sandbox's mount namespace, deepest first: what an earlier
// daemon left
func (s *sandbox) detachBelow(dir string) error {
	points, err := mountsBelow(fmt.Sprintf("/proc/%d/mountinfo", s.pid), dir)
	if err != nil {
		return err
	}
	return s.detach(points...)
}

// namespaces opens the sandbox's mount namespace and the user namespace that owns it
func (s *sandbox) namespaces() (*os.File, *os.File, error) {
	mnt, err := os.Open(fmt.Sprintf("/proc/%d/ns/mnt", s.pid))
	if err != nil {
		return nil, nil, fmt.Errorf("Open the sandbox's mount namespace: %w", err)
	}
	if !s.alive() {
		mnt.Close()
		return nil, nil, errors.New("The sandbox ended")
	}
	ownerFd, err := unix.IoctlRetInt(int(mnt.Fd()), unix.NS_GET_USERNS)
	if err != nil {
		mnt.Close()
		return nil, nil, fmt.Errorf("Find the owner of the sandbox's mount namespace: %w", err)
	}
	return mnt, os.NewFile(uintptr(ownerFd), "userns"), nil
}

func recvTree(sock int) (*os.File, string, error) {
	buf := make([]byte, 4096)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unix.Recvmsg(sock, buf, oob, 0)
	if err != nil {
		return nil, "", fmt.Errorf("Receive the cloned tree: %w", err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		return nil, "", errors.New("The clone helper sent no tree")
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		return nil, "", errors.New("The clone helper sent no tree")
	}
	return os.NewFile(uintptr(fds[0]), "tree"), string(buf[:n]), nil
}

// cloneTree is the clone-tree helper, run in the user namespace owning the sandbox's mount namespace. In a mount
// namespace of its own, copied from ours (open_tree only clones from the caller's own), it opens root without
// following links, rel beneath it without following links or crossing mounts, refuses what is a denied directory,
// lies beneath one or holds one, and clones that one mount, read-only if asked and without devices or setuid for a
// directory. It sends the tree's fd and the path it resolved to on fd 4
func cloneTree(root, rel, mode string, denied []string) error {
	// The new mount namespace is this thread's, so everything below stays on it; the process ends after
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_FS | unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("Unshare a mount namespace: %w (%s)", err, credentials())
	}
	noLinks := uint64(unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS)
	rootFd, err := unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: noLinks})
	if err != nil {
		return fmt.Errorf("Open %s, which must be reached without links: %w", root, err)
	}
	defer unix.Close(rootFd)
	fd, err := unix.Openat2(rootFd, rel, &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: noLinks | unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return fmt.Errorf("Open %s beneath %s without links or crossing mounts: %w", rel, root, err)
	}
	defer unix.Close(fd)
	if err := checkIdentity(fd, rootFd, denied); err != nil {
		return err
	}
	// Not AT_RECURSIVE: a mount beneath it would come along unchecked. In this namespace, copied into a less
	// privileged one, every mount is locked, so a source with mounts beneath fails here
	tree, err := unix.OpenTree(fd, "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH)
	if err != nil {
		return fmt.Errorf("Clone %s (it mustn't have mounts beneath it): %w", rel, err)
	}
	defer unix.Close(tree)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	var attr uint64
	if mode == "ro" {
		attr |= unix.MOUNT_ATTR_RDONLY
	}
	if st.Mode&unix.S_IFMT == unix.S_IFDIR {
		attr |= unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOSUID
	}
	if attr != 0 {
		if err := unix.MountSetattr(tree, "", unix.AT_EMPTY_PATH, &unix.MountAttr{Attr_set: attr}); err != nil {
			return fmt.Errorf("Set the attributes of %s: %w", rel, err)
		}
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return err
	}
	if err := unix.Sendmsg(4, []byte(path), unix.UnixRights(tree), nil, 0); err != nil {
		return fmt.Errorf("Send the tree: %w", err)
	}
	return nil
}

type fileID struct{ dev, ino uint64 }

func idOf(fd int) (fileID, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fileID{}, err
	}
	return fileID{st.Dev, st.Ino}, nil
}

// checkIdentity refuses fd if it, or a directory between it and root, is a denied directory, or if a denied
// directory lies beneath it. By device and inode: no path to a denied directory, link or bind mount, gets around it
func checkIdentity(fd, rootFd int, denied []string) error {
	deniedIDs := map[fileID]string{}
	for _, d := range denied {
		var st unix.Stat_t
		if err := unix.Stat(d, &st); err == nil {
			deniedIDs[fileID{st.Dev, st.Ino}] = d
		}
	}
	rootID, err := idOf(rootFd)
	if err != nil {
		return err
	}
	src, err := idOf(fd)
	if err != nil {
		return err
	}
	// Up from the source to the root
	cur, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	for {
		id, err := idOf(cur)
		if err != nil {
			unix.Close(cur)
			return err
		}
		if d, ok := deniedIDs[id]; ok {
			unix.Close(cur)
			return fmt.Errorf("Never granted: it's %s or beneath it", d)
		}
		if id == rootID {
			unix.Close(cur)
			break
		}
		up, err := unix.Openat(cur, "..", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		unix.Close(cur)
		if err != nil {
			return err
		}
		if upID, _ := idOf(up); upID == id {
			unix.Close(up)
			return errors.New("The source isn't beneath its root")
		}
		cur = up
	}
	// Up from each denied directory to /: the source mustn't be on the way
	for _, d := range denied {
		cur, err := unix.Open(d, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		for {
			id, err := idOf(cur)
			if err != nil || id == src {
				unix.Close(cur)
				if err == nil {
					return fmt.Errorf("Never granted: %s lies beneath it", d)
				}
				return err
			}
			up, err := unix.Openat(cur, "..", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			unix.Close(cur)
			if err != nil {
				return err
			}
			if upID, _ := idOf(up); upID == id {
				unix.Close(up)
				break
			}
			cur = up
		}
	}
	return nil
}

// moveTree is the move-tree helper: in the sandbox's mount namespace, it attaches the tree on fd 5 at mountpoint
func moveTree(mountpoint string) error {
	if err := unix.MoveMount(5, "", unix.AT_FDCWD, mountpoint, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return fmt.Errorf("Attach at %s: %w", mountpoint, err)
	}
	return nil
}

// detachHelper unmounts mount points, lazily: what's open on them stays open
func detachHelper(points []string) error {
	for _, p := range points {
		if err := unix.Unmount(p, unix.MNT_DETACH); err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("Unmount %s: %w", p, err)
		}
	}
	return nil
}

// mountsBelow lists the mount points strictly below dir in a mountinfo file, deepest first
func mountsBelow(mountinfo, dir string) ([]string, error) {
	ids, err := mountIDs(mountinfo, func(p string) bool { return strings.HasPrefix(p, dir+"/") })
	if err != nil {
		return nil, err
	}
	var points []string
	for _, p := range ids {
		points = append(points, p)
	}
	sort.Slice(points, func(i, j int) bool { return len(points[i]) > len(points[j]) })
	return points, nil
}

// mountIDs maps the ids of the mounts in a mountinfo file whose mount point matches to the mount point
func mountIDs(mountinfo string, match func(string) bool) (map[int]string, error) {
	f, err := os.Open(mountinfo)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ids := map[int]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		point := unescapeMountinfo(fields[4])
		if match(point) {
			id, _ := strconv.Atoi(fields[0])
			ids[id] = point
		}
	}
	return ids, sc.Err()
}

// mountinfo escapes space, tab, newline and backslash as \ooo
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// A process in the sandbox holding files, mappings, its working directory or a mount of its own of a grant
type holder struct {
	Pid  int    `json:"pid"`
	Comm string `json:"comm"`
}

// How long the holders' scan may take: the sandbox decides how many processes and files there are
var holdersTimeout = 10 * time.Second

// grantMounts maps each mount namespace in the sandbox (by inode) to the ids of the grant's mounts there: those at or
// below its mount point. Read once per namespace, before detaching, while the mount points still resolve
func (s *sandbox) grantMounts(mountpoint string) map[uint64]map[uint64]bool {
	byNs := map[uint64]map[uint64]bool{}
	for _, pid := range append([]int{s.pid}, descendants(s.pid)...) {
		ns, ok := mntNs(pid)
		if !ok {
			continue
		}
		if _, seen := byNs[ns]; seen {
			continue
		}
		ids, _ := mountIDs(fmt.Sprintf("/proc/%d/mountinfo", pid), func(p string) bool {
			return p == mountpoint || strings.HasPrefix(p, mountpoint+"/")
		})
		set := map[uint64]bool{}
		for id := range ids {
			set[uint64(id)] = true
		}
		byNs[ns] = set
	}
	return byNs
}

// holdersAfter lists, after the detach, the processes in the sandbox still holding the grant: files, mappings or a
// working directory on its mounts (by mount id, which an open file keeps), or a mount of their own of the same
// filesystem and root, which a process can make in a mount namespace of its own and the detach doesn't reach
func (s *sandbox) holdersAfter(ids map[uint64]map[uint64]bool, dev, root string) []holder {
	deadline := time.Now().Add(holdersTimeout)
	var hs []holder
	rebinds := map[uint64]bool{}
	for _, pid := range descendants(s.pid) {
		if time.Now().After(deadline) {
			slog.Warn("Holders' scan cut short", "after", holdersTimeout)
			break
		}
		ns, ok := mntNs(pid)
		if !ok {
			continue
		}
		held := holdsMount(pid, ids[ns])
		if !held && dev != "" {
			if _, checked := rebinds[ns]; !checked {
				rebinds[ns] = mountsOf(fmt.Sprintf("/proc/%d/mountinfo", pid), dev, root)
			}
			held = rebinds[ns]
		}
		if held {
			comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
			hs = append(hs, holder{Pid: pid, Comm: strings.TrimSpace(string(comm))})
		}
	}
	return hs
}

func mntNs(pid int) (uint64, bool) {
	var st unix.Stat_t
	if unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", pid), &st) != nil {
		return 0, false
	}
	return st.Ino, true
}

// holdsMount reports whether pid's working directory, an open file or a mapping is on one of the mounts
func holdsMount(pid int, ids map[uint64]bool) bool {
	if len(ids) == 0 {
		return false
	}
	on := func(path string) bool {
		var stx unix.Statx_t
		return unix.Statx(unix.AT_FDCWD, path, 0, unix.STATX_MNT_ID, &stx) == nil && ids[stx.Mnt_id]
	}
	if on(fmt.Sprintf("/proc/%d/cwd", pid)) {
		return true
	}
	for _, dir := range []string{"fd", "map_files"} {
		entries, _ := os.ReadDir(fmt.Sprintf("/proc/%d/%s", pid, dir))
		for _, e := range entries {
			if on(fmt.Sprintf("/proc/%d/%s/%s", pid, dir, e.Name())) {
				return true
			}
		}
	}
	return false
}

// mountsOf reports whether a mountinfo file has a mount of the filesystem dev (major:minor) whose root is root or
// beneath it
func mountsOf(mountinfo, dev, root string) bool {
	f, err := os.Open(mountinfo)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 || fields[2] != dev {
			continue
		}
		r := unescapeMountinfo(fields[3])
		if r == root || strings.HasPrefix(r, strings.TrimSuffix(root, "/")+"/") {
			return true
		}
	}
	return false
}

// mountOf finds the device and root of the mount at mountpoint in a mountinfo file
func mountOf(mountinfo, mountpoint string) (dev, root string) {
	f, err := os.Open(mountinfo)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 5 && unescapeMountinfo(fields[4]) == mountpoint {
			dev, root = fields[2], unescapeMountinfo(fields[3])
		}
	}
	return dev, root
}

// descendants lists pid's descendants, through every thread's children
func descendants(pid int) []int {
	var out []int
	queue := []int{pid}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		tasks, _ := os.ReadDir(fmt.Sprintf("/proc/%d/task", p))
		for _, t := range tasks {
			data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/children", p, t.Name()))
			for _, c := range strings.Fields(string(data)) {
				if n, err := strconv.Atoi(c); err == nil {
					out = append(out, n)
					queue = append(queue, n)
				}
			}
		}
	}
	return out
}

// isDescendant reports whether pid is below the sandbox's pid
func (s *sandbox) isDescendant(pid int) bool {
	for p := pid; p > 1; {
		ppid, _, err := parent(p)
		if err != nil {
			return false
		}
		if ppid == s.pid {
			return true
		}
		p = ppid
	}
	return false
}

// makeMountpoint creates a grant's mountpoint in the grant directory on the host, through a dirfd that doesn't
// follow links: a directory for a directory, an empty file for anything else
func makeMountpoint(grantDir, name string, dir bool) error {
	dfd, err := unix.Open(grantDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("Open the grant directory: %w", err)
	}
	defer unix.Close(dfd)
	if dir {
		return unix.Mkdirat(dfd, name, 0o700)
	}
	fd, err := unix.Openat(dfd, name, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

// removeMountpoint removes a mountpoint makeMountpoint made
func removeMountpoint(grantDir, name string) {
	dfd, err := unix.Open(grantDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer unix.Close(dfd)
	if unix.Unlinkat(dfd, name, unix.AT_REMOVEDIR) != nil {
		_ = unix.Unlinkat(dfd, name, 0)
	}
}

// isDir reports whether path is a directory, following links: what clone-tree will resolve it to beneath its root
// may still differ, which only makes the mount fail
func isDir(path string) bool {
	var st unix.Stat_t
	return unix.Stat(path, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR
}

// A type C request's source, resolved by its plugin and checked against its ceiling
type sourceC struct {
	root, rel string
	ro        bool
}

func (s sourceC) path() string { return filepath.Join(s.root, s.rel) }

// resolveC runs a type C plugin's resolve command and checks what it names against the ceiling
func (b *broker) resolveC(c *capability, params json.RawMessage) (sourceC, error) {
	in, _ := json.Marshal(pluginInput{Params: params, Ceiling: c.Ceiling.Raw})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Resolve[0], c.Resolve[1:]...)
	cmd.Stdin = bytes.NewReader(in)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := runPlugin(cmd); err != nil {
		return sourceC{}, fmt.Errorf("%s couldn't resolve: %s", c.id(), strings.TrimSpace(errOut.String()))
	}
	var r resolved
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		return sourceC{}, fmt.Errorf("%s resolved to something other than JSON: %w", c.id(), err)
	}
	var ceil ceilingC
	if len(c.Ceiling.Raw) > 0 {
		if err := json.Unmarshal(c.Ceiling.Raw, &ceil); err != nil {
			return sourceC{}, fmt.Errorf("The ceiling of %s: %w", c.id(), err)
		}
	}
	root, rel, err := checkSource(ceil, b.cfg.Denied, r.Source, r.RO)
	if err != nil {
		return sourceC{}, err
	}
	return sourceC{root: root, rel: rel, ro: r.RO}, nil
}

// describeC adds what a type C grant attaches to its summary, as the daemon checked it
func describeC(summary string, src sourceC) string {
	access := "read-write"
	if src.ro {
		access = "read-only"
	}
	return fmt.Sprintf("%s: %q, %s", summary, src.path(), access)
}

// mountC attaches a type C grant at its mountpoint in the sandbox
func (b *broker) mountC(g *grant) error {
	src, err := b.resolveC(g.cap, g.Params)
	if err != nil {
		return err
	}
	if err := makeMountpoint(b.cfg.GrantDir, g.ID, isDir(src.path())); err != nil {
		return fmt.Errorf("Create the mountpoint: %w", err)
	}
	g.Path = filepath.Join(b.cfg.SandboxGrantDir, g.ID)
	if g.Source, err = b.sb.attach(src.root, src.rel, src.ro, b.cfg.Denied, g.Path); err != nil {
		removeMountpoint(b.cfg.GrantDir, g.ID)
		return err
	}
	g.dev, g.root = mountOf(fmt.Sprintf("/proc/%d/mountinfo", b.sb.pid), g.Path)
	return nil
}

// unmountC detaches a type C grant and removes its mountpoint, which ends its mounts in every namespace it
// propagated to, then lists what still holds it. Its mount ids are taken first, while its mount points resolve
func (b *broker) unmountC(g *grant) {
	if !b.sb.alive() {
		// Its mounts went with the sandbox
		removeMountpoint(b.cfg.GrantDir, g.ID)
		return
	}
	ids := b.sb.grantMounts(g.Path)
	if err := b.sb.detach(g.Path); err != nil {
		slog.Warn("Detach", "grant", g.ID, "err", err)
	}
	removeMountpoint(b.cfg.GrantDir, g.ID)
	g.Holders = b.sb.holdersAfter(ids, g.dev, g.root)
	if len(g.Holders) > 0 {
		slog.Info("Still held", "grant", g.ID, "holders", g.Holders)
	}
}

// isShared reports whether dir is a shared mount in the sandbox's mount namespace: a daemon started again finds the
// grant directory shared by the one before
func (s *sandbox) isShared(dir string) bool {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mountinfo", s.pid))
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 7 || unescapeMountinfo(fields[4]) != dir {
			continue
		}
		for _, opt := range fields[6:] {
			if opt == "-" {
				break
			}
			if strings.HasPrefix(opt, "shared:") {
				return true
			}
		}
	}
	return false
}

// credentials describes this process's ids and capabilities, for errors where they're the likely cause
func credentials() string {
	status, _ := os.ReadFile("/proc/self/status")
	var parts []string
	for _, line := range strings.Split(string(status), "\n") {
		for _, k := range []string{"Uid:", "CapPrm:", "CapEff:", "CapAmb:", "NoNewPrivs:"} {
			if strings.HasPrefix(line, k) {
				parts = append(parts, strings.Join(strings.Fields(line), " "))
			}
		}
	}
	bits, _ := unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0)
	user, _ := os.Readlink("/proc/self/ns/user")
	return strings.Join(append(parts, fmt.Sprintf("securebits %#x", bits), user), ", ")
}
