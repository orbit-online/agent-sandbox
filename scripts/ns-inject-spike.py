#!/usr/bin/env python3
"""Spike: bind host paths into a running bwrap sandbox and detach them again, from outside it without capabilities.

Usage: ns-inject-spike.py BWRAP

Run inside the sandbox: the shell there stands to a nested bwrap as an unprivileged host process stands to the
sandbox. Starts two nested bwraps shaped like the sandbox (B1 for nixpak's, B2 for the FHS env's inside it), then
checks each finding and prints it. Last worked 2026-10-31, kernel 6.18, bubblewrap 0.12.0.
"""
import contextlib, ctypes, errno, fcntl, os, pickle, shutil, signal, socket, subprocess, sys, tempfile, time

libc = ctypes.CDLL(None, use_errno=True)
SYS_open_tree, SYS_move_mount, SYS_mount_setattr = 428, 429, 442
OPEN_TREE_CLONE, AT_RECURSIVE, AT_EMPTY_PATH, AT_FDCWD = 1, 0x8000, 0x1000, -100
MOVE_MOUNT_F_EMPTY_PATH, MOUNT_ATTR_RDONLY, MNT_DETACH, MS_SHARED = 0x4, 0x1, 2, 1 << 20
NS_GET_USERNS = 0xB701
KVM_GET_API_VERSION = 0xAE00


def check(ret, what):
    if ret < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"{what}: {os.strerror(e)}")
    return ret


def open_tree(dfd, path, flags):
    return check(libc.syscall(SYS_open_tree, dfd, path.encode(), flags | os.O_CLOEXEC), "open_tree")


def enter_owner(pid, mnt=True):
    """Join the userns that owns pid's mntns (with CAP_SYS_ADMIN there, as its creator's uid), then the mntns.

    Not pid's own userns: unless given --userns-block-fd, bwrap unshares a second userns inside the first when its
    uid there differs from the sandbox's (--dev mounts devpts as root), and the sandbox runs in that second one,
    which has no capabilities over the mounts."""
    mntfd = os.open(f"/proc/{pid}/ns/mnt", os.O_RDONLY)
    os.setns(fcntl.ioctl(mntfd, NS_GET_USERNS), os.CLONE_NEWUSER)
    if mnt:
        os.setns(mntfd, os.CLONE_NEWNS)
    os.chdir("/")


def enter_as_sandbox(pid):
    """Join pid's own userns and mntns, as a process in the sandbox."""
    os.setns(os.pidfd_open(pid), os.CLONE_NEWUSER | os.CLONE_NEWNS)
    os.chdir("/")


def attach(pid, src, dst, readonly=False):
    """Clone src in a mntns of our own owned by the target's mntns owner, then move it to dst in the target's.

    OPEN_TREE_CLONE needs CAP_SYS_ADMIN over the mntns src is in, and may only clone from the caller's own mntns
    (may_copy_tree), so the clone happens in a copy of ours made after joining the owner userns. move_mount then
    attaches the detached tree from inside the target's mntns."""
    is_dir = os.path.isdir(src)
    parent, child = socket.socketpair()
    if os.fork() == 0:
        try:
            enter_owner(pid, mnt=False)
            os.unshare(os.CLONE_NEWNS)
            tree = open_tree(AT_FDCWD, src, OPEN_TREE_CLONE | AT_RECURSIVE)
            if readonly:
                attr = (ctypes.c_uint64 * 4)(MOUNT_ATTR_RDONLY, 0, 0, 0)  # struct mount_attr
                check(libc.syscall(SYS_mount_setattr, tree, b"", AT_EMPTY_PATH | AT_RECURSIVE, attr,
                                   ctypes.sizeof(attr)), "mount_setattr")
            socket.send_fds(child, [b"t"], [tree])
        finally:
            os._exit(0)
    _, fds, _, _ = socket.recv_fds(parent, 1, 1)
    os.wait()
    if not fds:
        raise OSError("helper sent no tree")

    def move():
        enter_owner(pid)
        if is_dir:
            os.makedirs(dst, exist_ok=True)
        elif not os.path.exists(dst):
            open(dst, "w").close()
        check(libc.syscall(SYS_move_mount, fds[0], b"", AT_FDCWD, dst.encode(), MOVE_MOUNT_F_EMPTY_PATH),
              "move_mount")

    in_child(move)


def detach(pid, dst, remove=True):
    def run():
        enter_owner(pid)
        check(libc.umount2(dst.encode(), MNT_DETACH), "umount2")
        if remove:
            (os.rmdir if os.path.isdir(dst) else os.unlink)(dst)

    in_child(run)


def in_child(fn):
    """Run fn in a fork, since setns sticks to the process; return its result or raise its error."""
    r, w = os.pipe()
    if os.fork() == 0:
        os.close(r)
        try:
            out = ("ok", fn())
        except BaseException as e:
            out = ("err", e)
        try:
            os.write(w, pickle.dumps(out))
        finally:
            os._exit(0)
    os.close(w)
    with os.fdopen(r, "rb") as f:
        status, val = pickle.loads(f.read())
    os.wait()
    if status == "err":
        raise val
    return val


def errno_of(fn):
    try:
        in_child(fn)
    except OSError as e:
        return e.errno
    return 0


def descendants(pid):
    out = []
    for c in subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True).stdout.split():
        out += [int(c)] + descendants(int(c))
    return out


def start_nested(bwrap, before_b2="", extra_b1=(), grants_b1=("--tmpfs", "/grants")):
    """B1 with B2 inside, each with its own userns and mntns. Returns (the process, B1's sandboxed pid, B2's payload
    pid), the last None when before_b2 holds B2 back."""
    common = ["--ro-bind", "/nix", "/nix", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    sleep, bash = shutil.which("sleep"), os.path.realpath(shutil.which("bash"))
    b2 = [bwrap, "--die-with-parent", "--unshare-user", "--unshare-pid", *common, "--bind", "/grants", "/grants",
          "--", sleep, "600"]
    p = subprocess.Popen(["timeout", "600", bwrap, "--unshare-all", "--die-with-parent", *common, *grants_b1,
                          *extra_b1, "--", bash, "-c", f"{before_b2}exec \"$@\"", "-", *b2],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    for _ in range(100):
        tree = descendants(p.pid)
        ns = {pid: os.readlink(f"/proc/{pid}/ns/mnt") for pid in tree if os.path.exists(f"/proc/{pid}/ns/mnt")}
        mnts = list(dict.fromkeys(ns.values()))  # ours (timeout, bwrap's parent), M1, M2
        # Held back, B2 is known to wait once B1's bash runs, which is after bwrap's pivot_root
        ready = len(mnts) == 3 or before_b2 and len(mnts) == 2 and any(comm(pid) == "bash" for pid in tree)
        if ready:
            m1 = next(pid for pid in tree if ns.get(pid) == mnts[1])
            m2 = [pid for pid in tree if ns.get(pid) == mnts[2]][-1] if not before_b2 else None
            return p, m1, m2
        time.sleep(0.1)
    p.kill()
    sys.exit("nested sandbox didn't come up")


def comm(pid):
    with contextlib.suppress(OSError), open(f"/proc/{pid}/comm") as f:
        return f.read().strip()


def report(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'} {name}{': ' + detail if detail else ''}", flush=True)
    return ok


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    bwrap = sys.argv[1]
    work = tempfile.mkdtemp()
    host = os.path.join(work, "host")
    os.mkdir(host)
    with open(os.path.join(host, "file"), "w") as f:
        f.write("one\n")
    results = []

    proc, m1, m2 = start_nested(bwrap)
    root = f"/proc/{m2}/root"
    try:
        def foreign():
            src = os.open(host, os.O_PATH)
            enter_owner(m2)
            open_tree(src, "", OPEN_TREE_CLONE | AT_RECURSIVE | AT_EMPTY_PATH)
        e = errno_of(foreign)
        results.append(report("open_tree on a path from another mntns fails", e == errno.EINVAL, os.strerror(e)))

        def own_userns_then_mnt():
            os.setns(os.open(f"/proc/{m2}/ns/user", os.O_RDONLY), os.CLONE_NEWUSER)
            os.setns(os.open(f"/proc/{m2}/ns/mnt", os.O_RDONLY), os.CLONE_NEWNS)
        e = errno_of(own_userns_then_mnt)
        results.append(report("the payload's own userns can't enter its mntns (bwrap's second userns)",
                              e == errno.EPERM, os.strerror(e)))

        attach(m2, host, "/grants/rw")
        with open(os.path.join(host, "file"), "a") as f:
            f.write("two\n")
        with open(f"{root}/grants/rw/file") as f:
            results.append(report("rw folder attached, host writes show live", f.read() == "one\ntwo\n"))

        e = errno_of(lambda: (enter_as_sandbox(m2), check(libc.umount2(b"/grants/rw", MNT_DETACH), "umount2")))
        results.append(report("the sandbox can't unmount a grant", e == errno.EPERM, os.strerror(e)))

        attach(m2, host, "/grants/ro", readonly=True)
        e = errno_of(lambda: (enter_as_sandbox(m2), open("/grants/ro/new", "w")))
        results.append(report("ro folder attached read-only", e == errno.EROFS, os.strerror(e)))

        r, w = os.pipe()
        signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGUSR1])
        holder = os.fork()
        if holder == 0:
            try:
                enter_as_sandbox(m2)
                os.chdir("/grants/ro")
                f = open("file")
                os.write(w, b"x")
                signal.sigwait([signal.SIGUSR1])
                os.write(w, pickle.dumps((os.listdir("."), f.read())))
            finally:
                os._exit(0)
        if os.read(r, 1) != b"x":
            sys.exit("fd holder failed")
        detach(m2, "/grants/ro")
        detach(m2, "/grants/rw")
        results.append(report("detach removes both grants", os.listdir(f"{root}/grants") == []))
        os.kill(holder, signal.SIGUSR1)
        held = pickle.loads(os.read(r, 4096))
        os.waitpid(holder, 0)
        results.append(report("a cwd or fd held across a lazy detach keeps access", held == (["file"], "one\ntwo\n"),
                              "MNT_DETACH doesn't revoke what's open"))

        if os.path.exists("/dev/kvm"):
            attach(m2, "/dev/kvm", "/dev/kvm")
            def kvm():
                enter_as_sandbox(m2)
                return fcntl.ioctl(os.open("/dev/kvm", os.O_RDWR), KVM_GET_API_VERSION)
            v = in_child(kvm)
            detach(m2, "/dev/kvm")
            results.append(report("/dev/kvm attached and usable, then gone",
                                  v == 12 and not os.path.exists(f"{root}/dev/kvm"), f"API version {v}"))
    finally:
        proc.kill()

    # B1 waits for /grants to turn shared in M1 before B2 copies it, so B2's /grants is its slave. As in the sandbox,
    # M1's /grants is a read-only bind of a directory outside, where the mountpoints are made
    flag = os.path.join(work, "shared")
    grants = os.path.join(work, "grants")
    os.makedirs(os.path.join(grants, "prop"))
    proc, m1, _ = start_nested(bwrap, before_b2=f"while [ ! -e {flag} ]; do sleep 0.1; done; ",
                               extra_b1=("--ro-bind", work, work), grants_b1=("--ro-bind", grants, "/grants"))
    try:
        def share():
            enter_owner(m1)
            check(libc.mount(None, b"/grants", None, MS_SHARED, None), "make-shared")
        in_child(share)
        open(flag, "w").close()
        m2 = None
        for _ in range(50):
            new = [p for p in descendants(m1) if os.readlink(f"/proc/{p}/ns/mnt") != os.readlink(f"/proc/{m1}/ns/mnt")]
            if new:
                m2 = new[-1]
                break
            time.sleep(0.1)
        if m2 is None:
            sys.exit("B2 didn't come up")
        attach(m1, host, "/grants/prop", readonly=True)
        seen = os.listdir(f"/proc/{m2}/root/grants/prop")
        e = errno_of(lambda: (enter_as_sandbox(m2), os.mkdir("/grants/new")))
        detach(m1, "/grants/prop", remove=False)
        gone = os.listdir(f"/proc/{m2}/root/grants/prop") == []
        results.append(report("attach and detach in M1 propagate to M2 when M1's /grants, a read-only bind, is shared "
                              "before B2 starts", seen == ["file"] and gone))
        results.append(report("the sandbox can't write to the grant directory", e == errno.EROFS, os.strerror(e)))
    finally:
        proc.kill()
        shutil.rmtree(work)
    sys.exit(0 if all(results) else 1)


main()
