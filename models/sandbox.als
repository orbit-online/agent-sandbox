/*
 * The shared base of the sandbox's models (README.md, "Model files"):
 * principals, processes, namespaces, capabilities, sockets and mounts,
 * and the facts that hold by kernel semantics alone. structure.als,
 * protocol.als and launch.als open it and add the sandbox's own shape
 * and the attacker's moves.
 *
 * Sources for the kernel facts: user_namespaces(7), namespaces(7),
 * setns(2), pid_namespaces(7), mount_namespaces(7), and
 * kernel/capability.c's cap_capable() for the capability walk. Linux
 * 6.18.
 *
 * Time: a process's namespaces, ids, capabilities and parent change
 * through setns, unshare, execve and reparenting, a user namespace's
 * map is written once, and processes come and go, so those are `var`.
 * Namespaces, mounts and sockets are a fixed universe: models over time
 * keep their own `var` set of the ones that exist. A model of one
 * snapshot adds `fact { frozen }`.
 */
module sandbox

// ---------------------------------------------------------------------
// Ids. A user or group id as the init user namespace sees it (a kuid).
// Ids inside a user namespace are whatever its map sends to these, so
// the models need kuids only, and uids and gids alike.

sig Id {}
// The host user (1000 in the diagram), host root, and the overflow id
// (65534) a process gets in a user namespace whose map isn't written
// yet. Subordinate ids from /etc/subuid and other users' ids are the
// remaining atoms; structure.als names them.
one sig HostUser, HostRoot, Overflow extends Id {}

// ---------------------------------------------------------------------
// Capabilities. Only the ones some step of the sandbox needs.

abstract sig Cap {}
one sig SysAdmin, NetAdmin, Bpf, SetUid, SetGid, CheckpointRestore,
  SysPtrace, Kill, SysChroot extends Cap {}

// ---------------------------------------------------------------------
// Principals and trust domains. Everything in the Sandbox domain is the
// attacker: whatever one process there can do, the attacker can. A
// principal names a role; its processes are Process atoms, so one
// principal (the broker) may have processes in several namespaces (its
// nsenter helpers).

abstract sig Domain {}
one sig Host, Sandbox extends Domain {}

abstract sig Principal { domain: one Domain }
// Host side: the user's own processes (terminal, host Claude Code), the
// permissions broker daemon and its helpers, the Permissions window, the
// notification daemon, nixpak's xdg-dbus-proxy, the launcher scripts
// (cmd/launcher with its bwrap and helper, nixpak's launcher),
// subid-broker, the netns-netkit setcap wrapper, the call units of host
// commands, and what host commands and host sockets reach (a VM, a host
// socket's server).
one sig HostUserP, BrokerP, WindowP, NotifierP, DbusProxyP, LauncherP,
  SubidBrokerP, NetnsNetkitP, CallUnitP, HostTargetP extends Principal {}
// Sandbox side: bwrap's init and the FHS env script (in U1), the app,
// Claude Code sessions and what they spawn (shells, MCP servers incl. the
// permissions one), anything those start in user namespaces of their
// own, and re-entries (claude://, --shell): inside once joined, their
// parent a host nsenter (README.md, Principals 16).
one sig BwrapInitP, AppP, SessionP, NestedP, ReentryP extends Principal {}
fact domains {
  (HostUserP + BrokerP + WindowP + NotifierP + DbusProxyP + LauncherP
    + SubidBrokerP + NetnsNetkitP + CallUnitP + HostTargetP).domain = Host
  (BwrapInitP + AppP + SessionP + NestedP + ReentryP).domain = Sandbox
}

// ---------------------------------------------------------------------
// Namespaces. User namespaces and the other kinds are separate
// signatures, so a command's scope counts them apart: `for 4 but 8
// OwnedNS` leaves room for the init namespaces and the sandbox's.

// user_namespaces(7): a tree under the initial namespace. The owner is
// the effective uid of the process that created it (NS_GET_OWNER_UID);
// mapped is the set of kuids its uid map sends ids to.
sig UserNS {
  parent: lone UserNS,
  owner: lone Id,
  var mapped: set Id
}
one sig InitUserNS extends UserNS {}

// Every other kind is owned by the user namespace its creator was in
// (NS_GET_USERNS). Capabilities over it are checked there.
abstract sig OwnedNS { ownedBy: one UserNS }
sig MountNS, NetNS, IpcNS, UtsNS, CgroupNS extends OwnedNS {}
// pid_namespaces(7): a tree too; a process sees its own pid namespace
// and the ones below it.
sig PidNS extends OwnedNS { pparent: lone PidNS }
one sig InitPidNS extends PidNS {}

fact userTree {
  no InitUserNS.parent
  no InitUserNS.owner
  all u: UserNS - InitUserNS | one u.parent and one u.owner
  all u: UserNS | InitUserNS in u.*parent
  // the creator ran in the parent, so its euid is mapped there once the
  // parent has a map: a model may start before a map is written, with
  // the namespaces below it already in its universe
  always all u: UserNS - InitUserNS | some u.parent.mapped implies u.owner in u.parent.mapped
}

fact pidTree {
  no InitPidNS.pparent
  all n: PidNS - InitPidNS | one n.pparent
  all n: PidNS | InitPidNS in n.*pparent
  InitPidNS.ownedBy = InitUserNS
}

// user_namespaces(7), "Defining user and group ID mappings": the outer
// ids must be mapped in the parent, and a map is written once.
fact maps {
  always InitUserNS.mapped = Id - Overflow
  always all u: UserNS - InitUserNS | u.mapped in u.parent.mapped
  always all u: UserNS | some u.mapped implies u.mapped' = u.mapped
}

// ---------------------------------------------------------------------
// Processes. pid is the pid the host's pid namespace gives it, which is
// how the broker and subid-broker name processes; a pid is reused once
// its process is gone. Pidfds name a process, not a pid: models give
// them as Process atoms.

sig Pid {}

var sig Process {
  // var only because Process is; it never changes (fact processes)
  var principal: one Principal,
  var pid: one Pid,
  var ppid: lone Process,
  // effective uid, as a kuid
  var uid: one Id,
  // effective capabilities, which count in its own user namespace
  var caps: set Cap,
  var userns: one UserNS,
  var mnt: one MountNS,
  var net: one NetNS,
  var pidns: one PidNS
}

fact processes {
  always all p: Process & Process' | p.principal' = p.principal
  always all disj p, q: Process | p.pid != q.pid
  always all p: Process | p.ppid in Process - p
  // In a namespace whose map isn't written yet, a process runs as the
  // overflow id; once it is, as one of its ids
  always all p: Process | p.uid in p.userns.mapped + Overflow
  // namespaces(7): a process's pid namespace never changes; setns only
  // moves its later children (models give the child the new one)
  always all p: Process | p.pidns' = p.pidns or p not in Process'
  // A parent sees its children: theirs is its own or below
  always all p: Process | some p.ppid implies p.pidns in p.ppid.pidns.*~pparent
}

// A snapshot: nothing changes. For structure.als.
pred frozen {
  always {
    Process' = Process
    mapped' = mapped
    pid' = pid and ppid' = ppid and uid' = uid and caps' = caps
    userns' = userns and mnt' = mnt and net' = net and pidns' = pidns
  }
}

// ---------------------------------------------------------------------
// Capabilities across user namespaces: cap_capable(). Walking up from
// u, p has c if it is in that namespace with c effective, or if it is in
// the namespace's parent with the namespace's owner as euid, which gives
// it every capability there and in everything below.

pred hasCap[p: Process, u: UserNS, c: Cap] {
  some a: u.*parent |
    (a = p.userns and c in p.caps)
    or (a.parent = p.userns and a.owner = p.uid)
}

// Capability over a namespace of another kind: in its owner.
pred hasCapOver[p: Process, n: OwnedNS, c: Cap] { hasCap[p, n.ownedBy, c] }

// setns(2): joining a user namespace needs CAP_SYS_ADMIN in it, and
// can't re-enter one's own (nor can a multithreaded process, which is why
// the Go helpers run through nsenter).
pred canJoinUser[p: Process, u: UserNS] {
  u != p.userns
  hasCap[p, u, SysAdmin]
}

// Joining any other kind needs CAP_SYS_ADMIN over it, and for a mount
// namespace CAP_SYS_CHROOT and CAP_SYS_ADMIN in one's own user namespace
// as well.
pred canJoin[p: Process, n: OwnedNS] {
  hasCapOver[p, n, SysAdmin]
  n in MountNS implies (hasCap[p, p.userns, SysAdmin] and hasCap[p, p.userns, SysChroot])
}

// pid_namespaces(7): p can name q (kill, pidfd_open, ptrace, /proc) only
// if q's pid namespace is p's or below it.
pred sees[p, q: Process] { q.pidns in p.pidns.*~pparent }

// kill(2): the same uid, or CAP_KILL in the target's user namespace.
// (The kernel compares real and saved ids too; the model has one id.)
pred canSignal[p, q: Process] {
  sees[p, q]
  p.uid = q.uid or hasCap[p, q.userns, Kill]
}

// ---------------------------------------------------------------------
// Files and mounts. A File is an inode (device and inode number); a
// Mount shows one in one mount namespace. Locked is MNT_LOCKED: set on
// every mount copied into a mount namespace owned by a less privileged
// user namespace, so it can't be unmounted or moved there to reveal what
// lies beneath (mount_namespaces(7)).

sig File { up: lone File }
abstract sig MountFlag {}
one sig ReadOnly, Locked, Shared, Slave, NoDev, NoSuid extends MountFlag {}
sig Mount {
  ns: one MountNS,
  root: one File,
  at: one File,
  flags: set MountFlag
}

fact files { no f: File | f in f.^up }

// umount2(2): CAP_SYS_ADMIN over the mount namespace, and not locked.
pred canUnmount[p: Process, m: Mount] {
  p.mnt = m.ns
  hasCapOver[p, m.ns, SysAdmin]
  Locked not in m.flags
}

// ---------------------------------------------------------------------
// Sockets. A Unix socket by path: a process can connect when its mount
// namespace has a mount through which the path resolves (a read-only
// bind is enough). Abstract sockets are per network namespace, and the
// sandbox has its own. checks are what the listener verifies about the
// peer; structure.als gives them meaning.

abstract sig PeerCheck {}
// SO_PEERCRED's uid; SO_PEERPIDFD instead of the pid alone; the peer in
// the listener's own user namespace; the target's user namespace below
// the peer's; the peer in a given mount namespace; the peer's /proc
// entry owned by the listener's uid.
one sig PeerUid, PeerPidfd, SameUserNS, UserNSBelow, InMountNS, ProcOwner
  extends PeerCheck {}

sig Socket {
  listener: one Principal,
  reachable: set MountNS,
  checks: set PeerCheck
}

// The peer a listener sees is the process that connected; the socket's
// fd can be passed on afterwards, and the listener still sees the first.
pred canConnect[p: Process, s: Socket] { p.mnt in s.reachable }

// ---------------------------------------------------------------------
// Checks of the base itself: that the facts encode the man pages as
// intended. None of them is a claim about the sandbox.

// An instance shaped like the sandbox: init, U1 owned by the host user,
// U2 below it, a process in U2 without capabilities.
run shape {
  some disj u1, u2: UserNS - InitUserNS, p: Process {
    u1.parent = InitUserNS and u1.owner = HostUser
    u2.parent = u1 and u2.owner = HostUser
    p.userns = u2 and no p.caps and p.uid = HostUser
  }
} for 4 but 8 OwnedNS, 1..2 steps expect 1

// user_namespaces(7): the creator's euid in the parent has every
// capability in the namespace and all below it.
assert ownerHasCapsBelow {
  always all p: Process, u: UserNS - InitUserNS, v: u.*~parent, c: Cap |
    (p.userns = u.parent and p.uid = u.owner) implies hasCap[p, v, c]
}
check ownerHasCapsBelow for 4 but 8 OwnedNS, 1..2 steps expect 0

// Capabilities never reach above or beside a process's user namespace.
assert capsOnlyBelow {
  always all p: Process, u: UserNS, c: Cap |
    hasCap[p, u, c] implies u in p.userns.*~parent
}
check capsOnlyBelow for 4 but 8 OwnedNS, 1..2 steps expect 0

// So nothing in a child user namespace can join a namespace its parent
// owns, whatever capabilities it holds.
assert noJoinUpward {
  always all p: Process, n: OwnedNS |
    n.ownedBy in p.userns.^parent implies not canJoin[p, n]
}
check noJoinUpward for 4 but 8 OwnedNS, 1..2 steps expect 0

// A nested user namespace never maps an id its ancestors don't.
assert mapsNarrow {
  always all u: UserNS, a: u.^parent | u.mapped in a.mapped
}
check mapsNarrow for 4 but 8 OwnedNS, 1..2 steps expect 0
