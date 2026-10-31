/*
 * The sandbox's structure (README.md, S1-S14): its namespaces, where
 * each principal's processes run, the sockets that cross the boundary
 * and the store paths the host execs inside. This file is also the
 * library the other structure models open:
 *
 *   structure.als           this: the shape, S6, S8, S9, S12
 *   structure-attacker.als  S1-S4: the attacker's moves over time
 *   structure-mounts.als    S5, S10, S11, S14: mounts, locks, binds
 *   structure-race.als      S7, S13: pid reuse and moving targets
 *
 * Code is cited as it is on main 9a902c9: nix/home/claude-desktop/ as
 * hm/, nix/packages/<pkg>/ as <pkg>/.
 *
 * Revert checks: each property's comment says which modelled check was
 * removed to see Alloy find a counterexample, and that it did.
 */
module structure
open sandbox

// HIDE: Pid

// ---------------------------------------------------------------------
// Ids. U1 maps inner 0-999 and 1001-65535 to the user's /etc/subuid
// range and 1000 to 1000 (hm/bwrap-subid.sh:26-27); U2 maps all of
// U1's ids as themselves (hm/bwrap-subid.sh:68-69). SubStart is inner
// 0 of both, SubId the rest of the range. Other Id atoms are other host
// users.

one sig SubStart extends Id {}
sig SubId extends Id {}

// ---------------------------------------------------------------------
// The sandbox's namespaces (the diagram at the top of hm/default.nix).
// HostMnt and HostNet are the init mount and network namespaces. Any
// other namespace atom is one somebody made later: the attacker's,
// nested below U1, or the host's own (a rootless container).

one sig U1, U2 extends UserNS {}
one sig HostMnt, M1, M2 extends MountNS {}
one sig HostNet, N extends NetNS {}
one sig P, P2 extends PidNS {}

fact shape {
  U1.parent = InitUserNS and U1.owner = HostUser
  U2.parent = U1 and U2.owner = HostUser
  always U1.mapped = HostUser + SubStart + SubId
  always U2.mapped = U1.mapped
  (HostMnt + HostNet).ownedBy = InitUserNS
  (M1 + N + P).ownedBy = U1
  (M2 + P2).ownedBy = U2
  P.pparent = InitPidNS and P2.pparent = P
}

// The kuid inner 0 of a user namespace maps to. execve gives a process
// running as it every capability in its namespace, no_new_privs or not.
one sig NsRoot { of: UserNS -> lone Id }
fact roots {
  NsRoot.of[InitUserNS] = HostRoot
  NsRoot.of[U1] = SubStart and NsRoot.of[U2] = SubStart
  all u: UserNS | NsRoot.of[u] in u.mapped
}

// The sandbox's pid as the broker and the launcher hold it: the outer
// bwrap's child, bwrapinfo.json's child-pid (permissions-broker/
// sandbox.go:39-62). Every helper the broker runs finds the sandbox's
// namespaces through /proc/<this pid>/ns (sandbox.go:105-118,
// mounts.go:188-202).
one sig SbPid extends Pid {}
fun sb: Process { pid.SbPid }

fun sandboxProcs: set Process { principal.domain.Sandbox }

// ---------------------------------------------------------------------
// Where the code runs each principal, in one state.

// Host principals run in the init namespaces as the user, without
// capabilities, except netns-macvlan (cap_net_admin by setcap) and the
// helpers below.
pred hostAt[p: Process] {
  p.userns = InitUserNS and p.mnt = HostMnt and p.net = HostNet
  p.pidns = InitPidNS and p.uid = HostUser
  p.caps = (p.principal = NetnsMacvlanP => NetAdmin else none)
}

// The host's nsenters with capabilities:
// - the broker's make-shared, move-tree and detach: the user namespace
//   owning the sandbox's mount namespace and that mount namespace,
//   --keep-caps (sandbox.go:124, mounts.go:143, mounts.go:168);
//   clone-tree: that user namespace, the host's mount namespace
//   (mounts.go:130);
// - subid-broker's write-map: the target's parent user namespace only
//   (subid-broker/main.go:223);
// - net-setup's setpriv, before it execs udhcpc: U1, N, M1, P with
//   every capability (hm/net-setup.sh:17-28).
// All stay in the init pid namespace but the last.
pred helperAt[p: Process] {
  p.uid = HostUser and p.caps = Cap
  p.principal = BrokerP implies {
    p.userns = sb.mnt.ownedBy and p.mnt in sb.mnt + HostMnt
    p.net = HostNet and p.pidns = InitPidNS
  }
  p.principal = SubidBrokerP implies {
    p.userns in U1.*~parent and p.mnt = HostMnt and p.net = HostNet and p.pidns = InitPidNS
  }
  p.principal = LauncherP implies {
    p.userns = U1 and p.mnt = M1 and p.net = N and p.pidns = P
  }
  p.principal in BrokerP + SubidBrokerP + LauncherP
}

pred hostPlaced {
  all p: Process - sandboxProcs | hostAt[p] or helperAt[p]
}

// Where the sandbox's processes start (hm/default.nix's diagram):
// bwrap's init and the FHS env script in U1 without capabilities,
// udhcpc there with net_admin and net_raw (hm/net-setup.sh:26-28), the
// app, sessions and re-entries in U2 without any (hm/app-pid.sh:9,
// hm/claude-desktop.sh:50).
pred sandboxStart {
  all p: sandboxProcs {
    p.uid = HostUser
    p.principal in BwrapInitP + UdhcpcP implies {
      p.userns = U1 and p.mnt = M1 and p.net = N and p.pidns = P
      p.caps in (p.principal = UdhcpcP => NetAdmin + NetRaw else none)
    }
    p.principal in AppP + SessionP + ReentryP implies {
      p.userns = U2 and p.mnt = M2 and p.net = N and p.pidns = P2 and no p.caps
    }
    p.principal != NestedP
  }
  sb.principal = BwrapInitP
}

// Everywhere the sandbox's processes can get to, as structure-attacker
// shows (S1-S4): U1 as they started, or anywhere strictly below U1
// with any capabilities there. The snapshot models assume this rather
// than replay the moves.
pred reach {
  all p: sandboxProcs {
    p.uid in p.userns.mapped
    (p.userns = U1 and p.principal in BwrapInitP + UdhcpcP
      and p.mnt = M1 and p.net = N and p.pidns = P
      and p.caps in (p.principal = UdhcpcP => NetAdmin + NetRaw else none))
    or (p.userns in U1.^~parent and p.mnt.ownedBy in U1.*~parent
      and p.net.ownedBy in U1.*~parent and p.pidns in P.*~pparent)
  }
  sb.principal = BwrapInitP
}

// The sandbox's pid still in M1 and U1. The README's attacker includes
// bwrap's init (principal 11), so `reach` lets it unshare a user and
// mount namespace of its own; this rules that out. In practice bwrap's
// init runs only bwrap's code and is nobody's descendant in there, so
// with Yama's ptrace_scope at 1 (this host) nothing gets to run code
// as it.
pred sbPinned { sb.userns = U1 and sb.mnt = M1 }

pred world { reach and hostPlaced }

// ---------------------------------------------------------------------
// Sockets: request.sock in the grant directory, bound read-only at
// /run/permissions, and control.sock, not bound (hm/default.nix:
// 819-823, 855-856). Reachable is free beyond that: a user's bind or a
// ceiling may expose either.

one sig RequestSock, ControlSock extends Socket {}
abstract sig Op {}
one sig Watch, Share, OtherOp extends Op {}

fact sockets {
  (RequestSock + ControlSock).listener = BrokerP
  // SO_PEERPIDFD for both (broker.go:303-325); control: same user
  // namespace as the daemon (broker.go:386); share: the sandbox's mount
  // namespace (broker.go:486)
  ControlSock.checks = PeerPidfd + SameUserNS
  RequestSock.checks = PeerPidfd + InMountNS
  HostMnt + M1 + M2 in RequestSock.reachable
  HostMnt in ControlSock.reachable
}

// What the broker answers a peer, by its checks. The daemon runs in the
// init user namespace. watch is streamed before handleControl's check
// (broker.go:292-295), on both sockets.
pred served[p: Process, s: Socket, o: Op] {
  canConnect[p, s]
  s = ControlSock implies o != Share
  (s = ControlSock and o != Watch and SameUserNS in s.checks) implies p.userns = InitUserNS
  (o = Share and InMountNS in s.checks) implies p.mnt = sb.mnt
}

// S6: control.sock answers nothing but watch to a sandbox process,
// whatever exposes it. Holds because nothing in the sandbox gets into
// the init user namespace (S3). Revert: without SameUserNS in
// ControlSock.checks, a sandbox process in M2 with control.sock bound
// gets an answer (counterexample found).
assert S6controlOnlyHost {
  world implies no p: sandboxProcs, o: Op - Watch | served[p, ControlSock, o]
}
check S6controlOnlyHost for 4 but 11 OwnedNS, 1 steps expect 0

// S6's exception (README lead 3): a sandbox process that reaches
// control.sock gets a watch stream, events of the kinds and ids
// request.sock's watch gives too.
run S6watchFromSandbox {
  world and some p: sandboxProcs | served[p, ControlSock, Watch]
} for 4 but 11 OwnedNS, 1 steps expect 1

// S9: share takes effect only for a client in M1. Holds with the
// sandbox's pid in M1. Revert: without InMountNS in RequestSock.checks,
// the app in M2 gets share served (counterexample found). Without
// sbPinned the check compares with wherever the sandbox's pid is: an
// attacker running as bwrap's init that moved it gets share run in its
// own mount namespace, which only touches that namespace.
assert S9shareOnlyFromM1 {
  (world and sbPinned) implies
    all p: sandboxProcs | served[p, RequestSock, Share] implies p.mnt = M1
}
check S9shareOnlyFromM1 for 4 but 11 OwnedNS, 1 steps expect 0

// S9's vacuity guard, and README lead 4: udhcpc, in M1, may send share.
run S9udhcpcShares {
  world and sbPinned and some p: sandboxProcs |
    p.principal = UdhcpcP and served[p, RequestSock, Share]
} for 4 but 11 OwnedNS, 1 steps expect 1

// ---------------------------------------------------------------------
// netns-macvlan (netns-macvlan/main.go openNetns, ownedBelow): the
// target pid's /proc entry belongs to the caller (checked against a
// pidfd), its network namespace isn't the caller's, and walking up from
// the user namespace owning it (NS_GET_PARENT), the one right below the
// caller's is owned by the caller's uid (NS_GET_OWNER_UID). setcap
// cap_net_admin, so only the host runs it with effect (no_new_privs in
// the sandbox).

// The owner rule alone: c could act on namespaces of u without any
// file capability.
pred ownsBelow[c: Process, u: UserNS] {
  some a: u.*parent | a.parent = c.userns and a.owner = c.uid
}

pred macvlanAccepts[c, q: Process] {
  q.uid = c.uid
  q.net != c.net
  ownsBelow[c, q.net.ownedBy]
}

// The check before the fix: the immediate owner's uid only
pred macvlanAcceptedBefore[c, q: Process] {
  q.uid = c.uid
  q.net != c.net
  q.net.ownedBy.owner = c.uid
}

// S8: eth0 lands only in a network namespace other than the caller's
// over which the caller's uid holds every capability by the owner rule,
// so netns-macvlan does only what the caller could do there with
// cap_net_admin of its own. Holds.
assert S8macvlanOwned {
  all c, q: Process | (hostAt[c] and macvlanAccepts[c, q]) implies {
    q.net != c.net
    ownsBelow[c, q.net.ownedBy]
  }
}
check S8macvlanOwned for 4 but 6 UserNS, 11 OwnedNS, 1 steps expect 0

run S8macvlanOnN {
  world and sbPinned and some c: Process |
    c.principal = LauncherP and hostAt[c] and macvlanAccepts[c, sb] and sb.net = N
} for 4 but 11 OwnedNS, 1 steps expect 1

// S8, revert: the check before the fix read the immediate owner's uid
// only. A user namespace owned by the user below one owned by another uid
// (a root-made container that maps the user's uid) passed, though the
// user has no capability over it. The kernel's ptrace check on
// /proc/<pid>/ns/net already refuses the caller a process inside such a
// namespace; one of the user's own processes that root put in that
// netns passed. Outside the sandbox's attacker (it can't run setcap
// binaries); a host-side gap of the setcap wrapper.
assert S8ownerChainRevert {
  all c, q: Process | (hostAt[c] and macvlanAcceptedBefore[c, q]) implies ownsBelow[c, q.net.ownedBy]
}
check S8ownerChainRevert for 4 but 6 UserNS, 11 OwnedNS, 1 steps expect 1

// ---------------------------------------------------------------------
// Store paths the host execs after joining a sandbox mount namespace.
// The sandbox's /nix is its own, rw (hm/default.nix:533-536); nixpak
// binds storeRoots' closure read-only over it (hm/default.nix:108-111,
// 629-656, 806-807). A path outside the closure is the sandbox's to
// write.

sig StorePath { refs: set StorePath }
one sig FhsEnv, BwrapFhs, BrokerBin, NetSetup, UtilLinux, Busybox, Iproute2,
  DhcpScript extends StorePath {}
// storeRoots' list (hm/default.nix:632-647)
sig Root in StorePath {}
fun closure: set StorePath { Root.*refs }

abstract sig Exec { bin: one StorePath, inNs: one MountNS, keeps: set Cap }
// The broker's make-shared, move-tree, detach: `self` (os.Executable)
// in sb's mount namespace, every capability in its owner
one sig BrokerHelper extends Exec {}
// net-setup's setpriv with every capability in U1, and udhcpc and its
// script's ip with net_admin and net_raw (hm/net-setup.sh:26-28,
// hm/udhcpc.sh)
one sig NetSetupSetpriv, Udhcpc, UdhcpcIp extends Exec {}
// Today's helpers; a later one would be another Exec
sig LaterExec extends Exec {}

fact store {
  FhsEnv + NetSetup in Root
  // the FHS env's bwrap is bwrapFhs (hm/default.nix:735), which names
  // the broker for share (hm/default.nix:80-85)
  BwrapFhs in FhsEnv.refs
  BrokerBin in BwrapFhs.refs
  // net-setup's vars and runtimeInputs (hm/default.nix:699-712)
  UtilLinux + Busybox + DhcpScript + Iproute2 in NetSetup.refs
  // udhcpc.sh's runtimeInputs (hm/default.nix:165-169)
  Iproute2 in DhcpScript.refs
  BrokerHelper.bin = BrokerBin and BrokerHelper.keeps = Cap
  NetSetupSetpriv.bin = UtilLinux and NetSetupSetpriv.keeps = Cap
  Udhcpc.bin = Busybox and Udhcpc.keeps = NetAdmin + NetRaw
  UdhcpcIp.bin = Iproute2 and UdhcpcIp.keeps = NetAdmin + NetRaw
  (NetSetupSetpriv + Udhcpc + UdhcpcIp).inNs = M1
}

// The sandbox can replace what e execs: its path isn't bound from the
// host, or the mount namespace e resolves it in is one the sandbox has
// CAP_SYS_ADMIN over, where it can mount over the bind.
pred replaceable[e: Exec] {
  e.bin not in closure
  or some p: sandboxProcs | hasCapOver[p, e.inNs, SysAdmin]
}

// S12 for today's helpers: each resolves to a read-only bind of the
// closure that no sandbox process can cover. Holds. Revert: without
// BrokerBin in BwrapFhs.refs (the broker only reachable through that
// incidental reference), the broker's helpers exec from the sandbox's
// writable store (counterexample found).
assert S12helpersFromClosure {
  (world and sbPinned and BrokerHelper.inNs = sb.mnt) implies
    all e: Exec - LaterExec | some e.keeps implies not replaceable[e]
}
check S12helpersFromClosure for 4 but 11 OwnedNS, 12 StorePath, 1 steps expect 0

// S12 as a design property (README lead 5): nothing in the build
// checks that a helper's binary is in storeRoots' closure; today's are
// there through net-setup's vars and the FHS env's bwrap. A later
// helper exec'd in M1 with capabilities from a path outside it runs the
// sandbox's code with every capability in U1. Known.
assert S12anyHelperFromClosure {
  (world and sbPinned) implies all e: Exec | some e.keeps implies not replaceable[e]
}
check S12anyHelperFromClosure for 4 but 11 OwnedNS, 12 StorePath, 1 steps expect 1

// S12 under the README's attacker, which counts bwrap's init in: it may
// move the sandbox's pid into a user and mount namespace of its own
// (unshare -Um as that process, `reach` without sbPinned). The daemon
// pins U1 and M1 when it finds the sandbox (pinSandbox, sandbox.go: the
// mount namespace bwrapinfo.json names, owned by the pid's own user
// namespace, a child of the daemon's) and refuses once the pid shows
// other namespaces, so its helpers join M1 whatever bwrap's init does.
// Holds. Revert: helpers joining wherever the sandbox's pid is
// (BrokerHelper.inNs = sb.mnt, as before the fix): the helper execs the
// attacker's binary mounted over the closure's, a child of the daemon
// in the host's pid namespace (counterexample found).
assert S12helpersUnderHijack {
  (world and BrokerHelper.inNs = M1) implies not replaceable[BrokerHelper]
}
check S12helpersUnderHijack for 4 but 11 OwnedNS, 12 StorePath, 1 steps expect 0
