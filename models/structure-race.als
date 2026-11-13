/*
 * S7 and S13 over time: the checks that name a process by pid while
 * the attacker exits, recycles pids and moves its processes between
 * user namespaces. Processes come and go (host activity included, so a
 * freed pid may go to a host process); a live process's attributes stay,
 * except where S7's target moves.
 */
open structure

// HIDE: StorePath Exec Socket Op

fact staticMaps { always mapped' = mapped }

pred keepAll[ps: set Process] {
  all q: ps {
    q.principal' = q.principal and q.pid' = q.pid and q.ppid' = q.ppid
    q.uid' = q.uid and q.caps' = q.caps and q.userns' = q.userns
    q.mnt' = q.mnt and q.net' = q.net and q.pidns' = q.pidns
  }
}

// A process exits (its pid is free again), or one appears, with any pid
// no live process holds: forks in the sandbox, the host's own. A pidfd
// or a /proc directory fd still names the exited process: the checks
// and the request record that it is gone (a field can't name a process
// that no longer exists).
pred exit[p: Process] {
  no ppid.p & Process - p
  Process' = Process - p and keepAll[Process - p]
  all c: Chk {
    c.peer = p => (no c.peer' and c.gone' = c) else (c.peer' = c.peer and c.gone' = c.gone)
    c.stage' = c.stage and c.npid' = c.npid and c.peerNs' = c.peerNs
    c.seen' = c.seen and c.actual' = c.actual
  }
  Req.tgt = p => no Req.tgt' else Req.tgt' = Req.tgt
  Req.client = p => no Req.client' else Req.client' = Req.client
  Req.rstage' = Req.rstage and Req.cns' = Req.cns and Req.tpid' = Req.tpid
  Req.tns' = Req.tns and Req.pu' = Req.pu and Req.landed' = Req.landed
}
pred spawn[p: Process] {
  p not in Process and Process' = Process + p and keepAll[Process]
}

// ---------------------------------------------------------------------
// S13. A peer check takes a pidfd, then reads /proc/<pid> and checks the
// pidfd's process is alive, in some order. Read then alive: the process
// was alive at the read, so the pid was its. Alive then read: it may
// have exited in between and its pid gone to another.
//
// The orders in the code:
// - control.sock's user namespace check and share's mount namespace
//   check: handleControl's sameNs and shareFrom's sameNsAs, then
//   peer.gone() on the pidfd (sockets.go); serveOn's check before them
//   only turns away peers gone early;
// - subid-broker's client and target: openUserns reads, then signals the
//   pidfd (subid-broker/main.go:292-313);
// - netns-netkit: pidfd, reads, signal (netns-netkit/netns.go openNetns).
// What a check reads is modelled as the user namespace for all of them
// (share reads the mount namespace: the same race).

abstract sig Order {}
one sig AliveThenRead, ReadThenAlive extends Order {}
abstract sig Stage {}
one sig Idle, Opened, Half, Done, Failed extends Stage {}

abstract sig Chk {
  order: one Order,
  var stage: one Stage,
  var peer: lone Process,
  var gone: lone Chk,
  var npid: lone Pid,
  var peerNs: lone UserNS,
  var seen: lone UserNS,
  // the pidfd's process's user namespace at the read
  var actual: lone UserNS
}
one sig CtlChk, ShareChk, SubidChk, NetkitChk extends Chk {}
fact orders {
  (CtlChk + ShareChk + SubidChk + NetkitChk).order = ReadThenAlive
}

fact chkInit { all c: Chk | c.stage = Idle and no c.peer + c.gone + c.npid + c.peerNs + c.seen + c.actual }

pred chkKeep[cs: set Chk] {
  all c: cs | c.stage' = c.stage and c.peer' = c.peer and c.gone' = c.gone and c.npid' = c.npid
    and c.peerNs' = c.peerNs and c.seen' = c.seen and c.actual' = c.actual
}

pred connect[c: Chk, p: Process] {
  c.stage = Idle and p in Process
  c.stage' = Opened and c.peer' = p and c.npid' = p.pid and c.peerNs' = p.userns
  no c.seen' and no c.actual' and no c.gone' and chkKeep[Chk - c]
}
pred aliveStep[c: Chk] {
  (c.order = AliveThenRead and c.stage = Opened) or (c.order = ReadThenAlive and c.stage = Half)
  c.stage' = (some c.gone => Failed else (c.stage = Opened => Half else Done))
  c.gone' = c.gone and c.peer' = c.peer and c.npid' = c.npid and c.peerNs' = c.peerNs and c.seen' = c.seen
  c.actual' = c.actual and chkKeep[Chk - c]
}
pred readStep[c: Chk] {
  (c.order = ReadThenAlive and c.stage = Opened) or (c.order = AliveThenRead and c.stage = Half)
  let q = pid.(c.npid) & Process {
    c.stage' = (no q => Failed else (c.stage = Opened => Half else Done))
    c.seen' = q.userns
  }
  c.actual' = c.peer.userns
  c.gone' = c.gone and c.peer' = c.peer and c.npid' = c.npid and c.peerNs' = c.peerNs
  chkKeep[Chk - c]
}

// S7's request (below)
abstract sig RStage {}
one sig RIdle, Authorized, Written, Refused extends RStage {}
one sig Req {
  var rstage: one RStage,
  var client: lone Process,
  var cns: lone UserNS,
  var tgt: lone Process,
  var tpid: lone Pid,
  var tns: lone UserNS,
  var pu: lone UserNS,
  var landed: lone UserNS
}
// What the code and kernel do, so the revert checks can drop each:
// below() (subid-broker/main.go:265, 348-366); the /proc/<pid>
// directory fd that pins the target (main.go:249-258, 280); the
// kernel's map_write() rule that the opener's user namespace is the
// target's or its parent (kernel/user_namespace.c, proc_uid_map_write).
abstract sig Guard7 {}
one sig Below, PinDir, OpenerRule extends Guard7 {}
one sig G7 { on: set Guard7 }

pred reqKeep {
  Req.rstage' = Req.rstage and Req.client' = Req.client and Req.cns' = Req.cns
  Req.tgt' = Req.tgt and Req.tpid' = Req.tpid and Req.tns' = Req.tns
  Req.pu' = Req.pu and Req.landed' = Req.landed
}
fact reqInit { Req.rstage = RIdle and no Req.(client + cns + tgt + tpid + tns + pu + landed) }

// authorize(): both of the user's uid (their /proc entries), the client
// outside the broker's user namespace (init), the target's parent at or
// below the client's. Reads are pidfd-checked after (S13), so accurate.
pred authorize[c, t: Process] {
  Req.rstage = RIdle and c + t in Process
  c.principal.domain = Sandbox
  c.uid = HostUser and t.uid = HostUser and c.userns != InitUserNS
  t.userns != InitUserNS
  Below in G7.on implies t.userns.parent in c.userns.*~parent
  Req.rstage' = Authorized and Req.client' = c and Req.cns' = c.userns
  Req.tgt' = t and Req.tpid' = t.pid and Req.tns' = t.userns and Req.pu' = t.userns.parent
  no Req.landed'
  Process' = Process and keepAll[Process] and chkKeep[Chk]
}

// The target moves: unshare(CLONE_NEWUSER) into a new child, or setns
// into a user namespace it holds CAP_SYS_ADMIN in.
pred moveTarget[t: Process, u: UserNS] {
  t in Process and t.principal.domain = Sandbox and u != t.userns
  (u.parent = t.userns and u.owner = t.uid and no userns.u) or canJoinUser[t, u]
  t.uid in u.mapped
  Process' = Process and keepAll[Process - t]
  t.principal' = t.principal and t.pid' = t.pid and t.ppid' = t.ppid and t.uid' = t.uid
  t.caps' = Cap and t.userns' = u and t.mnt' = t.mnt and t.net' = t.net and t.pidns' = t.pidns
  reqKeep and chkKeep[Chk]
}

// write-map in pu: opens uid_map through the pinned directory (or by
// pid, without PinDir) and writes; the map lands in the user namespace
// the task is in at the open.
pred writeMap {
  Req.rstage = Authorized
  let t = (PinDir in G7.on => Req.tgt else pid.(Req.tpid) & Process) {
    // pu's own map is written already (T's owner is mapped in it), and
    // a map is written once
    (no t or t.userns = Req.pu
      or (OpenerRule in G7.on and Req.pu != t.userns.parent)) implies
      (Req.rstage' = Refused and no Req.landed')
    else (Req.rstage' = Written and Req.landed' = t.userns)
  }
  Req.client' = Req.client and Req.cns' = Req.cns and Req.tgt' = Req.tgt
  Req.tpid' = Req.tpid and Req.tns' = Req.tns and Req.pu' = Req.pu
  Process' = Process and keepAll[Process] and chkKeep[Chk]
}

fact moves {
  always (
    (Process' = Process and keepAll[Process] and chkKeep[Chk] and reqKeep)
    or (some p: Process | exit[p])
    or (some p: Process' - Process | spawn[p] and chkKeep[Chk] and reqKeep)
    or (some c: Chk, p: Process | connect[c, p] and Process' = Process and keepAll[Process] and reqKeep)
    or (some c: Chk | (aliveStep[c] or readStep[c]) and Process' = Process and keepAll[Process] and reqKeep)
    or (some c, t: Process | authorize[c, t])
    or (some t: Process, u: UserNS | moveTarget[t, u])
    or writeMap)
}

fact start { hostPlaced and reach and sbPinned }

pred guarded7 { G7.on = Guard7 }

// S13 for subid-broker and netns-netkit: what they read is about the
// pidfd's process. Holds. Revert: with their order swapped to alive then
// read, counterexample found (as for the broker below).
assert S13readThenAlive {
  always all c: SubidChk + NetkitChk | c.stage = Done implies c.seen = c.actual
}
check S13readThenAlive for 3 but 5 UserNS, 11 OwnedNS, 3 Pid, 8 StorePath, 0 LaterExec, 1..7 steps expect 0

// S13 for the broker: control.sock's and share's checks read the peer's
// /proc/<pid>/ns, then check the pidfd's process is still alive
// (peer.gone, sockets.go), as request's session walk does. Holds.
// Revert: with their order AliveThenRead, as before the fix, a peer that
// exits between the two, its pid gone to a host process, passes
// control.sock's check (counterexample found).
assert S13brokerAliveThenRead {
  always all c: CtlChk + ShareChk | c.stage = Done implies c.seen = c.actual
}
check S13brokerAliveThenRead for 3 but 5 UserNS, 11 OwnedNS, 3 Pid, 8 StorePath, 0 LaterExec, 1..7 steps expect 0

run S13checksFinish {
  (eventually CtlChk.stage = Done) and (eventually SubidChk.stage = Done)
} for 3 but 5 UserNS, 11 OwnedNS, 3 Pid, 8 StorePath, 0 LaterExec, 1..8 steps expect 1

// S7: a map lands only in the user namespace authorize() checked, whose
// parent is the client's or below, though the target unshares, setns'
// or exits and its pid is reused in between. Holds. Revert: without the
// kernel's opener rule, a target that unshared after the check gets the
// map in its new namespace (counterexample found); without the pinned
// directory, a recycled pid's process in a sibling does (found). The
// parent condition (S7below) holds in both: the write runs in the
// checked parent.
assert S7landsInChecked {
  guarded7 implies always (some Req.landed implies Req.landed = Req.tns)
}
check S7landsInChecked for 4 but 6 UserNS, 11 OwnedNS, 4 Pid, 8 StorePath, 0 LaterExec, 1..7 steps expect 0

// Revert: without below(), a client in a nested namespace gets a map
// written for a sibling's (counterexample found).
assert S7below {
  guarded7 implies always (some Req.landed implies Req.landed.parent in Req.cns.*~parent)
}
check S7below for 4 but 6 UserNS, 11 OwnedNS, 4 Pid, 8 StorePath, 0 LaterExec, 1..7 steps expect 0

run S7targetMovesFirst {
  guarded7 and eventually (Req.rstage = Authorized and some t: Process, u: UserNS | moveTarget[t, u]
    and t = Req.tgt)
} for 4 but 6 UserNS, 11 OwnedNS, 4 Pid, 8 StorePath, 0 LaterExec, 1..7 steps expect 1

// S13's broker race as the attacker wants it, a sandbox peer's request
// to control.sock passing the check on a host process's namespaces, is
// gone with the check after the read (an instance before the fix).
assert S13sandboxPeerPassesControl {
  not eventually (CtlChk.stage = Done and CtlChk.seen = InitUserNS and CtlChk.peerNs != InitUserNS)
}
check S13sandboxPeerPassesControl for 3 but 5 UserNS, 11 OwnedNS, 3 Pid, 8 StorePath, 0 LaterExec, 1..7 steps expect 0
