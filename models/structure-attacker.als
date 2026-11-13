/*
 * S1-S4 over time: the sandbox's processes start where the code puts
 * them (structure.als's sandboxStart) and then do anything the kernel
 * lets them, one move per step: unshare a user, mount or network
 * namespace, setns, fork (into a new pid namespace too), setuid, exec,
 * or take over a process they may ptrace. The host's processes stay as
 * they are. Maps are written when a namespace is made (subid-broker or
 * the creator's own one-id map); when exactly is S7's business, in
 * structure-race.als.
 *
 * Exec gains nothing beyond what a process has, except all
 * capabilities for inner root of its own user namespace: bwrap sets
 * no_new_privs for everything in the sandbox, so setuid and file
 * capabilities don't apply (bwrap sets it for what it starts, cmd/launcher
 * enter.go:111 for re-entries). Takeover ignores Yama, so the attacker here is stronger than
 * on a host with ptrace_scope 1.
 */
open structure

// The attacker's processes: the sandbox's, and what it took over.
var sig Evil in Process {}
// User namespaces the attacker made.
var sig Made in UserNS {}
// Namespaces in use; the rest are free for unshare.
var sig UsedU in UserNS {}
var sig UsedO in OwnedNS {}

fact init {
  hostPlaced and sandboxStart
  Evil = sandboxProcs
  no Made
  UsedU = Process.userns and UsedO = Process.(mnt + net + pidns)
  InitUserNS + U1 + U2 in UsedU
  HostMnt + M1 + M2 + HostNet + N + InitPidNS + P + P2 in UsedO
}

fact staticMaps { always mapped' = mapped }

pred keep[q: Process] {
  q in Process'
  q.principal' = q.principal and q.pid' = q.pid and q.ppid' = q.ppid
  q.uid' = q.uid and q.caps' = q.caps and q.userns' = q.userns
  q.mnt' = q.mnt and q.net' = q.net and q.pidns' = q.pidns
}

// Everything but p stays; p keeps what the move doesn't set.
pred others[p: Process] {
  Process' = Process
  all q: Process - p | keep[q]
  p.principal' = p.principal and p.pid' = p.pid and p.ppid' = p.ppid
  p.pidns' = p.pidns
  Evil' = Evil and UsedO' = UsedO
}

// unshare(CLONE_NEWUSER): a fresh child of its namespace, owned by its
// euid, with every capability there.
pred unshareUser[p: Process, u: UserNS] {
  p in Evil and u not in UsedU
  u.parent = p.userns and u.owner = p.uid and p.uid in u.mapped
  others[p]
  p.userns' = u and p.caps' = Cap and p.uid' = p.uid
  p.mnt' = p.mnt and p.net' = p.net
  UsedU' = UsedU + u and Made' = Made + u
}

// setns(2) into a user namespace: every capability there.
pred joinUser[p: Process, u: UserNS] {
  p in Evil and u in UsedU and canJoinUser[p, u] and p.uid in u.mapped
  others[p]
  p.userns' = u and p.caps' = Cap and p.uid' = p.uid
  p.mnt' = p.mnt and p.net' = p.net
  UsedU' = UsedU and Made' = Made
}

// unshare(CLONE_NEWNS / CLONE_NEWNET): needs CAP_SYS_ADMIN in its own.
pred unshareOther[p: Process, n: MountNS + NetNS] {
  p in Evil and n not in UsedO
  hasCap[p, p.userns, SysAdmin] and n.ownedBy = p.userns
  Process' = Process and (all q: Process - p | keep[q])
  p.principal' = p.principal and p.pid' = p.pid and p.ppid' = p.ppid and p.pidns' = p.pidns
  p.uid' = p.uid and p.caps' = p.caps and p.userns' = p.userns
  n in MountNS implies (p.mnt' = n and p.net' = p.net) else (p.net' = n and p.mnt' = p.mnt)
  Evil' = Evil and UsedU' = UsedU and Made' = Made and UsedO' = UsedO + n
}

pred joinOther[p: Process, n: MountNS + NetNS] {
  p in Evil and n in UsedO and canJoin[p, n]
  others[p]
  p.uid' = p.uid and p.caps' = p.caps and p.userns' = p.userns
  n in MountNS implies (p.mnt' = n and p.net' = p.net) else (p.net' = n and p.mnt' = p.mnt)
  UsedU' = UsedU and Made' = Made
}

// setuid(2) to an id of its namespace: CAP_SETUID there.
pred setuid[p: Process, i: Id] {
  p in Evil and hasCap[p, p.userns, SetUid] and i in p.userns.mapped
  others[p]
  p.uid' = i and p.caps' = p.caps and p.userns' = p.userns
  p.mnt' = p.mnt and p.net' = p.net
  UsedU' = UsedU and Made' = Made
}

// execve(2) under no_new_privs: keeps what it has (ambient), drops any,
// or, as its namespace's inner root, gets them all.
pred exec[p: Process] {
  p in Evil
  p.caps' in p.caps or p.uid = NsRoot.of[p.userns]
  others[p]
  p.uid' = p.uid and p.userns' = p.userns
  p.mnt' = p.mnt and p.net' = p.net
  UsedU' = UsedU and Made' = Made
}

// fork(2), the child in p's pid namespace or a new one below it
// (unshare(CLONE_NEWPID) needs CAP_SYS_ADMIN in its user namespace).
pred fork[p, c: Process] {
  p in Evil and c not in Process and c in Process'
  Process' = Process + c and (all q: Process | keep[q])
  c.principal' = p.principal and c.ppid' = p and c.uid' = p.uid and c.caps' = p.caps
  c.userns' = p.userns and c.mnt' = p.mnt and c.net' = p.net
  c.pidns' = p.pidns or {
    c.pidns' not in UsedO and c.pidns'.pparent = p.pidns
    c.pidns'.ownedBy = p.userns and hasCap[p, p.userns, SysAdmin]
  }
  Evil' = Evil + c and UsedU' = UsedU and Made' = Made and UsedO' = UsedO + c.pidns'
}

// ptrace(2) by commoncap's rule (security/commoncap.c,
// cap_ptrace_access_check): same euid and, in the same user namespace,
// the target's capabilities a subset of the tracer's; or CAP_SYS_PTRACE
// in the target's. And the target in sight.
pred takeover[p, q: Process] {
  p in Evil and q not in Evil and sees[p, q]
  (p.uid = q.uid and p.userns = q.userns and q.caps in p.caps)
    or hasCap[p, q.userns, SysPtrace]
  Process' = Process and (all r: Process | keep[r])
  Evil' = Evil + q and UsedU' = UsedU and Made' = Made and UsedO' = UsedO
}

pred stutter {
  Process' = Process and (all q: Process | keep[q])
  Evil' = Evil and UsedU' = UsedU and Made' = Made and UsedO' = UsedO
}

fact moves {
  always (stutter
    or (some p: Process, u: UserNS | unshareUser[p, u] or joinUser[p, u])
    or (some p: Process, n: MountNS + NetNS | unshareOther[p, n] or joinOther[p, n])
    or (some p: Process, i: Id | setuid[p, i])
    or (some p: Process | exec[p])
    or (some p, c: Process | fork[p, c])
    or (some p, q: Process | takeover[p, q]))
}

// The scope: the init namespaces, the sandbox's, and room for two user
// namespaces and two others the attacker makes.

// S1: no attacker process has a capability in the init user namespace,
// so none over any namespace the host owns. Holds. Revert: start bwrap's
// init in the init user namespace (bwrap without --unshare-user, which
// dropping nixpak's --unshare-user-try prevents, cmd/launcher
// bwrap.go:86): it owns U1, and S2, S3 and S4 get counterexamples (found).
// S1 itself holds even then, as nothing gains a capability in init
// under no_new_privs.
assert S1noInitCaps {
  always all p: Evil, c: Cap | not hasCap[p, InitUserNS, c]
}
check S1noInitCaps for 5 but 6 UserNS, 12 OwnedNS, 7 Id, 1..4 steps expect 0

// S2: no attacker process holds a capability in U1, so none over N, M1,
// P and the rest U1 owns. Holds. Revert: exec raising any capability (no
// no_new_privs, a setcap or setuid binary in reach) gives bwrap's init
// CAP_SYS_ADMIN in U1 (counterexample found).
assert S2noCapsInU1 {
  always all p: Evil, c: Cap | not hasCap[p, U1, c]
}
check S2noCapsInU1 for 5 but 6 UserNS, 12 OwnedNS, 7 Id, 1..4 steps expect 0

// S3: nothing the attacker runs can setns into U1, the init user
// namespace, or any namespace either owns. Holds; the reverts for S1
// and S2 each give a counterexample (found).
assert S3noJoinUp {
  always all p: Evil {
    no u: U1 + InitUserNS | canJoinUser[p, u]
    no n: OwnedNS | n.ownedBy in U1 + InitUserNS and canJoin[p, n]
  }
}
check S3noJoinUp for 5 but 6 UserNS, 12 OwnedNS, 7 Id, 1..4 steps expect 0

// S4: every user namespace the attacker makes is strictly below U1 and
// maps only ids U1 maps. Holds (the kernel's map rule and S3). Not "U2
// or below", as the README had it: bwrap's init runs in U1
// and may unshare a user namespace there, a sibling of U2, which is no
// more than U2 (owned by the user under U1, U1's ids).
assert S4madeBelowU1 {
  always (Made in U1.^~parent and (all u: Made | u.mapped in U1.mapped))
}
check S4madeBelowU1 for 5 but 6 UserNS, 12 OwnedNS, 7 Id, 1..4 steps expect 0

// Vacuity guards: the attacker gets every capability in a namespace of
// its own, and a mount namespace there; it runs in U1 beside bwrap's
// init (S2).
run attackerNests {
  eventually some p: Evil, n: MountNS |
    p.userns in Made and p.mnt = n and n.ownedBy = p.userns and hasCap[p, p.userns, SysAdmin]
} for 5 but 6 UserNS, 12 OwnedNS, 7 Id, 1..4 steps expect 1

run S2attackerInU1 {
  eventually some p: Evil - sb | p.userns = U1
} for 5 but 6 UserNS, 12 OwnedNS, 7 Id, 1..4 steps expect 1

// A U1 attacker (bwrap's init) gets every capability in U2 by
// the owner rule, can setns into U2 and from there into M2. Not one of
// S1-S4; L4 (nothing in U2 holds a capability) assumes U1 is clean.
run u1AttackerOwnsU2 {
  eventually some p: Evil | p.userns = U2 and p.mnt = M2 and hasCap[p, U2, SysAdmin]
} for 5 but 6 UserNS, 12 OwnedNS, 7 Id, 1..4 steps expect 1
