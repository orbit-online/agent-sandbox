/*
 * The grants' lifecycle: P3, P4, P9-P13 over the system in protocol.als,
 * with the findings about replay, forget and exclusive instances. As in
 * protocol-consent.als, each claim has a `run` for its premise, and
 * "Revert:" names the check dropped to see it fail (tried 2026-10-31).
 */
open protocol_system

// HIDE: Id Cap UserNS OwnedNS MountNS NetNS IpcNS UtsNS CgroupNS PidNS Pid Process File MountFlag Mount PeerCheck Socket Domain

// P3, type C. A folder is mounted only if what its parameters resolve to
// at mount time is beneath the ceiling: mountC resolves again and
// clone-tree opens it without links or mount crossings (mounts.go:702-716,
// 228-283), so a rename after the question can't reach outside.
// Revert: mountChecks true: the notification's Allow mounts what the
// sandbox renamed into place after asking.
assert P3folderWithinCeiling {
  always all g: Grant | (born[g] and g.gcap.dtype = TypeC) implies g.gparams.resolves in InCeiling
  always all g: Mounted | g.mdir in InCeiling
}
check P3folderWithinCeiling for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 0
run P3folders {
  eventually some g: Grant | born[g] and g.gcap.dtype = TypeC
  eventually some r: Req, g: Grant | r.rcap.dtype = TypeC and (notifAllow[r, g] or fromStore[r, g])
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 1

// P3, types A and B: the parameters match an instance `list` prints at
// grant time. Known, minor: request() runs inList before asking
// (broker.go:561) and again only for parameters the window sends
// (611-625); an Allow on the notification up to 2 minutes later grants
// whatever `list` says by then. replay("A") at start never runs `list`
// (broker.go:1053-1066), see P12.
assert P3listedAtGrant {
  always all g: Grant | (born[g] and g.gcap.dtype != TypeC) implies passes[g.gcap, g.gparams]
}
check P3listedAtGrant for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Session, 2 Grant, 2 Req, 1 Text, 3 Int, 1..6 steps expect 1

// The folder the user is asked about is the one mounted. Known, by design
// (docs/permissions.md, "A grant is of the path"): between the question
// and mountC, and between launches for an always folder, the sandbox can
// rename another directory under the same ceiling root into the path; P3
// still holds.
assert P3mountedIsShown {
  always all r: Req, g: Grant | (notifAllow[r, g] and g.gcap.dtype = TypeC) implies g.gparams.resolves = r.shownDir
}
check P3mountedIsShown for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 2 Dir,
  1 Session, 2 Grant, 2 Req, 1 Text, 3 Int, 1..7 steps expect 1

// P4. A grant that ended is dead: its type A unit and socket are gone
// (stopServe, BindsTo= on a crash) and its folder detached (unmountC), the
// latter only once ExecStopPost or the next start has run after a crash.
// Revert: bindsTo with UnitUp unchanged; or cleanup leaving Mounted: a
// counterexample either way.
assert P4endedIsDead {
  always no (UnitUp - Live)
  always all g: Mounted - Live | g.gl in Dirty
}
check P4endedIsDead for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 0
run P4ends {
  eventually some g: Grant | g in Ended and g.gcap.dtype = TypeA
  eventually some l: Launcher | crash[l] and some Mounted & gl.l
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 1

// P4, type B: no credential once the grant ended. A request a live type
// B grant covers waits for one of four plugin slots (plugins.go); deliver
// checks the grant is still live once it has one, before `issue` runs,
// and again before handing the credential out (consent.go). Holds.
// Revert: issue without `g in Live` (as before the fix): the sandbox
// queues requests, the user revokes, the queued ones issue credentials
// of the full maxValidity (counterexample found).
assert P4noCredentialAfterEnd {
  always all g: Grant | credential[g] implies g in Live
}
check P4noCredentialAfterEnd for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Session, 2 Grant, 3 Req, 1 Text, 3 Int, 1..7 steps expect 0

// P9. No lock lease is granted while the lock isn't watched. checkLease
// runs before asking and again on the answer, and grant() refuses a lock
// lease when lockOK is false under the lock that watchLogind clears it
// under (leases.go). Holds. Revert: the lease checked after the answer
// only when it differs from the request's (as before the fix): lockOK
// turning false while the notification is up ends the live lock leases,
// then the Allow makes one nothing will end (counterexample found).
assert P9noLockLeaseUnwatched {
  always all g: Grant | (born[g] and g.glease = LLock) implies g.gl in Watched
}
check P9noLockLeaseUnwatched for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Session, 2 Grant, 2 Req, 1 Text, 3 Int, 1..7 steps expect 0

// P9. A lock lease ends on Lock, LockedHint or PrepareForSleep, and when
// the watch is lost (lockEvent, broker.go:986-992, 1364).
// Revert: lockEv ending nothing: counterexample.
assert P9lockEnds {
  always all l: Launcher | (lockEv[l] or lockLost[l]) implies after no Live & gl.l & glease.LLock
}
check P9lockEnds for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 0
run P9locks {
  eventually some l: Launcher | lockEv[l] and some Live & gl.l & glease.LLock
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 1

// P10. A credential's validity is at most maxValidity and at most what is
// left of a duration lease (validity, broker.go:676-684), and none is
// issued at zero (643-646).
// Revert: validity = maxV alone: counterexample.
assert P10validityBounded {
  always all g: Grant | credential[g] implies
    (validity[g] <= g.gcap.maxV and (g.glease = LDuration implies validity[g] <= g.left))
}
check P10validityBounded for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 0
run P10credentials {
  eventually some g: Grant | credential[g] and g.glease = LDuration and g.left < g.gcap.maxV
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 1

// P11. Every grant ends with the daemon and with the sandbox: no live
// grant of a launcher whose daemon is down, nothing of a launcher whose
// sandbox ended (BindsTo, ExecStopPost, endAll at broker.go:234).
// Revert: crash keeping Live: counterexample.
assert P11endsWithDaemonAndSandbox {
  always all l: Launcher - Up | no Live & gl.l
  always all l: Gone | no (Live + UnitUp + Mounted + Issuing) & gl.l
}
check P11endsWithDaemonAndSandbox for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 0
run P11restarts {
  eventually some l: Launcher | crash[l] and some Live & gl.l and eventually start[l]
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 1

// P12. After the daemon starts, its live grants are exactly the stored
// always grants that pass P3 (types A and C; B is issued on request),
// C only once the grant directory is shared. Known, a finding: replay("A")
// starts a stored type A grant without `list` (broker.go:1053-1066), so an
// always grant of a VM that no longer runs, or another one's name, is
// started again.
assert P12replayIsStoreUnderCeiling {
  always all l: Launcher | start[l] implies
    { c: Capability, p: Param | some g: Live' & gl.l | g.gcap = c and g.gparams = p }
    = { c: Capability, p: Param | p in l.stored[c] and passes[c, p] and c.dtype != TypeB
        and (c.dtype = TypeC implies l in SharedDir) and (c in Exclusive implies no p.(c.lockFile) - l) }
}
check P12replayIsStoreUnderCeiling for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Session, 2 Grant, 2 Req, 1 Text, 3 Int, 1..4 steps expect 1
run P12replays {
  eventually some l: Launcher | start[l] and some (Live' - Live) & typed[TypeC]
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..6 steps expect 1

// One live grant per launcher, capability and parameters. Known, a
// finding: replay("C") looks for no live grant, and shareFrom runs it on
// every `share` from M1 (broker.go:485-497), which udhcpc's script may
// send: each `share` mounts every always folder once more. A window
// answer narrowing to parameters already granted makes a second grant too
// (broker.go:611-626 never calls `matching`).
assert P12noDuplicateGrants {
  always all disj g, h: Live | not (g.gl = h.gl and g.gcap = h.gcap and g.gparams = h.gparams)
}
check P12noDuplicateGrants for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Session, 2 Grant, 2 Req, 1 Text, 3 Int, 1..5 steps expect 1

// Forget leaves no live always grant of its parameters. Known, a finding,
// from the duplicates above: forget ends the one grant `matching` returns
// in map order (broker.go:1100-1102), and only if that one's lease is
// always; the other copies stay mounted with no store entry behind them.
assert P12forgetEndsAlways {
  always all l: Launcher, c: Capability, p: Param, w: Principal, g: Grant |
    forget[l, c, p, w, g] implies after no h: Live | h.gl = l and h.gcap = c and h.gparams = p and h.glease = LAlways
}
check P12forgetEndsAlways for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Session, 3 Grant, 2 Req, 1 Text, 3 Int, 1..6 steps expect 1

// P13. Two launchers never hold the same exclusive parameters at once
// (exclusiveLock's O_EXCL file, plugins.go:369-392; a crashed daemon's
// stay until its cleanup).
// Revert: exclusiveLockFree true: counterexample.
assert P13exclusiveByParams {
  always all disj g, h: Live | (g.gcap = h.gcap and g.gcap in Exclusive) implies g.gparams != h.gparams
}
check P13exclusiveByParams for 3 but 0 Process, 2 Launcher, 1 Capability, 2 Param, 2 Instance, 1 Dir,
  1 Session, 3 Grant, 3 Req, 1 Text, 3 Int, 1..7 steps expect 0
run P13twoLaunchers {
  eventually some disj g, h: Live | g.gl != h.gl and g.gcap = h.gcap and g.gcap in Exclusive
} for 3 but 0 Process, 2 Launcher, 1 Capability, 2 Param, 2 Instance, 1 Dir,
  1 Session, 3 Grant, 3 Req, 1 Text, 3 Int, 1..7 steps expect 1

// P13 as the README states it: an exclusive instance (what `list`
// prints) at most one launcher at a time. Known, latent: the lock is
// named by all the parameters' hash, while a request matches an instance
// when the instance's keys agree (inList, plugins.go:334-365). A
// capability with a parameter `list` doesn't print (a mode, a read-only
// flag) lets two launchers take one VM with different values of it.
// windows-vm's manifest decides whether this is live.
assert P13exclusiveByInstance {
  always all disj g, h: Live | (g.gcap = h.gcap and g.gcap in Exclusive and g.gl != h.gl)
    implies no g.gparams.(g.gcap.matches) & h.gparams.(h.gcap.matches)
}
check P13exclusiveByInstance for 3 but 0 Process, 2 Launcher, 1 Capability, 2 Param, 1 Instance, 1 Dir,
  1 Session, 2 Grant, 2 Req, 1 Text, 3 Int, 1..7 steps expect 1
