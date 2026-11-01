/*
 * The grants' lifecycle: P3, P4, P9-P13 and P15 over the system in
 * protocol.als, with the findings about the start's standing grants and
 * exclusive instances, and the holds that releases and session ends drop. As in
 * protocol-consent.als, each claim has a `run` for its premise, and
 * "Revert:" names the check dropped to see it fail (tried 2026-10-31).
 */
open protocol_system

// HIDE: Id Cap UserNS OwnedNS MountNS NetNS IpcNS UtsNS CgroupNS PidNS Pid Process File MountFlag Mount PeerCheck Socket Domain

// P3, attach. A folder is mounted only if what its parameters resolve to
// at mount time is beneath the ceiling: attachGrant resolves again and
// clone-tree opens it without links or mount crossings (mounts.go:702-716,
// 228-283), so a rename after the question can't reach outside.
// Revert: mountChecks true: the notification's Allow mounts what the
// sandbox renamed into place after asking.
assert P3folderWithinCeiling {
  always all g: Grant | (born[g] and g.gcap.dtype = Attach) implies g.gparams.resolves in InCeiling
  always all g: Mounted | g.mdir in InCeiling
}
check P3folderWithinCeiling for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 0
run P3folders {
  eventually some g: Grant | born[g] and g.gcap.dtype = Attach
  eventually some r: Req, g: Grant | r.rcap.dtype = Attach and notifAllow[r, g]
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 1

// P3, service and command: the parameters match an instance `list` prints at
// grant time. request() runs inList before asking and again on every
// answer (consent.go), start before granting a standing grant (run.go). Holds. Revert: notifAllow without its `list` (as before the
// fix): an Allow up to 2 minutes later grants whatever `list` says by
// then (counterexample found).
assert P3listedAtGrant {
  always all g: Grant | (born[g] and g.gcap.dtype != Attach) implies passes[g.gcap, g.gparams]
}
check P3listedAtGrant for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Session, 2 Grant, 2 Req, 1 Text, 3 Int, 1..6 steps expect 0

// P4. A grant that ended is dead: its service unit and socket are gone
// (stopServe, BindsTo= on a crash) and its folder detached (detachGrant, the
// holders' scan only after, so the sandbox can't hold the detach up with
// namespaces and mounts for it to read; the end is one step here), the
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
  eventually some g: Grant | g in Ended and g.gcap.dtype = Service
  eventually some l: Launcher | crash[l] and some Mounted & gl.l
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 1

// P4, command: no credential once the grant ended. A request a live
// command grant covers waits for one of four plugin slots (plugins.go); deliver
// checks the grant is still live once it has one, before `run` runs,
// and again before handing the credential out (consent.go). Holds.
// Revert: runCommand without `g in Live` (as before the fix): the sandbox
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
  always all l: Gone | no (Live + UnitUp + Mounted + ToRun) & gl.l
}
check P11endsWithDaemonAndSandbox for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 0
run P11restarts {
  eventually some l: Launcher | crash[l] and some Live & gl.l and eventually start[l]
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 1

// P12. After the daemon starts, its live grants are exactly the standing
// grants of the config that pass P3 and the exclusive lock (service and
// command; a command runs on request). start runs `list` as a request
// does (run.go), and nothing of the earlier daemon's life survives. Holds.
// Revert: standingOK without `list`: a standing grant of a VM that isn't
// running is started (counterexample, tried 2026-11-01).
assert P12startIsStandingUnderCeiling {
  always all l: Launcher | start[l] implies
    { c: Capability, p: Param | some g: Live' & gl.l | g.gcap = c and g.gparams = p }
    = { c: Capability, p: Param | p in l.standing[c] and passes[c, p]
        and (c in Exclusive implies no p.(c.matches).(c.lockFile) - l) }
}
check P12startIsStandingUnderCeiling for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Session, 2 Grant, 2 Req, 1 Text, 3 Int, 1..4 steps expect 0
run P12starts {
  eventually some l: Launcher | start[l] and some (Live' - Live) & typed[Service]
  eventually some l: Launcher | start[l] and some (Live' - Live) & typed[Command]
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..6 steps expect 1

// P12. A restart brings back what the user ended: after a start, every
// standing grant that passes is live again, whether or not it was revoked
// or released before (start clears what was ended, run.go). Revert: start
// keeping `ended` and granting only standing grants not in it: a revoked
// one stays out after a restart (counterexample, tried 2026-11-01).
assert P12restartRestoresStanding {
  always all l: Launcher, c: Capability, p: l.standing[c] |
    (start[l] and passes[c, p] and (c in Exclusive implies no p.(c.matches).(c.lockFile) - l))
      implies after some g: Live | g.gl = l and g.gcap = c and g.gparams = p and g.glease = LStanding
}
check P12restartRestoresStanding for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Session, 3 Grant, 2 Req, 1 Text, 3 Int, 1..7 steps expect 0

// One live grant per launcher, capability and parameters. A request a
// live grant covers uses it, a standing one included (matching, before
// isStanding), and an answer that finds a grant of the same made while
// the user was asked uses it (consent.go, all under c.covered). Holds.
// Revert: fromConfig without the look for a live grant: a second request
// for a live standing grant starts another (counterexample, tried
// 2026-11-01).
assert P12noDuplicateGrants {
  always all disj g, h: Live | not (g.gl = h.gl and g.gcap = h.gcap and g.gparams = h.gparams)
}
check P12noDuplicateGrants for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Session, 2 Grant, 2 Req, 1 Text, 3 Int, 1..5 steps expect 0

// P13. Two launchers never hold the same exclusive parameters at once
// (exclusiveLock's O_EXCL files, instances.go; a crashed daemon's
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
// prints) at most one launcher at a time. The lock is on each instance
// the parameters match (instances.go). Holds. Revert: the lock named by
// all the parameters' hash (as before the fix): a parameter `list`
// doesn't print (a mode, a read-only flag) lets two launchers take one
// VM with different values of it (counterexample found).
assert P13exclusiveByInstance {
  always all disj g, h: Live | (g.gcap = h.gcap and g.gcap in Exclusive and g.gl != h.gl)
    implies no g.gparams.(g.gcap.matches) & h.gparams.(h.gcap.matches)
}
check P13exclusiveByInstance for 3 but 0 Process, 2 Launcher, 1 Capability, 2 Param, 1 Instance, 1 Dir,
  1 Session, 2 Grant, 2 Req, 1 Text, 3 Int, 1..7 steps expect 0

// P15. A release by one session never ends a grant another live session
// holds: it drops the caller's hold only (release, leases.go). A caller
// without a session ends it all the same, so s is a session here.
// Revert: release ending the grant always (as this model had it before
// ec044cd): counterexample (tried 2026-11-01).
assert P15releaseKeepsOthersHold {
  always all g: Grant, s: Session | (release[g, s] and some (g.holders & Alive) - s) implies after g in Live
}
check P15releaseKeepsOthersHold for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Session, 2 Grant, 3 Req, 1 Text, 3 Int, 1..8 steps expect 0
run P15holderReleases {
  eventually some g: Grant, s: Session | s in g.holders and some g.holders - s and release[g, s]
} for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Session, 2 Grant, 3 Req, 1 Text, 3 Int, 1..8 steps expect 1

// P15. Every hold is a live session's: a session that ends drops its
// holds on every grant (watchSession, leases.go), so a grant nobody holds
// any more, but for a session lease, given to no caller without a session,
// ends on the next release from any session, and on any release without
// one. Revert: sessionEnd dropping the holds on session leases only (as
// before 48dcd7b): the ended session's hold keeps a duration grant live
// after the other holder releases it (counterexample, tried 2026-11-01).
assert P15releaseEndsUnheld {
  always all g: Live | g.holders in Alive
  always all g: Grant, s: Session | (release[g, s] and g.glease != LSession and g not in Anon
    and no (g.holders & Alive) - s) implies after g not in Live
  always all g: Grant | release[g, none] implies after g not in Live
}
check P15releaseEndsUnheld for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Session, 2 Grant, 3 Req, 1 Text, 3 Int, 1..8 steps expect 0
run P15lastHolderReleases {
  eventually some g: Grant, s, t: Session | g.glease != LSession and s + t in g.holders and s != t
    and sessionEnd[t] and after eventually release[g, s]
} for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Session, 2 Grant, 3 Req, 1 Text, 3 Int, 1..8 steps expect 1

// P15 and P8. A session lease ends exactly when its last holder ends: a
// live one always has a live holder, and a session's end ends it if and
// only if that session was its last holder. A caller without a session
// doesn't hold a session lease (release, leases.go). Revert: release
// counting that caller for a session lease too (as before 48dcd7b): a
// caller without a session matches the grant, its only session releases
// it, and it stays live with no session holding it (counterexample,
// tried 2026-11-01).
assert P15sessionLeaseEndsWithLastHolder {
  always all g: Live & glease.LSession | some g.holders & Alive
  always all g: Grant, s: Session | (sessionEnd[s] and g in Live and g.glease = LSession)
    implies (after g in Live iff some g.holders - s)
}
check P15sessionLeaseEndsWithLastHolder for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Session, 2 Grant, 3 Req, 1 Text, 3 Int, 1..8 steps expect 0
run P15sessionLeaseOutlivesFirstHolder {
  eventually some g: Grant, s: Session | g.glease = LSession and g in Live and some g.holders - s
    and sessionEnd[s] and after eventually (some t: Session | sessionEnd[t] and g in Live)
} for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Session, 2 Grant, 3 Req, 1 Text, 3 Int, 1..8 steps expect 1
