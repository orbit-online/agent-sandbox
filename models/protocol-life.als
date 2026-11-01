/*
 * The grants' lifecycle: P3, P4, P9-P13 over the system in protocol.als,
 * with the findings about replay, forget and exclusive instances. As in
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
  eventually some r: Req, g: Grant | r.rcap.dtype = Attach and (notifAllow[r, g] or fromStore[r, g])
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 1

// P3, service and command: the parameters match an instance `list` prints at
// grant time. request() runs inList before asking and again on every
// answer (consent.go), replay("service") before starting a stored grant
// (store.go). Holds. Revert: notifAllow without its `list` (as before the
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

// P12. After the daemon starts, its live grants are exactly the stored
// always grants that pass P3 (service and attach; a command runs on
// request), attach only once the grant directory is shared.
// replay("service") runs `list` as a request does (store.go). Holds.
// Revert: replayOK without `list` (as before the fix): an always grant of
// a VM that no longer runs is started again (counterexample found).
assert P12replayIsStoreUnderCeiling {
  always all l: Launcher | start[l] implies
    { c: Capability, p: Param | some g: Live' & gl.l | g.gcap = c and g.gparams = p }
    = { c: Capability, p: Param | p in l.stored[c] and passes[c, p] and c.dtype != Command
        and (c.dtype = Attach implies l in SharedDir) and (c in Exclusive implies no p.(c.matches).(c.lockFile) - l) }
}
check P12replayIsStoreUnderCeiling for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Session, 2 Grant, 2 Req, 1 Text, 3 Int, 1..4 steps expect 0
run P12replays {
  eventually some l: Launcher | start[l] and some (Live' - Live) & typed[Attach]
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..6 steps expect 1

// One live grant per launcher, capability and parameters. share runs
// once per sandbox (sockets.go), a replay grants nothing already live,
// and an answer that finds a grant of the same made while the user was
// asked uses it (consent.go, all under c.covered). Holds. Revert: share
// without its once and replays without the look for a live grant (as
// before the fix): udhcpc's script sends share again and every always
// folder is mounted once more (counterexample found; either alone holds).
assert P12noDuplicateGrants {
  always all disj g, h: Live | not (g.gl = h.gl and g.gcap = h.gcap and g.gparams = h.gparams)
}
check P12noDuplicateGrants for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Session, 2 Grant, 2 Req, 1 Text, 3 Int, 1..5 steps expect 0

// Forget leaves no live always grant of its parameters: it ends every
// one (store.go), and with P12noDuplicateGrants there is at most one.
// Holds (a counterexample before both fixes).
assert P12forgetEndsAlways {
  always all l: Launcher, c: Capability, p: Param, w: Principal |
    forget[l, c, p, w] implies after no h: Live | h.gl = l and h.gcap = c and h.gparams = p and h.glease = LAlways
}
check P12forgetEndsAlways for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Session, 3 Grant, 2 Req, 1 Text, 3 Int, 1..6 steps expect 0

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
