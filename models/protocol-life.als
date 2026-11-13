/*
 * The grants' lifecycle: P3, P4 and P9-P13 over the system in
 * protocol.als, with the findings about the start's standing grants and
 * exclusive instances. As in protocol-consent.als, each claim has a `run`
 * for its premise, and "Revert:" names the check dropped to see it fail
 * (tried 2026-10-31, and 2026-11-03 for the calls, connections and
 * instances).
 */
open protocol_system

// HIDE: Id Cap UserNS OwnedNS MountNS NetNS IpcNS UtsNS CgroupNS PidNS Pid Process File MountFlag Mount PeerCheck Socket Domain

// P3, attach. A folder is mounted only if what its parameters resolve to
// at mount time is beneath the ceiling: attachGrant resolves again and
// clone-tree opens it without links or mount crossings (attach.go,
// tree.go), so a rename after the question can't reach outside.
// Revert: mountChecks true: the notification's Allow mounts what the
// sandbox renamed into place after asking.
assert P3folderWithinCeiling {
  always all g: Grant | (born[g] and g.gcap.dtype = Attach) implies g.gparams.resolves in InCeiling
  always all g: Mounted | g.mdir in InCeiling
}
check P3folderWithinCeiling for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 0
run P3folders {
  eventually some g: Grant | born[g] and g.gcap.dtype = Attach
  eventually some r: Req, g: Grant | r.rcap.dtype = Attach and notifAllow[r, g]
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 1

// P3, host sockets and host commands: the parameters match an instance
// the instances glob finds at grant time. obtain runs inList before
// asking and again on every answer (consent.go), grantStanding before
// granting a standing grant (standing.go). Holds. Revert: notifAllow
// without its inList (as before the fix): an Allow up to 2 minutes later
// grants whatever the glob found by then (counterexample found).
assert P3listedAtGrant {
  always all g: Grant | (born[g] and g.gcap.dtype != Attach) implies passes[g.gcap, g.gparams]
}
check P3listedAtGrant for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Grant, 2 Req, 0 Conn, 1 Text, 3 Int, 1..6 steps expect 0

// P4. A grant that ended is dead: no call of it runs (runCall stops its
// unit when the grant ends, call.go; BindsTo= the daemon's unit on a
// crash), no connection is spliced under it (g.end closes them,
// closeConns in splice.go; on a crash they close with the daemon's
// process), and its folder is detached (detachGrant, the holders' scan
// only after, so the sandbox can't hold the detach up with namespaces and
// mounts for it to read; the end is one step here), the latter only once
// ExecStopPost or the next start has run after a crash.
// Revert: stopCalls without the calls of E; closeConns closing nothing;
// bindsTo with Running unchanged; cleanup leaving Mounted: a
// counterexample each (2026-11-03).
assert P4endedIsDead {
  always no Running.under - Live
  always no Spliced.via - Live
  always all g: Mounted - Live | g.gl in Dirty
}
check P4endedIsDead for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 1 Conn, 2 Text, 3 Int, 1..8 steps expect 0
// P4's premise: a revoke while a call runs under the grant, a release
// while a connection is spliced under it, and a crash with a folder
// mounted.
run P4ends {
  eventually some g: Grant | some under.g & Running and revoke[g, WindowP]
} for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Grant, 2 Req, 0 Conn, 1 Text, 3 Int, 1..8 steps expect 1
run P4endsSpliced {
  eventually some g: Grant | some via.g & Spliced and release[g]
} for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Grant, 2 Req, 1 Conn, 1 Text, 3 Int, 1..8 steps expect 1
run P4crashMounted {
  eventually some l: Launcher | crash[l] and some Mounted & gl.l
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 1

// P18. The host reaches a port of the sandbox only under a live grant of
// it or a pending revoke: the port is on while its grant lives, after
// that only while the daemon records it closing (its revoke failed and is
// tried again), and the ports of a crashed daemon only until ExecStopPost
// or the next start ran its cleanup, which tries until the helper revokes
// them (live, end, portOff and closePort of portKind, revokePorts in
// cleanup, ports.go; the helper switching it in the ports map of the
// sandbox, netns-netkit bpf.go). A grant that switched its port on and
// then failed to find its addresses leaves it closing as an end does.
// Revert: change keeping Forwarded for E; change not recording F as
// Closing; cleanup leaving Forwarded; start keeping those of the old
// daemon: a counterexample each (2026-11-12). stopPost done while the
// helper fails (one try of revoke --all, as before 2026-11-13); dropPort
// leaving the port on without recording g: a counterexample each
// (2026-11-13).
assert P18portsLive {
  always Forwarded in typed[Fwd]
  always Closing in Forwarded - Live
  always all g: Forwarded - Live | g.gl in Dirty or g in Closing
}
check P18portsLive for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 1 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 0
// P18's premise: a port granted and revoked, a crash with a port on that
// the cleanup switches off, and a cleanup failing first.
run P18ports {
  eventually some g: Grant | g.gcap.dtype = Fwd and revoke[g, WindowP]
  some l: Launcher | eventually (crash[l] and some Forwarded & gl.l and after (stopPost[l] and l in Failing
    and after eventually stopPost[l]))
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 1 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 1

// P18, once the helper revokes again: every closing port goes off. A
// record goes only with its port off, with a grant of the port, or with
// the daemon, whose cleanup switches the port off. The tries of closePort
// are weakly fair: one enabled from some step on is taken.
// Revert: crash keeping Closing: the record outlives the daemon, which
// tries no more (counterexample, 2026-11-12).
assert P18closingEnds {
  ((eventually always no Failing) and (all g: Grant | (eventually always closeEnabled[g]) implies
    (always eventually closeRetry[g])))
  implies (all g: Grant | always (g in Closing implies eventually g not in Closing))
}
check P18closingEnds for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 1 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 0
// The premise of P18: the revoke of a port failing, then a grant of it
// again, a try succeeding for another, and a grant that failed after
// switching its port on left closing.
run P18closing {
  some g: Grant | eventually (g in Closing and after some samePort[g] & Live - g)
  some g: Grant | eventually closeRetry[g]
  some r: Req, g: Grant | eventually (dropPort[r, g] and after g in Closing)
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 1 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 1

// P4, host commands: no call starts once its grant ended. A call a live
// grant covers waits for its slot (callSlot, call.go); runCall checks the
// grant is still live once it has one, before the unit starts, and again
// before handing out the output. Holds.
// Revert: startCall without `r.under in Live` (as runCommand before the
// fix): the sandbox queues calls, the user revokes, the queued ones run
// (counterexample, 2026-11-03).
assert P4noCallAfterEnd {
  always all r: Req | startCall[r] implies r.under in Live
}
check P4noCallAfterEnd for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Grant, 3 Req, 0 Conn, 1 Text, 3 Int, 1..7 steps expect 0

// P9. No lock lease is granted while the lock isn't watched. checkLease
// runs before asking and again on the answer, and grant() refuses a lock
// lease when lockOK is false under the lock that lockSignals clears it
// under (leases.go). Holds. Revert: the lease checked after the answer
// only when it differs from the request's (as before the fix): lockOK
// turning false while the notification is up ends the live lock leases,
// then the Allow makes one nothing will end (counterexample found).
assert P9noLockLeaseUnwatched {
  always all g: Grant | (born[g] and g.glease = LLock) implies g.gl in Watched
}
check P9noLockLeaseUnwatched for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Grant, 2 Req, 0 Conn, 1 Text, 3 Int, 1..7 steps expect 0

// P9. A lock lease ends on Lock, LockedHint or PrepareForSleep, and when
// the watch is lost (lockEvent, lockSignals, leases.go).
// Revert: lockEv ending nothing: counterexample.
assert P9lockEnds {
  always all l: Launcher | (lockEv[l] or lockLost[l]) implies after no Live & gl.l & glease.LLock
}
check P9lockEnds for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 0
run P9locks {
  eventually some l: Launcher | lockEv[l] and some Live & gl.l & glease.LLock
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 1

// P10. The validity a call is given is at most maxValidity and at most
// what is left of a duration lease (callValidity, call.go), and none
// starts at zero.
// Revert: validity = maxV alone: counterexample.
assert P10validityBounded {
  always all r: Req | startCall[r] implies
    (validity[r.under] <= r.under.gcap.maxV and (r.under.glease = LDuration implies validity[r.under] <= r.under.left))
}
check P10validityBounded for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 0
run P10calls {
  eventually some r: Req | startCall[r] and r.under.glease = LDuration and r.under.left < r.under.gcap.maxV
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 1

// P11. Every grant ends with the daemon and with the sandbox: no live
// grant of a launcher whose daemon is down, nothing of a launcher whose
// sandbox ended (call units BindsTo= the daemon's, ExecStopPost's
// cleanup, endAll in run.go).
// Revert: crash keeping Live: counterexample.
assert P11endsWithDaemonAndSandbox {
  always all l: Launcher - Up | no Live & gl.l
  always all l: Gone | no (Live + Mounted + Forwarded) & gl.l and no (Queued + Running).under & gl.l and no Spliced.via & gl.l
}
check P11endsWithDaemonAndSandbox for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 1 Conn, 2 Text, 3 Int, 1..8 steps expect 0
run P11restarts {
  eventually some l: Launcher | crash[l] and some Live & gl.l and eventually start[l]
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 1

// P11. A grant ends when its instance goes: the instance check
// (watchInstance, commands.go, on its timer) ends every grant of a host
// command or host socket whose instance the glob no longer finds. Holds.
// Revert: instanceGone ending nothing: counterexample (2026-11-03).
assert P11endsWithInstance {
  always all l: Launcher | instanceGone[l] implies
    after no g: Live & gl.l - typed[Attach] | no g.gparams.(g.gcap.matches) & Listed
}
check P11endsWithInstance for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 1 Dir,
  2 Grant, 2 Req, 1 Conn, 2 Text, 3 Int, 1..7 steps expect 0
// Until the timer fires, no call starts on an instance that's gone:
// runCall checks inList once it has its slot (call.go). Holds.
// Revert: startCall without the instance: counterexample (2026-11-03).
assert P11noCallOnGoneInstance {
  always all r: Req | startCall[r] implies some r.under.gparams.(r.under.gcap.matches) & Listed
}
check P11noCallOnGoneInstance for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Grant, 3 Req, 0 Conn, 1 Text, 3 Int, 1..7 steps expect 0
// P11's premise: an instance goes, and the check ends a grant of it with
// a connection spliced under it.
run P11instanceGone {
  eventually some l: Launcher | instanceGone[l] and some (Live - Live') & gl.l & Spliced.via
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 1 Dir,
  2 Grant, 2 Req, 1 Conn, 2 Text, 3 Int, 1..7 steps expect 1

// P12. After the daemon starts, its live grants are exactly the standing
// grants of the config that pass P3 and the exclusive lock (host sockets
// and host commands). grantStanding runs inList as a request
// does (standing.go), and nothing of the earlier daemon's life survives.
// Holds. Revert: standingOK without the instances: a standing grant of a
// VM that isn't running is granted (counterexample, tried 2026-11-01).
assert P12startIsStandingUnderCeiling {
  always all l: Launcher | start[l] implies
    { c: Capability, p: Param | some g: Live' & gl.l | g.gcap = c and g.gparams = p }
    = { c: Capability, p: Param | p in l.standing[c] and passes[c, p]
        and (c in Exclusive implies no p.(c.matches).(c.lockFile) - l) }
}
check P12startIsStandingUnderCeiling for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Grant, 2 Req, 0 Conn, 1 Text, 3 Int, 1..4 steps expect 0
run P12starts {
  eventually some l: Launcher | start[l] and some (Live' - Live) & typed[Socket]
  eventually some l: Launcher | start[l] and some (Live' - Live) & typed[Command]
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..6 steps expect 1

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
  3 Grant, 2 Req, 0 Conn, 1 Text, 3 Int, 1..7 steps expect 0

// One live grant per launcher, capability and parameters, once grants
// aside (P16: one covers its own call only, so a call beside it asks
// again). A request a live grant covers uses it, a standing one included
// (matching, before isStanding), and an answer that finds a grant of the
// same made while the user was asked uses it (obtain, consent.go, all
// under c.covered). Holds.
// Revert: fromConfig without the look for a live grant: a second request
// for a live standing grant starts another (counterexample, tried
// 2026-11-01).
assert P12noDuplicateGrants {
  always all disj g, h: Live - glease.LOnce | not (g.gl = h.gl and g.gcap = h.gcap and g.gparams = h.gparams)
}
check P12noDuplicateGrants for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Grant, 2 Req, 0 Conn, 1 Text, 3 Int, 1..5 steps expect 0

// P13. Two launchers never hold the same exclusive parameters at once
// (exclusiveLock's O_EXCL files, instances.go; a crashed daemon's
// stay until its cleanup). One launcher may: a once grant beside another
// shares its lock.
// Revert: exclusiveLockFree true, with lockFile no longer `lone` (the
// O_EXCL file is what makes it so): counterexample (2026-11-03).
assert P13exclusiveByParams {
  always all disj g, h: Live | (g.gcap = h.gcap and g.gcap in Exclusive and g.gl != h.gl) implies g.gparams != h.gparams
}
check P13exclusiveByParams for 3 but 0 Process, 2 Launcher, 1 Capability, 2 Param, 2 Instance, 1 Dir,
  3 Grant, 3 Req, 0 Conn, 1 Text, 3 Int, 1..7 steps expect 0
run P13twoLaunchers {
  eventually some disj g, h: Live | g.gl != h.gl and g.gcap = h.gcap and g.gcap in Exclusive
} for 3 but 0 Process, 2 Launcher, 1 Capability, 2 Param, 2 Instance, 1 Dir,
  3 Grant, 3 Req, 0 Conn, 1 Text, 3 Int, 1..7 steps expect 1

// P13 as the README states it: an exclusive instance (what the instances
// glob finds) at most one launcher at a time. The lock is on each instance
// the parameters match (exclusiveLock, instances.go). Holds. Revert: the
// lock named by all the parameters' hash (as before the fix): a parameter
// the instance doesn't name (a mode, a read-only flag) lets two launchers
// take one VM with different values of it (counterexample found).
assert P13exclusiveByInstance {
  always all disj g, h: Live | (g.gcap = h.gcap and g.gcap in Exclusive and g.gl != h.gl)
    implies no g.gparams.(g.gcap.matches) & h.gparams.(h.gcap.matches)
}
check P13exclusiveByInstance for 3 but 0 Process, 2 Launcher, 1 Capability, 2 Param, 1 Instance, 1 Dir,
  2 Grant, 2 Req, 0 Conn, 1 Text, 3 Int, 1..7 steps expect 0
