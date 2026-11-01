/*
 * The protocol model's state (protocol.als): signatures, the checks the
 * daemon makes, and the frames and grant bookkeeping every event shares.
 * protocol_events.als adds requests, answers and ends of grants,
 * protocol_system.als the daemon's life and the traces.
 */
module protocol_state
open sandbox

abstract sig DType {}
one sig Service, Command, Attach extends DType {}

// Requested or granted lease. A duration is LDuration with a counter.
// LStanding only for a standing grant from the config: no request or
// answer picks it.
abstract sig Lease {}
one sig LSession, LLock, LDuration, LStanding extends Lease {}

// One daemon per launcher, with its gates. standing: the standing grants
// the launcher's config declares (capability, exact parameters), static:
// nothing at runtime adds or removes one. ended: those the user revoked or
// released in this daemon's life; a start clears it.
sig Launcher {
  standing: Capability -> Param,
  var ended: Capability -> Param,
  var asking: set Capability,
  var refused: Capability -> lone Int,
  var blocked: set Capability
}
// Up: the daemon runs. Dirty: it crashed and ExecStopPost hasn't run.
// SharedDir: /run/permissions is shared in M1. Watched: logind is watched
// (lockOK). Gone: the sandbox ended.
var sig Up, Dirty, SharedDir, Watched, Gone in Launcher {}

sig Capability {
  dtype: one DType,
  // validate() passes
  wellFormed: set Param,
  // the instances `list` may print that these parameters match
  matches: Param -> Instance,
  // command: maxValidity
  maxV: one Int,
  // the exclusive lock files, by capability and instance
  var lockFile: Instance -> lone Launcher
}
// Exclusive capabilities are of types service and command, whose `list` names the
// instances locked (an attach one would lock by its parameters; none is).
sig Exclusive in Capability {}
fact { no Exclusive & dtype.Attach }
// What an attach parameter resolves to now: the attacker renames
// directories under a ceiling root at will.
sig Param { var resolves: lone Dir }
sig Instance {}
var sig Listed in Instance {}
// A directory. InCeiling: beneath a ceiling root reached without links or
// mount crossings, not denied, no submounts (S11, clone-tree).
sig Dir {}
sig InCeiling in Dir {}
// A Claude Code session, by its anchor; Alive while the anchor runs.
sig Session {}
var sig Alive in Session {}
sig Text {}

sig Grant {
  gl: one Launcher, gcap: one Capability, gparams: one Param, glease: one Lease,
  // the sessions it was given to, which hold it until they release it or
  // end, whatever the lease (holders, leases.go)
  var holders: set Session,
  // a duration lease's remaining time
  var left: lone Int,
  // attach: the directory mounted
  var mdir: lone Dir
}
// UnitUp: the service unit and socket. Mounted: the attach mount in M1 and
// everywhere it propagated. ToRun: a command grant waiting for a plugin
// slot to run its `run` command.
var sig Live, Ended, UnitUp, Mounted, ToRun in Grant {}
// Given to a caller without a session (anon, leases.go): held, but for a
// session lease, until it ends.
var sig Anon in Grant {}

// One request on request.sock: what the sandbox sends and the daemon
// derives from it. summary: the
// daemon's text (describe, describeAttach). shows: what the notification with
// the request's id draws now.
sig Req {
  rl: one Launcher, rcap: one Capability, rparams: one Param, rlease: one Lease, rsess: lone Session,
  summary: one Text,
  var shownDir: lone Dir,
  var shows: lone Text,
  // who answered it
  var by: lone Principal
}
// Mature: its notification has been up a second. Opened: Options clicked,
// the window owns it. Forged: the sandbox replaced its notification.
var sig Pending, Mature, Opened, Asked, Forged in Req {}
// The sandbox reaches the notification server itself, as with the proxy's
// talk on org.freedesktop.Notifications. Today it reaches the portal's
// notifications only (libnotify with NOTIFY_FORCE_PORTAL, the app's own
// backend patched out, hm/patch-asar.sh), which keys them by app ID: it
// can't replace or close the broker's. The models without it are today's.
lone sig RawNotify {}

fact static {
  all i: Instance | lone c: Capability | i in Param.(c.matches)
  all c: Capability | c.matches.Instance in c.wellFormed
  all c: Capability | c.maxV > 0
  // A request names a session only if it has one; the summary is the
  // daemon's, a function of capability and parameters
  all r: Req | r.rlease = LSession implies some r.rsess
  all r, q: Req | (r.rcap = q.rcap and r.rparams = q.rparams) implies r.summary = q.summary
  // request() refuses lease standing (consent.go)
  no rlease.LStanding
  // standing grants are of types service and command only: folders that
  // should always be there are binds (the module's assertion)
  all l: Launcher | no l.standing.Param & dtype.Attach
}

// Not ended by the user in this daemon's life: request() grants it
// without asking (isStanding, consent.go). Exact parameters only.
pred standingNow[l: Launcher, c: Capability, p: Param] {
  p in l.standing[c] - l.ended[c]
}

// Sessions don't come back: an anchor that exited is gone.
fact sessions {
  always all s: Session | (s in Alive and after s not in Alive) implies after always s not in Alive
}

// ---------------------------------------------------------------------
// Checks the daemon makes, each named so a revert check can drop it.

// The parameters validate, and match an instance `list` prints (service, command),
// or resolve beneath the ceiling (attach): request() before asking, and again
// when the window narrows (broker.go:516-563, 611-625; plugins.go:334-365;
// mounts.go:664-690).
pred passes[c: Capability, p: Param] {
  p in c.wellFormed
  c.dtype = Attach implies (some p.resolves and p.resolves in InCeiling)
  c.dtype != Attach implies some p.(c.matches) & Listed
}

// checkLease (broker.go:653-673): a session lease needs a session, a lock
// lease a watched logind.
pred leaseOK[l: Launcher, ls: Lease, s: lone Session] {
  ls = LSession implies (some s and s in Alive)
  ls = LLock implies l in Watched
}

// openGate (broker.go:711-740): one open request per capability, none
// while blocked.
pred gateOpen[l: Launcher, c: Capability] { c not in l.asking + l.blocked }

// control.sock answers only peers in the daemon's user namespace
// (broker.go:386).
pred hostOnly[w: Principal] { w.domain = Host }

// share only from M1 (broker.go:486): bwrap's init and the FHS env script,
// and udhcpc, which runs there too.
pred inM1[w: Principal] { w in BwrapInitP + UdhcpcP }

// notifyAsk ignores an action within a second of the notification
// appearing (broker.go:1237).
pred actionMature[r: Req] { r in Mature }

// attachGrant resolves again and clone-tree checks what it opens (mounts.go:
// 702-716, 228-283): an attach grant mounts only what is in the ceiling now.
pred mountChecks[N: set Grant] {
  all g: N & typed[Attach] | some g.gparams.resolves and g.gparams.resolves in InCeiling
}

// exclusiveLock (instances.go): O_EXCL on a file per instance the
// parameters match. The locks of L were removed first (a start's cleanup
// of its own launcher's).
pred exclusiveLockFree[N: set Grant, L: set Launcher] {
  all g: N & gcap.Exclusive | no g.gparams.(g.gcap.matches).(g.gcap.lockFile) - L
  all disj g, h: N & gcap.Exclusive | g.gcap != h.gcap or no g.gparams.(g.gcap.matches) & h.gparams.(h.gcap.matches)
}

// service units are BindsTo= the daemon's unit (plugins.go:246-248).
pred bindsTo[l: Launcher] { UnitUp' = UnitUp - gl.l }

// cleanup (mounts.go:742-757): stops the launcher's units, removes its
// locks, detaches its folders and removes their mountpoints.
pred cleanup[l: Launcher] {
  Mounted' = Mounted - gl.l
  UnitUp' = UnitUp - gl.l
  lockFile' = lockFile - (Capability -> Instance -> l)
}

// ---------------------------------------------------------------------
// Frames and the grant bookkeeping every event shares.

fun typed[t: DType]: set Grant { (gcap.dtype).t }
fun locksOf[G: set Grant]: Capability -> Instance -> Launcher {
  { c: Exclusive, i: Instance, l: Launcher | some g: G | g.gcap = c and i in g.gparams.(c.matches) and g.gl = l }
}
// The standing grants among E, as the daemon records them ended.
fun standingOf[E: set Grant]: Launcher -> Capability -> Param {
  { l: Launcher, c: Capability, p: Param | some g: E & glease.LStanding | g.gl = l and g.gcap = c and g.gparams = p }
}
fun nref[l: Launcher, c: Capability]: Int { some c.(l.refused) implies c.(l.refused) else 0 }

pred keepDaemons { Up' = Up and Dirty' = Dirty and SharedDir' = SharedDir and Watched' = Watched and Gone' = Gone }
pred keepGates { asking' = asking and refused' = refused and blocked' = blocked }
pred keepEnv { Listed' = Listed and resolves' = resolves and Alive' = Alive }
pred keepReqs {
  Pending' = Pending and Mature' = Mature and Opened' = Opened and Asked' = Asked and Forged' = Forged
  shownDir' = shownDir and shows' = shows and by' = by
}
pred keepGrants {
  Live' = Live and Ended' = Ended and UnitUp' = UnitUp and Mounted' = Mounted and ToRun' = ToRun
  keepHolds and left' = left and mdir' = mdir and lockFile' = lockFile
}
pred keepHolds { holders' = holders and Anon' = Anon }

// N are made live and E end in this step; the locks of E are released.
// grant() (broker.go:840-913) and g.end (880-905). hold records who was
// given them.
pred change[N, E: set Grant] {
  no N & (Live + Ended)
  E in Live
  exclusiveLockFree[N, none]
  mountChecks[N]
  Live' = Live - E + N
  Ended' = Ended + E
  UnitUp' = UnitUp - E + (N & typed[Service])
  Mounted' = Mounted - E + (N & typed[Attach])
  // deliver() runs a new command grant's command, after a plugin slot frees
  ToRun' = ToRun - E + (N & typed[Command])
  all g: N & typed[Attach] | g.mdir' = g.gparams.resolves
  all g: Grant - (N & typed[Attach]) | g.mdir' = g.mdir
  all g: N | g.glease = LDuration implies g.left' > 0 else no g.left'
  all g: Grant - N | g.left' = g.left
  lockFile' = lockFile - locksOf[E] + locksOf[N]
}

// Ends E, nothing else changes.
pred endOnly[E: set Grant] {
  change[none, E]
  keepHolds
  keepDaemons and keepGates and keepEnv and keepReqs and ended' = ended
}

// A request leaves the daemon: answered, refused, failed.
pred settle[r: Req, w: lone Principal] {
  Pending' = Pending - r and Mature' = Mature and Opened' = Opened and Asked' = Asked
  Forged' = Forged and shownDir' = shownDir and shows' = shows
  by' = by - r -> Principal + r -> w
}

// hold (leases.go): a caller of s (none: no session found) was given g.
// A session holds it; the hold of a session whose anchor is gone is
// dropped at once by its watch, so it is never added here. A live session
// lease nobody holds is ending: it takes no new hold.
pred hold[g: Grant, s: lone Session] {
  no s implies (Anon' = Anon + g and holders' = holders)
  else {
    Anon' = Anon
    (s in Alive and not (g in Live and g.glease = LSession and no g.holders))
      implies holders' = holders + g -> s else holders' = holders
  }
}

pred init {
  no Up + Dirty + Gone
  no Live + Ended + UnitUp + Mounted + ToRun
  no Pending + Mature + Opened + Asked + Forged
  no asking and no refused and no blocked and no lockFile
  no ended
  no holders and no Anon and no left and no mdir and no shownDir and no shows
}
