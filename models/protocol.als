/*
 * Step 3: the permissions broker's protocol over time (README.md, P1-P14).
 * This file holds the system: requests, consent, grants per delivery type,
 * leases, the store, the daemon's crashes and restarts, several launchers,
 * and the attacker's moves interleaved; its own commands only test the
 * encoding. protocol-consent.als checks consent (P1, P2, P6, P7, P14),
 * protocol-life.als the grants' lifecycle (P3, P4, P9-P13),
 * protocol-tree.als the process tree (P5, P8), protocol-window.als the
 * window's view. One file, though over 400 lines: the checks `open` it,
 * and Alloy module names can't contain '-'.
 *
 * Sources: nix/packages/permissions-broker/{broker,plugins,mounts,sandbox}.go
 * at 9a902c9; the code wins where docs/permissions.md differs.
 *
 * Time is abstract: a step is one event. The 1 s guard on notification
 * actions is the event `mature`, a lease's clock the event `tick`, the
 * 2 minute block the event `unblock`. Answer timeouts are refusals.
 *
 * The attacker is the sandbox: it picks every request's capability,
 * parameters, lease and session (forged CLAUDE_CODE_SESSION_ID included),
 * releases any grant, ends its sessions, renames directories under a
 * ceiling root (`env` changes what a parameter resolves to), sends `share`
 * from M1 (udhcpc), and posts notifications. It can't reach control.sock
 * (S6), so window answers come from host principals.
 */
module protocol
open sandbox

// HIDE: Id Cap UserNS OwnedNS MountNS NetNS IpcNS UtsNS CgroupNS PidNS Pid Process File MountFlag Mount PeerCheck Socket Domain

abstract sig DType {}
one sig TypeA, TypeB, TypeC extends DType {}

// Requested or granted lease. A duration is LDuration with a counter.
abstract sig Lease {}
one sig LSession, LLock, LDuration, LAlways extends Lease {}

// One daemon per launcher, with its own store (stateDir) and gates.
sig Launcher {
  var stored: Capability -> Param,
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
  // type B: maxValidity
  maxV: one Int,
  // the exclusive lock files, by capability and hash of the parameters
  var lockFile: Param -> lone Launcher
}
sig Exclusive in Capability {}
// What a type C parameter resolves to now: the attacker renames
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
  var gsess: set Session,
  // a duration lease's remaining time
  var left: lone Int,
  // type C: the directory mounted
  var mdir: lone Dir
}
// UnitUp: the type A unit and socket. Mounted: the type C mount in M1 and
// everywhere it propagated. Issuing: a type B delivery waiting for a plugin
// slot to run `issue`.
var sig Live, Ended, UnitUp, Mounted, Issuing in Grant {}

// One request on request.sock: what the sandbox sends and the daemon
// derives from it. asked: the lease the notification offers. summary: the
// daemon's text (describe, describeC). shows: what the notification with
// the request's id draws now.
sig Req {
  rl: one Launcher, rcap: one Capability, rparams: one Param, rlease: one Lease, rsess: lone Session,
  asked: one Lease, summary: one Text,
  var shownDir: lone Dir,
  var shows: lone Text,
  // who answered it
  var by: lone Principal
}
// Mature: its notification has been up a second. Opened: Options clicked,
// the window owns it. Forged: the sandbox replaced its notification.
var sig Pending, Mature, Opened, Asked, Forged in Req {}

fact static {
  all i: Instance | lone c: Capability | i in Param.(c.matches)
  all c: Capability | c.matches.Instance in c.wellFormed
  all c: Capability | c.maxV > 0
  // A request names a session only if it has one; the summary is the
  // daemon's, a function of capability and parameters
  all r: Req | r.rlease = LSession implies some r.rsess
  all r, q: Req | (r.rcap = q.rcap and r.rparams = q.rparams) implies r.summary = q.summary
  all r: Req | offered[r]
}

// always is offered in the window only: the notification proposes the
// session, or an hour without one (broker.go:588-595).
pred offered[r: Req] {
  r.rlease = LAlways implies r.asked = (some r.rsess implies LSession else LDuration)
  else r.asked = r.rlease
}

// Sessions don't come back: an anchor that exited is gone.
fact sessions {
  always all s: Session | (s in Alive and after s not in Alive) implies after always s not in Alive
}

// ---------------------------------------------------------------------
// Checks the daemon makes, each named so a revert check can drop it.

// The parameters validate, and match an instance `list` prints (A, B), or
// resolve beneath the ceiling (C): request() before asking, and again
// when the window narrows (broker.go:516-563, 611-625; plugins.go:334-365;
// mounts.go:664-690).
pred passes[c: Capability, p: Param] {
  p in c.wellFormed
  c.dtype = TypeC implies (some p.resolves and p.resolves in InCeiling)
  c.dtype != TypeC implies some p.(c.matches) & Listed
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

// mountC resolves again and clone-tree checks what it opens (mounts.go:
// 702-716, 228-283): a type C grant mounts only what is in the ceiling now.
pred mountChecks[N: set Grant] {
  all g: N & typed[TypeC] | some g.gparams.resolves and g.gparams.resolves in InCeiling
}

// exclusiveLock (plugins.go:369-392): O_EXCL on a file named by the
// capability and the hash of the parameters.
pred exclusiveLockFree[N: set Grant] {
  all g: N & gcap.Exclusive | no g.gparams.(g.gcap.lockFile)
  all disj g, h: N & gcap.Exclusive | g.gcap != h.gcap or g.gparams != h.gparams
}

// type A units are BindsTo= the daemon's unit (plugins.go:246-248).
pred bindsTo[l: Launcher] { UnitUp' = UnitUp - gl.l }

// cleanup (mounts.go:742-757): stops the launcher's units, removes its
// locks, detaches its folders and removes their mountpoints.
pred cleanup[l: Launcher] {
  Mounted' = Mounted - gl.l
  UnitUp' = UnitUp - gl.l
  lockFile' = lockFile - (Capability -> Param -> l)
}

// ---------------------------------------------------------------------
// Frames and the grant bookkeeping every event shares.

fun typed[t: DType]: set Grant { (gcap.dtype).t }
fun locksOf[G: set Grant]: Capability -> Param -> Launcher {
  { c: Exclusive, p: Param, l: Launcher | some g: G | g.gcap = c and g.gparams = p and g.gl = l }
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
  Live' = Live and Ended' = Ended and UnitUp' = UnitUp and Mounted' = Mounted and Issuing' = Issuing
  gsess' = gsess and left' = left and mdir' = mdir and lockFile' = lockFile
}

// N are made live and E end in this step; the locks of E are released.
// grant() (broker.go:840-913) and g.end (880-905). gsess is the caller's.
pred change[N, E: set Grant] {
  no N & (Live + Ended)
  E in Live
  exclusiveLockFree[N]
  mountChecks[N]
  Live' = Live - E + N
  Ended' = Ended + E
  UnitUp' = UnitUp - E + (N & typed[TypeA])
  Mounted' = Mounted - E + (N & typed[TypeC])
  // deliver() issues for a new type B grant, after a plugin slot frees
  Issuing' = Issuing + (N & typed[TypeB])
  all g: N & typed[TypeC] | g.mdir' = g.gparams.resolves
  all g: Grant - (N & typed[TypeC]) | g.mdir' = g.mdir
  all g: N | g.glease = LDuration implies g.left' > 0 else no g.left'
  all g: Grant - N | g.left' = g.left
  lockFile' = lockFile - locksOf[E] + locksOf[N]
}

// Ends E, nothing else changes.
pred endOnly[E: set Grant] {
  change[none, E]
  gsess' = gsess
  keepDaemons and keepGates and keepEnv and keepReqs and stored' = stored
}

// A request leaves the daemon: answered, refused, failed.
pred settle[r: Req, w: lone Principal] {
  Pending' = Pending - r and Mature' = Mature and Opened' = Opened and Asked' = Asked
  Forged' = Forged and shownDir' = shownDir and shows' = shows
  by' = by - r -> Principal + r -> w
}

pred init {
  no Up + Dirty + Gone
  no Live + Ended + UnitUp + Mounted + Issuing
  no Pending + Mature + Opened + Asked + Forged
  no asking and no refused and no blocked and no lockFile
  no gsess and no left and no mdir and no shownDir and no shows
}

// ---------------------------------------------------------------------
// Requests and answers.

// What request() checks before anything else (broker.go:512-563).
pred reqOK[r: Req] {
  r.rl in Up - Gone and r not in Asked
  r.rcap.dtype = TypeC implies r.rl in SharedDir
  leaseOK[r.rl, r.rlease, r.rsess]
  passes[r.rcap, r.rparams]
}

// request() asks the user (broker.go:511-596). A request matching a live
// grant or the store is matchLive or fromStore instead.
pred ask[r: Req] {
  let l = r.rl, c = r.rcap, p = r.rparams {
    reqOK[r]
    no g: Live | g.gl = l and g.gcap = c and g.gparams = p
    p not in l.stored[c]
    gateOpen[l, c]
    Pending' = Pending + r and Asked' = Asked + r
    Mature' = Mature and Opened' = Opened and Forged' = Forged
    r.shownDir' = p.resolves and r.shows' = r.summary
    all q: Req - r | q.shownDir' = q.shownDir and q.shows' = q.shows
    by' = by
    asking' = asking + l -> c and refused' = refused and blocked' = blocked
    keepDaemons and keepEnv and keepGrants and stored' = stored
  }
}

// matching (broker.go:565-582): a live grant with the same parameters
// covers the request, whatever lease it asks for. A session lease gains
// the caller's session (addSession); type B issues again.
pred matchLive[r: Req, g: Grant] {
  let l = r.rl, c = r.rcap, p = r.rparams {
    reqOK[r]
    g in Live and g.gl = l and g.gcap = c and g.gparams = p
    Asked' = Asked + r
    Pending' = Pending and Mature' = Mature and Opened' = Opened and Forged' = Forged
    shownDir' = shownDir and shows' = shows and by' = by
    (g.glease = LSession and some r.rsess and r.rsess in Alive and some g.gsess)
      implies gsess' = gsess + g -> r.rsess else gsess' = gsess
    Issuing' = Issuing + (g & typed[TypeB])
    Live' = Live and Ended' = Ended and UnitUp' = UnitUp and Mounted' = Mounted
    left' = left and mdir' = mdir and lockFile' = lockFile
    keepDaemons and keepGates and keepEnv and stored' = stored
  }
}

// isAlways (broker.go:573-578, 697-707): exact parameters in the store
// grant without asking.
pred fromStore[r: Req, g: Grant] {
  let l = r.rl, c = r.rcap, p = r.rparams {
    reqOK[r]
    no h: Live | h.gl = l and h.gcap = c and h.gparams = p
    p in l.stored[c]
    g.gl = l and g.gcap = c and g.gparams = p and g.glease = LAlways
    change[g, none]
    gsess' = gsess
    Asked' = Asked + r
    Pending' = Pending and Mature' = Mature and Opened' = Opened and Forged' = Forged
    shownDir' = shownDir and shows' = shows and by' = by
    keepDaemons and keepGates and keepEnv and stored' = stored
  }
}

pred mature[r: Req] {
  r in Pending - Mature
  Mature' = Mature + r
  Pending' = Pending and Opened' = Opened and Asked' = Asked and Forged' = Forged
  shownDir' = shownDir and shows' = shows and by' = by
  keepDaemons and keepGates and keepEnv and keepGrants and stored' = stored
}

// Options hands the request to the window; the notification is gone.
pred options[r: Req] {
  r in Pending and actionMature[r] and r not in Opened
  Opened' = Opened + r
  Pending' = Pending and Mature' = Mature and Asked' = Asked and Forged' = Forged
  shownDir' = shownDir and shows' = shows and by' = by
  keepDaemons and keepGates and keepEnv and keepGrants and stored' = stored
}

// The sandbox calls Notify with replaces_id set to the broker's
// notification: Plasma 6.6 replaces it whoever sends it
// (libnotificationmanager/server_p.cpp, Notify: no check of the sender;
// abstractnotificationsmodel.cpp:110-137 swaps it in place), with the
// sandbox's text and buttons, and libnotify's notify-send takes any
// ActionInvoked for its id (notification.c:813-827). The id is
// guessable: Plasma counts them up.
pred forge[r: Req] {
  r in Pending - Opened
  Forged' = Forged + r
  some t: Text - r.summary | r.shows' = t
  all q: Req - r | q.shows' = q.shows
  Pending' = Pending and Mature' = Mature and Opened' = Opened and Asked' = Asked
  shownDir' = shownDir and by' = by
  keepDaemons and keepGates and keepEnv and keepGrants and stored' = stored
}

// Allow on the notification: the lease it offered, the request's
// parameters. Only type C is checked again, by mountC.
pred notifAllow[r: Req, g: Grant] {
  let l = r.rl, c = r.rcap {
    r in Pending - Opened and actionMature[r]
    l in Up - Gone
    // re-checked only when the answer's lease differs from the request's
    r.rlease != r.asked implies leaseOK[l, r.asked, r.rsess]
    r.asked = LSession implies r.rsess in Alive
    g.gl = l and g.gcap = c and g.gparams = r.rparams and g.glease = r.asked
    change[g, none]
    r.asked = LSession implies gsess' = gsess + g -> r.rsess else gsess' = gsess
    // addAlways for the answer's lease (broker.go:632-634)
    r.asked = LAlways implies stored' = stored + l -> c -> r.rparams else stored' = stored
    settle[r, NotifierP]
    asking' = asking - l -> c and refused' = refused - l -> c -> Int and blocked' = blocked
    keepDaemons and keepEnv
  }
}

// An answer on control.sock (answer, broker.go:824-837), from Options or
// while the notification is still up. The window always sends the
// parameters (Permissions.qml:150), so they are checked again.
pred windowAllow[r: Req, w: Principal, ls: Lease, p: Param, g: Grant] {
  let l = r.rl, c = r.rcap {
    r in Pending and hostOnly[w]
    l in Up - Gone
    passes[c, p]
    ls != r.rlease implies leaseOK[l, ls, r.rsess]
    ls = LSession implies r.rsess in Alive
    g.gl = l and g.gcap = c and g.gparams = p and g.glease = ls
    change[g, none]
    ls = LSession implies gsess' = gsess + g -> r.rsess else gsess' = gsess
    ls = LAlways implies stored' = stored + l -> c -> p else stored' = stored
    settle[r, w]
    asking' = asking - l -> c and refused' = refused - l -> c -> Int and blocked' = blocked
    keepDaemons and keepEnv
  }
}

// Deny, no answer in time, or the notification failing: a refusal; the
// third in a row blocks the capability.
pred refuse[r: Req] {
  let l = r.rl, c = r.rcap, n = plus[nref[l, c], 1] {
    r in Pending
    settle[r, none]
    asking' = asking - l -> c
    n >= 3 implies (blocked' = blocked + l -> c and refused' = refused - l -> c -> Int)
    else (blocked' = blocked and refused' = refused - l -> c -> Int + l -> c -> n)
    keepDaemons and keepEnv and keepGrants and stored' = stored
  }
}

// Allowed, but grant() failed (a lock held, the mount refused).
pred drop[r: Req] {
  r in Pending
  settle[r, none]
  asking' = asking - r.rl -> r.rcap and refused' = refused - r.rl -> r.rcap -> Int and blocked' = blocked
  keepDaemons and keepEnv and keepGrants and stored' = stored
}

pred unblock[l: Launcher, c: Capability] {
  c in l.blocked
  blocked' = blocked - l -> c and asking' = asking and refused' = refused
  keepDaemons and keepEnv and keepGrants and keepReqs and stored' = stored
}

// ---------------------------------------------------------------------
// Ends of grants.

// release from inside, any grant by id (broker.go:1025-1034), or its
// plugin's watch exiting.
pred release[g: Grant] { g in Live and endOnly[g] }
// revoke in the window (broker.go:995-1004).
pred revoke[g: Grant, w: Principal] { hostOnly[w] and g in Live and endOnly[g] }
pred expire[g: Grant] { g in Live and g.glease = LDuration and g.left = 0 and endOnly[g] }

pred tick {
  all g: Grant | (g in Live and g.glease = LDuration and g.left > 0)
    implies g.left' = minus[g.left, 1] else g.left' = g.left
  Live' = Live and Ended' = Ended and UnitUp' = UnitUp and Mounted' = Mounted and Issuing' = Issuing
  gsess' = gsess and mdir' = mdir and lockFile' = lockFile
  keepDaemons and keepGates and keepEnv and keepReqs and stored' = stored
}

// An anchor exits (watchSession, broker.go:955-983): a session lease ends
// with its last session.
pred sessionEnd[s: Session] {
  s in Alive
  Alive' = Alive - s and Listed' = Listed and resolves' = resolves
  gsess' = gsess - Grant -> s
  change[none, { g: Live | g.glease = LSession and g.gsess in s }]
  keepDaemons and keepGates and keepReqs and stored' = stored
}

// Lock, LockedHint or PrepareForSleep (lockEvent, broker.go:986-992).
pred lockEv[l: Launcher] {
  change[none, Live & gl.l & glease.LLock]
  gsess' = gsess
  keepDaemons and keepGates and keepEnv and keepReqs and stored' = stored
}

// The system bus lost: lockOK off, lock leases end (broker.go:1361-1364).
pred lockLost[l: Launcher] {
  l in Watched
  Watched' = Watched - l
  Up' = Up and Dirty' = Dirty and SharedDir' = SharedDir and Gone' = Gone
  change[none, Live & gl.l & glease.LLock]
  gsess' = gsess and keepGates and keepEnv and keepReqs and stored' = stored
}

pred lockGained[l: Launcher] {
  l in Up - Watched
  Watched' = Watched + l
  Up' = Up and Dirty' = Dirty and SharedDir' = SharedDir and Gone' = Gone
  keepGates and keepEnv and keepGrants and keepReqs and stored' = stored
}

// forget (broker.go:1081-1104): the store entry goes; `matching` picks one
// live grant of the parameters, in map order, and ends it if its lease is
// always. G is that pick, none when there is no such grant.
pred forget[l: Launcher, c: Capability, p: Param, w: Principal, G: set Grant] {
  hostOnly[w] and l in Up and p in c.wellFormed
  lone G and G in Live and G.gl in l and G.gcap in c and G.gparams in p
  no G iff no h: Live | h.gl = l and h.gcap = c and h.gparams = p
  stored' = stored - l -> c -> p
  change[none, G & glease.LAlways]
  gsess' = gsess
  keepDaemons and keepGates and keepEnv and keepReqs
}

// ---------------------------------------------------------------------
// The daemon's life.

// replay (broker.go:1044-1071): every stored always grant of type t that
// validates (and for C resolves beneath the ceiling) is granted again,
// with no look for a live grant of the same and, for A, no `list`.
pred replays[l: Launcher, t: DType, N: set Grant] {
  all g: N | g.gl = l and g.glease = LAlways and g.gcap.dtype = t and g.gparams in l.stored[g.gcap]
  all c: Capability, p: l.stored[c] | (c.dtype = t and replayOK[c, p]) implies one g: N | g.gcap = c and g.gparams = p
  all g: N | replayOK[g.gcap, g.gparams]
}
pred replayOK[c: Capability, p: Param] {
  p in c.wellFormed
  c.dtype = TypeC implies (some p.resolves and p.resolves in InCeiling)
  c in Exclusive implies no p.(c.lockFile)
}

// share from M1 (shareFrom, broker.go:485-497): shared, then replay C.
pred share[l: Launcher, w: Principal] {
  inM1[w] and l in Up - Gone
  SharedDir' = SharedDir + l
  Up' = Up and Dirty' = Dirty and Watched' = Watched and Gone' = Gone
  replays[l, TypeC, Live' - Live]
  change[Live' - Live, none]
  gsess' = gsess
  keepGates and keepEnv and keepReqs and stored' = stored
}

// The daemon dies. Its type A units stop with it (BindsTo); its folders
// stay mounted until ExecStopPost; its locks stay; requests and gates go.
pred crash[l: Launcher] {
  l in Up
  Up' = Up - l and Dirty' = Dirty + l and Watched' = Watched - l
  SharedDir' = SharedDir and Gone' = Gone
  let E = Live & gl.l {
    Live' = Live - E and Ended' = Ended + E
    bindsTo[l]
    Mounted' = Mounted and lockFile' = lockFile
    Issuing' = Issuing - gl.l
  }
  gsess' = gsess and left' = left and mdir' = mdir
  Pending' = Pending - rl.l and Mature' = Mature - rl.l and Opened' = Opened - rl.l
  Asked' = Asked and Forged' = Forged and shownDir' = shownDir and shows' = shows and by' = by
  asking' = asking - l -> Capability and refused' = refused - l -> Capability -> Int
  blocked' = blocked - l -> Capability
  keepEnv and stored' = stored
}

// ExecStopPost: permissions-broker cleanup.
pred stopPost[l: Launcher] {
  l in Dirty
  Dirty' = Dirty - l and Up' = Up and SharedDir' = SharedDir and Watched' = Watched and Gone' = Gone
  cleanup[l]
  Live' = Live and Ended' = Ended and Issuing' = Issuing
  gsess' = gsess and left' = left and mdir' = mdir
  keepGates and keepEnv and keepReqs and stored' = stored
}

// run() (broker.go:203-238): cleanup, replay A, and, when an earlier
// daemon shared the grant directory, replay C (adoptShared).
pred start[l: Launcher] {
  l not in Up + Gone
  Up' = Up + l and Dirty' = Dirty - l
  SharedDir' = SharedDir and Watched' = Watched and Gone' = Gone
  let N = Live' - Live {
    all g: N | g.gl = l
    replays[l, TypeA, N & typed[TypeA]]
    l in SharedDir implies replays[l, TypeC, N & typed[TypeC]] else no N & typed[TypeC]
    no N & typed[TypeB]
    no N & (Live + Ended)
    exclusiveLockFree[N]
    mountChecks[N]
    Ended' = Ended and Issuing' = Issuing
    UnitUp' = UnitUp - gl.l + (N & typed[TypeA])
    Mounted' = Mounted - gl.l + (N & typed[TypeC])
    lockFile' = lockFile - (Capability -> Param -> l) + locksOf[N]
    all g: N & typed[TypeC] | g.mdir' = g.gparams.resolves
    all g: Grant - (N & typed[TypeC]) | g.mdir' = g.mdir
  }
  gsess' = gsess and left' = left
  keepGates and keepEnv and keepReqs and stored' = stored
}

// The sandbox ends: endAll, the daemon exits, the mounts go with M1.
pred sandboxEnd[l: Launcher] {
  l not in Gone
  Gone' = Gone + l and Up' = Up - l and Dirty' = Dirty - l
  SharedDir' = SharedDir and Watched' = Watched - l
  let E = Live & gl.l {
    Live' = Live - E and Ended' = Ended + E
    UnitUp' = UnitUp - gl.l and Mounted' = Mounted - gl.l and Issuing' = Issuing - gl.l
    lockFile' = lockFile - (Capability -> Param -> l)
  }
  gsess' = gsess and left' = left and mdir' = mdir
  Pending' = Pending - rl.l and Mature' = Mature - rl.l and Opened' = Opened - rl.l
  Asked' = Asked and Forged' = Forged and shownDir' = shownDir and shows' = shows and by' = by
  asking' = asking - l -> Capability and refused' = refused and blocked' = blocked
  keepEnv and stored' = stored
}

// deliver() for type B (broker.go:638-649): the validity, refused when it
// is not positive. Runs once a plugin slot frees; nothing checks the grant
// is still live.
fun validity[g: Grant]: Int {
  (g.glease = LDuration and g.left < g.gcap.maxV) implies g.left else g.gcap.maxV
}
pred issue[g: Grant] {
  g in Issuing
  Issuing' = Issuing - g
  Live' = Live and Ended' = Ended and UnitUp' = UnitUp and Mounted' = Mounted
  gsess' = gsess and left' = left and mdir' = mdir and lockFile' = lockFile
  keepDaemons and keepGates and keepEnv and keepReqs and stored' = stored
}
pred credential[g: Grant] { issue[g] and validity[g] > 0 }

// g is made live in this step.
pred born[g: Grant] { g not in Live and g not in Ended and after g in Live }

// Instances come and go, the sandbox renames directories, sessions start.
pred env {
  Alive in Alive'
  Live' = Live and Ended' = Ended and UnitUp' = UnitUp and Mounted' = Mounted and Issuing' = Issuing
  gsess' = gsess and left' = left and mdir' = mdir and lockFile' = lockFile
  keepDaemons and keepGates and keepReqs and stored' = stored
}

pred stutter {
  keepDaemons and keepGates and keepEnv and keepGrants and keepReqs and stored' = stored
}

// Who tries control.sock and request.sock: the window, and a process of
// the sandbox standing in for every other principal (the checks look at
// the domain only).
fun Clients: set Principal { WindowP + SessionP }

fact traces {
  init
  always (
    stutter or env or tick
    or (some r: Req | ask[r] or mature[r] or options[r] or forge[r] or refuse[r] or drop[r])
    or (some r: Req, g: Grant | matchLive[r, g] or fromStore[r, g] or notifAllow[r, g])
    or (some r: Req, w: Clients, ls: Lease, p: Param, g: Grant | windowAllow[r, w, ls, p, g])
    or (some g: Grant | release[g] or expire[g] or issue[g])
    or (some g: Grant, w: Clients | revoke[g, w])
    or (some s: Session | sessionEnd[s])
    or (some l: Launcher | lockEv[l] or lockLost[l] or lockGained[l] or crash[l] or stopPost[l]
          or start[l] or sandboxEnd[l])
    or (some l: Launcher, w: Clients + BwrapInitP + UdhcpcP | share[l, w])
    or (some l: Launcher, c: Capability | unblock[l, c])
    or (some l: Launcher, c: Capability, p: Param, w: Clients |
          forget[l, c, p, w, none] or (some g: Grant | forget[l, c, p, w, g]))
  )
}

// ---------------------------------------------------------------------
// Checks of the encoding itself: every delivery type is granted and ends,
// and a daemon crashes, is cleaned up and replays. No claim about the
// broker; protocol-*.als hold those.

run deliveries {
  all t: DType | eventually some g: Grant | g.gcap.dtype = t and born[g]
  eventually some g: Grant | g in Ended and g.gcap.dtype = TypeC
} for 3 but 0 Process, 1 Launcher, 3 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 1

run restart {
  some l: Launcher | eventually (crash[l] and some Mounted & gl.l and after (stopPost[l] and after start[l]))
  eventually some l: Launcher, w: Principal | share[l, w] and w in UdhcpcP
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 1
