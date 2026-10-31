/*
 * The protocol model's daemon life (crash, cleanup, start, replay), type B
 * delivery, and the traces that interleave every event (protocol.als).
 */
module protocol_system
open protocol_events

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
