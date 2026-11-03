/*
 * The protocol model's daemon life (crash, cleanup, start with the
 * standing grants), and the traces that interleave every event
 * (protocol.als).
 */
module protocol_system
open protocol_events

// ---------------------------------------------------------------------
// The daemon's life.

// start (run.go, grantStanding in standing.go): every standing grant of
// the config that validates, matches an instance the glob finds and whose
// exclusive lock is free is granted, with lease standing; one that fails
// is skipped. The start removed the launcher's own stale locks first
// (cleanup), so only another launcher's lock keeps one out.
pred standingGrants[l: Launcher, N: set Grant] {
  all g: N | g.gl = l and g.glease = LStanding and g.gparams in l.standing[g.gcap]
  all c: Capability, p: l.standing[c] | standingOK[l, c, p] implies one g: N | g.gcap = c and g.gparams = p
  all g: N | standingOK[l, g.gcap, g.gparams]
}
pred standingOK[l: Launcher, c: Capability, p: Param] {
  p in c.wellFormed
  some p.(c.matches) & Listed
  c in Exclusive implies no p.(c.matches).(c.lockFile) - l
}

// share from M1 (sockets.go): the grant directory is shared; no grant
// comes with it (no standing grant is an attach one).
pred share[l: Launcher, w: Principal] {
  inM1[w] and l in Up - Gone
  // once per sandbox (shareAsked, sockets.go)
  l not in SharedDir
  SharedDir' = SharedDir + l
  Up' = Up and Dirty' = Dirty and Watched' = Watched and Gone' = Gone
  keepGrants
  keepGates and keepEnv and keepReqs and ended' = ended
}

// The daemon dies. Its call units stop with it (BindsTo), the calls
// waiting for a slot and the connections it spliced go with its process;
// its folders stay mounted until ExecStopPost; its locks stay; requests
// and gates go.
pred crash[l: Launcher] {
  l in Up
  Up' = Up - l and Dirty' = Dirty + l and Watched' = Watched - l
  SharedDir' = SharedDir and Gone' = Gone
  let E = Live & gl.l {
    Live' = Live - E and Ended' = Ended + E
    Mounted' = Mounted and lockFile' = lockFile
  }
  bindsTo[l]
  Queued' = Queued - under.(gl.l) and under' = under
  Spliced' = Spliced - via.(gl.l) and Closed' = Closed + (Spliced & via.(gl.l)) and via' = via
  left' = left and mdir' = mdir
  Pending' = Pending - rl.l and Mature' = Mature - rl.l and Opened' = Opened - rl.l
  Asked' = Asked and Forged' = Forged and shownDir' = shownDir and shows' = shows and by' = by
  asking' = asking - l -> Capability and refused' = refused - l -> Capability -> Int
  blocked' = blocked - l -> Capability
  keepEnv and ended' = ended
}

// ExecStopPost: permissions-broker cleanup.
pred stopPost[l: Launcher] {
  l in Dirty
  Dirty' = Dirty - l and Up' = Up and SharedDir' = SharedDir and Watched' = Watched and Gone' = Gone
  cleanup[l]
  Live' = Live and Ended' = Ended
  Queued' = Queued and under' = under and keepConns
  left' = left and mdir' = mdir
  keepGates and keepEnv and keepReqs and ended' = ended
}

// start (run.go): cleanup, then the standing grants; nothing else of an
// earlier daemon survives, and what the user ended in its life is
// forgotten.
pred start[l: Launcher] {
  l not in Up + Gone
  Up' = Up + l and Dirty' = Dirty - l
  SharedDir' = SharedDir and Watched' = Watched and Gone' = Gone
  let N = Live' - Live {
    all g: N | g.gl = l
    standingGrants[l, N]
    no N & (Live + Ended)
    exclusiveLockFree[N, l]
    mountChecks[N]
    Ended' = Ended
    Mounted' = Mounted - gl.l + (N & typed[Attach])
    Running' = Running - under.(gl.l)
    lockFile' = lockFile - (Capability -> Instance -> l) + locksOf[N]
    all g: N & typed[Attach] | g.mdir' = g.gparams.resolves
    all g: Grant - (N & typed[Attach]) | g.mdir' = g.mdir
  }
  Queued' = Queued and under' = under and keepConns
  left' = left
  keepGates and keepEnv and keepReqs
  ended' = ended - l -> Capability -> Param
}

// The sandbox ends: endAll, the daemon exits, the mounts go with M1.
pred sandboxEnd[l: Launcher] {
  l not in Gone
  Gone' = Gone + l and Up' = Up - l and Dirty' = Dirty - l
  SharedDir' = SharedDir and Watched' = Watched - l
  let E = Live & gl.l {
    Live' = Live - E and Ended' = Ended + E
    Mounted' = Mounted - gl.l
    lockFile' = lockFile - (Capability -> Instance -> l)
  }
  Running' = Running - under.(gl.l) and Queued' = Queued - under.(gl.l) and under' = under
  Spliced' = Spliced - via.(gl.l) and Closed' = Closed + (Spliced & via.(gl.l)) and via' = via
  left' = left and mdir' = mdir
  Pending' = Pending - rl.l and Mature' = Mature - rl.l and Opened' = Opened - rl.l
  Asked' = Asked and Forged' = Forged and shownDir' = shownDir and shows' = shows and by' = by
  asking' = asking - l -> Capability and refused' = refused and blocked' = blocked
  keepEnv and ended' = ended
}

// g is made live in this step.
pred born[g: Grant] { g not in Live and g not in Ended and after g in Live }

// Instances come and go, the sandbox renames directories.
pred env {
  keepGrants
  keepDaemons and keepGates and keepReqs and ended' = ended
}

pred stutter {
  keepDaemons and keepGates and keepEnv and keepGrants and keepReqs and ended' = ended
}

// Who tries control.sock and request.sock: the window, and a process of
// the sandbox, the app's, standing in for every other principal (the
// checks look at the domain only).
fun Clients: set Principal { WindowP + AppP }

fact traces {
  init
  always (
    stutter or env or tick
    or (some r: Req | ask[r] or mature[r] or options[r] or forge[r] or refuse[r] or drop[r]
          or startCall[r] or answerCall[r])
    or (some r: Req, g: Grant | matchLive[r, g] or fromConfig[r, g] or notifAllow[r, g])
    or (some r: Req, w: Clients, ls: Lease, p: Param, g: Grant | windowAllow[r, w, ls, p, g])
    or (some g: Grant | release[g] or expire[g])
    or (some g: Grant, w: Clients | revoke[g, w])
    or (some k: Conn | hangup[k] or connect[k, none] or some g: Grant | connect[k, g])
    or (some l: Launcher | lockEv[l] or lockLost[l] or lockGained[l] or crash[l] or stopPost[l]
          or start[l] or sandboxEnd[l] or instanceGone[l])
    or (some l: Launcher, w: Clients + BwrapInitP + UdhcpcP | share[l, w])
    or (some l: Launcher, c: Capability | unblock[l, c])
  )
}
