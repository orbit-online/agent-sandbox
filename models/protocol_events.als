/*
 * The protocol model's events (protocol.als): requests, answers, and the
 * ends of grants.
 */
module protocol_events
open protocol_state

// ---------------------------------------------------------------------
// Requests and answers.

// What request() checks before anything else (broker.go:512-563).
pred reqOK[r: Req] {
  r.rl in Up - Gone and r not in Asked
  r.rcap.dtype = Attach implies r.rl in SharedDir
  leaseOK[r.rl, r.rlease, r.rsess]
  passes[r.rcap, r.rparams]
}

// request() asks the user (consent.go). A request matching a live grant
// or a standing grant the user hasn't ended is matchLive or fromConfig
// instead.
pred ask[r: Req] {
  let l = r.rl, c = r.rcap, p = r.rparams {
    reqOK[r]
    no g: Live | g.gl = l and g.gcap = c and g.gparams = p
    not standingNow[l, c, p]
    gateOpen[l, c]
    Pending' = Pending + r and Asked' = Asked + r
    Mature' = Mature and Opened' = Opened and Forged' = Forged
    r.shownDir' = p.resolves and r.shows' = r.summary
    all q: Req - r | q.shownDir' = q.shownDir and q.shows' = q.shows
    by' = by
    asking' = asking + l -> c and refused' = refused and blocked' = blocked
    keepDaemons and keepEnv and keepGrants and ended' = ended
  }
}

// matching (broker.go:565-582): a live grant with the same parameters
// covers the request, whatever lease it asks for. A session lease gains
// the caller's session (addSession); a command runs again.
pred matchLive[r: Req, g: Grant] {
  let l = r.rl, c = r.rcap, p = r.rparams {
    reqOK[r]
    g in Live and g.gl = l and g.gcap = c and g.gparams = p
    Asked' = Asked + r
    Pending' = Pending and Mature' = Mature and Opened' = Opened and Forged' = Forged
    shownDir' = shownDir and shows' = shows and by' = by
    hold[g, r.rsess]
    ToRun' = ToRun + (g & typed[Command])
    Live' = Live and Ended' = Ended and UnitUp' = UnitUp and Mounted' = Mounted
    left' = left and mdir' = mdir and lockFile' = lockFile
    keepDaemons and keepGates and keepEnv and ended' = ended
  }
}

// isStanding (consent.go): exact parameters of a standing grant in the
// config, not ended by the user in this daemon's life, grant without
// asking, with lease standing.
pred fromConfig[r: Req, g: Grant] {
  let l = r.rl, c = r.rcap, p = r.rparams {
    reqOK[r]
    no h: Live | h.gl = l and h.gcap = c and h.gparams = p
    standingNow[l, c, p]
    g.gl = l and g.gcap = c and g.gparams = p and g.glease = LStanding
    change[g, none]
    hold[g, r.rsess]
    Asked' = Asked + r
    Pending' = Pending and Mature' = Mature and Opened' = Opened and Forged' = Forged
    shownDir' = shownDir and shows' = shows and by' = by
    keepDaemons and keepGates and keepEnv and ended' = ended
  }
}

pred mature[r: Req] {
  r in Pending - Mature
  Mature' = Mature + r
  Pending' = Pending and Opened' = Opened and Asked' = Asked and Forged' = Forged
  shownDir' = shownDir and shows' = shows and by' = by
  keepDaemons and keepGates and keepEnv and keepGrants and ended' = ended
}

// Options hands the request to the window; the notification is gone.
pred options[r: Req] {
  r in Pending and actionMature[r] and r not in Opened
  Opened' = Opened + r
  Pending' = Pending and Mature' = Mature and Asked' = Asked and Forged' = Forged
  shownDir' = shownDir and shows' = shows and by' = by
  keepDaemons and keepGates and keepEnv and keepGrants and ended' = ended
}

// With RawNotify only: the sandbox calls Notify with replaces_id set to
// the broker's notification: Plasma 6.6 replaces it whoever sends it
// (libnotificationmanager/server_p.cpp, Notify: no check of the sender;
// abstractnotificationsmodel.cpp:110-137 swaps it in place), with the
// sandbox's text and buttons. The id is guessable: Plasma counts them up.
// The broker's buttons carry random action keys, per notification, and
// it takes ActionInvoked only from the server's own connection (askOn,
// notify.go): a click on the replacement's buttons is a refusal.
pred forge[r: Req] {
  some RawNotify
  r in Pending - Opened
  Forged' = Forged + r
  some t: Text - r.summary | r.shows' = t
  all q: Req - r | q.shows' = q.shows
  Pending' = Pending and Mature' = Mature and Opened' = Opened and Asked' = Asked
  shownDir' = shownDir and by' = by
  keepDaemons and keepGates and keepEnv and keepGrants and ended' = ended
}

// Allow on the notification: the request's lease and parameters, checked again: `list` for service and command, attachGrant
// for attach.
pred notifAllow[r: Req, g: Grant] {
  let l = r.rl, c = r.rcap {
    r in Pending - Opened and actionMature[r]
    // only the broker's own notification carries its allow key
    r not in Forged
    // `list` runs again after the answer (inList, consent.go); a folder
    // is whatever its path resolves to at mount time (mountChecks)
    c.dtype != Attach implies some r.rparams.(c.matches) & Listed
    l in Up - Gone
    // checked again at grant time (checkLease after the answer, and lockOK
    // under the lock in grant(), leases.go)
    leaseOK[l, r.rlease, r.rsess]
    r.rlease = LSession implies r.rsess in Alive
    // a grant of the same made meanwhile serves instead (consent.go), as
    // matchLive does
    no h: Live | h.gl = l and h.gcap = c and h.gparams = r.rparams
    g.gl = l and g.gcap = c and g.gparams = r.rparams and g.glease = r.rlease
    change[g, none]
    hold[g, r.rsess]
    ended' = ended
    settle[r, NotifierP]
    asking' = asking - l -> c and refused' = refused - l -> c -> Int and blocked' = blocked
    keepDaemons and keepEnv
  }
}

// An answer on control.sock (answer, consent.go), from Options or while
// the notification is still up. The window always sends the parameters
// (Permissions.qml), so they are checked again. Its lease is never
// standing (windowDecision, consent.go).
pred windowAllow[r: Req, w: Principal, ls: Lease, p: Param, g: Grant] {
  let l = r.rl, c = r.rcap {
    r in Pending and hostOnly[w]
    l in Up - Gone
    passes[c, p]
    ls != LStanding
    leaseOK[l, ls, r.rsess]
    ls = LSession implies r.rsess in Alive
    no h: Live | h.gl = l and h.gcap = c and h.gparams = p
    g.gl = l and g.gcap = c and g.gparams = p and g.glease = ls
    change[g, none]
    hold[g, r.rsess]
    ended' = ended
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
    keepDaemons and keepEnv and keepGrants and ended' = ended
  }
}

// Allowed, but grant() failed (a lock held, the mount refused).
pred drop[r: Req] {
  r in Pending
  settle[r, none]
  asking' = asking - r.rl -> r.rcap and refused' = refused - r.rl -> r.rcap -> Int and blocked' = blocked
  keepDaemons and keepEnv and keepGrants and ended' = ended
}

pred unblock[l: Launcher, c: Capability] {
  c in l.blocked
  blocked' = blocked - l -> c and asking' = asking and refused' = refused
  keepDaemons and keepEnv and keepGrants and keepReqs and ended' = ended
}

// ---------------------------------------------------------------------
// Ends of grants.

// release from inside (release, leases.go): the caller's session s drops
// its hold, s none when no session is found for the caller. The grant
// ends unless another session holds it or, but for a session lease, a
// caller without a session was given it; a caller without a session ends
// it outright (that only takes access away). A standing grant it ends is
// ended for the rest of the daemon's life (release, leases.go).
pred heldBesides[g: Grant, s: lone Session] {
  some s and (some g.holders - s or (g in Anon and g.glease != LSession))
}
pred release[g: Grant, s: lone Session] {
  g in Live
  holders' = holders - g -> s and Anon' = Anon
  heldBesides[g, s] implies (change[none, none] and ended' = ended)
  else (change[none, g] and ended' = ended + standingOf[g])
  keepDaemons and keepGates and keepEnv and keepReqs
}
// The plugin's watch or serve exits: the grant ends for everyone.
pred watchEnd[g: Grant] { g in Live and endOnly[g] }
// revoke in the window (leases.go): a standing grant is ended for the
// rest of the daemon's life.
pred revoke[g: Grant, w: Principal] {
  hostOnly[w] and g in Live
  change[none, g]
  keepHolds
  keepDaemons and keepGates and keepEnv and keepReqs
  ended' = ended + standingOf[g]
}
pred expire[g: Grant] { g in Live and g.glease = LDuration and g.left = 0 and endOnly[g] }

pred tick {
  all g: Grant | (g in Live and g.glease = LDuration and g.left > 0)
    implies g.left' = minus[g.left, 1] else g.left' = g.left
  Live' = Live and Ended' = Ended and UnitUp' = UnitUp and Mounted' = Mounted and ToRun' = ToRun
  keepHolds and mdir' = mdir and lockFile' = lockFile
  keepDaemons and keepGates and keepEnv and keepReqs and ended' = ended
}

// An anchor exits (watchSession, leases.go): the session drops its holds
// on every grant, and a session lease ends with its last holder.
pred sessionEnd[s: Session] {
  s in Alive
  Alive' = Alive - s and Listed' = Listed and resolves' = resolves
  holders' = holders - Grant -> s and Anon' = Anon
  change[none, { g: Live | g.glease = LSession and g.holders in s }]
  keepDaemons and keepGates and keepReqs and ended' = ended
}

// Lock, LockedHint or PrepareForSleep (lockEvent, broker.go:986-992).
pred lockEv[l: Launcher] {
  change[none, Live & gl.l & glease.LLock]
  keepHolds
  keepDaemons and keepGates and keepEnv and keepReqs and ended' = ended
}

// The system bus lost: lockOK off, lock leases end (broker.go:1361-1364).
pred lockLost[l: Launcher] {
  l in Watched
  Watched' = Watched - l
  Up' = Up and Dirty' = Dirty and SharedDir' = SharedDir and Gone' = Gone
  change[none, Live & gl.l & glease.LLock]
  keepHolds and keepGates and keepEnv and keepReqs and ended' = ended
}

pred lockGained[l: Launcher] {
  l in Up - Watched
  Watched' = Watched + l
  Up' = Up and Dirty' = Dirty and SharedDir' = SharedDir and Gone' = Gone
  keepGates and keepEnv and keepGrants and keepReqs and ended' = ended
}
