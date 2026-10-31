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
// sandbox's text and buttons. The id is guessable: Plasma counts them up.
// The broker's buttons carry random action keys, per notification, and
// it takes ActionInvoked only from the server's own connection (askOn,
// notify.go): a click on the replacement's buttons is a refusal.
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
// parameters, checked again: `list` for types A and B, mountC for C.
pred notifAllow[r: Req, g: Grant] {
  let l = r.rl, c = r.rcap {
    r in Pending - Opened and actionMature[r]
    // only the broker's own notification carries its allow key
    r not in Forged
    // `list` runs again after the answer (inList, consent.go)
    c.dtype != TypeC implies some r.rparams.(c.matches) & Listed
    l in Up - Gone
    // checked again at grant time (checkLease after the answer, and lockOK
    // under the lock in grant(), leases.go)
    leaseOK[l, r.asked, r.rsess]
    r.asked = LSession implies r.rsess in Alive
    // a grant of the same made meanwhile serves instead (consent.go), as
    // matchLive does
    no h: Live | h.gl = l and h.gcap = c and h.gparams = r.rparams
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
    leaseOK[l, ls, r.rsess]
    ls = LSession implies r.rsess in Alive
    no h: Live | h.gl = l and h.gcap = c and h.gparams = p
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
// revoke in the window (leases.go): an always grant leaves the store too.
pred revoke[g: Grant, w: Principal] {
  hostOnly[w] and g in Live
  change[none, g]
  gsess' = gsess
  keepDaemons and keepGates and keepEnv and keepReqs
  g.glease = LAlways implies stored' = stored - g.gl -> g.gcap -> g.gparams else stored' = stored
}
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

// forget (store.go): the store entry goes, and every live always grant
// of the parameters ends.
pred forget[l: Launcher, c: Capability, p: Param, w: Principal] {
  hostOnly[w] and l in Up and p in c.wellFormed
  stored' = stored - l -> c -> p
  change[none, { h: Live | h.gl = l and h.gcap = c and h.gparams = p and h.glease = LAlways }]
  gsess' = gsess
  keepDaemons and keepGates and keepEnv and keepReqs
}
