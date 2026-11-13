/*
 * The protocol model's events (protocol.als): requests and calls, answers,
 * calls running, connections to host sockets, and the ends of grants.
 */
module protocol_events
open protocol_state

// ---------------------------------------------------------------------
// Requests and answers.

// What obtain checks before anything else (call, request, obtain;
// consent.go, call.go).
pred reqOK[r: Req] {
  r.rl in Up - Gone and r not in Asked
  callChecks[r]
  onceForCalls[r, r.rlease]
  r.rcap.dtype = Attach implies r.rl in SharedDir
  leaseOK[r.rl, r.rlease]
  passes[r.rcap, r.rparams]
}

// obtain asks the user (consent.go). A request or call a live grant or
// a standing grant the user hasn't ended covers is matchLive or
// fromConfig instead.
pred ask[r: Req] {
  let l = r.rl, c = r.rcap, p = r.rparams {
    reqOK[r]
    no g: Grant | covers[g, l, c, p]
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

// matching (consent.go): a live grant with the same parameters covers the
// request, whatever lease it asks for; a call runs under it.
pred matchLive[r: Req, g: Grant] {
  let l = r.rl, c = r.rcap, p = r.rparams {
    reqOK[r]
    covers[g, l, c, p]
    Asked' = Asked + r
    Pending' = Pending and Mature' = Mature and Opened' = Opened and Forged' = Forged
    shownDir' = shownDir and shows' = shows and by' = by
    calls[r, g, none, none]
    keepLive and keepConns
    keepDaemons and keepGates and keepEnv and ended' = ended
  }
}

// isStanding (standing.go): exact parameters of a standing grant in the
// config, not ended by the user in this daemon's life, grant without
// asking, with lease standing.
pred fromConfig[r: Req, g: Grant] {
  let l = r.rl, c = r.rcap, p = r.rparams {
    reqOK[r]
    no h: Grant | covers[h, l, c, p]
    standingNow[l, c, p]
    g.gl = l and g.gcap = c and g.gparams = p and g.glease = LStanding
    change[g, none]
    calls[r, g, none, none]
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

// Allow on the notification: the request's lease and parameters, checked
// again: the instances for host commands and host sockets, attachGrant
// for attach. A call runs under the grant.
pred notifAllow[r: Req, g: Grant] {
  let l = r.rl, c = r.rcap {
    r in Pending - Opened and actionMature[r]
    // only the broker's own notification carries its allow key
    r not in Forged
    // inList runs again after the answer (obtain, consent.go); a folder
    // is whatever its path resolves to at mount time (mountChecks)
    c.dtype != Attach implies some r.rparams.(c.matches) & Listed
    l in Up - Gone
    // checked again at grant time (checkLease after the answer, and lockOK
    // under the lock in grant(), leases.go)
    leaseOK[l, r.rlease]
    // a grant of the same made meanwhile serves instead (consent.go), as
    // matchLive does
    no h: Grant | covers[h, l, c, r.rparams]
    g.gl = l and g.gcap = c and g.gparams = r.rparams and g.glease = r.rlease
    change[g, none]
    calls[r, g, none, none]
    ended' = ended
    settle[r, NotifierP]
    asking' = asking - l -> c and refused' = refused - l -> c -> Int and blocked' = blocked
    keepDaemons and keepEnv
  }
}

// An answer on control.sock (answer, consent.go), from Options or while
// the notification is still up. The window always sends the parameters
// (Permissions.qml), so they are checked again; a host command's must be
// the request's. Its lease is never standing (windowDecision,
// consent.go), and once only for a call (obtain).
pred windowAllow[r: Req, w: Principal, ls: Lease, p: Param, g: Grant] {
  let l = r.rl, c = r.rcap {
    r in Pending and hostOnly[w]
    l in Up - Gone
    passes[c, p]
    boundingFixed[r, p]
    ls != LStanding
    onceForCalls[r, ls]
    leaseOK[l, ls]
    no h: Grant | covers[h, l, c, p]
    g.gl = l and g.gcap = c and g.gparams = p and g.glease = ls
    change[g, none]
    calls[r, g, none, none]
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

// Allowed, but grant() failed (a lock held, the mount refused, a host
// socket's address not listened at).
pred drop[r: Req] {
  r in Pending
  settle[r, none]
  asking' = asking - r.rl -> r.rcap and refused' = refused - r.rl -> r.rcap -> Int and blocked' = blocked
  keepDaemons and keepEnv and keepGrants and ended' = ended
}

// Allowed, a port grant switched its port on, and addr failed (live of
// portKind, ports.go): portOff switches it off again, unless a live grant
// holds it, or the helper fails to revoke it and g, never live, is
// recorded closing.
pred dropPort[r: Req, g: Grant] {
  r in Pending and r.rcap.dtype = Fwd
  g not in Live + Ended + Forwarded
  g.gl = r.rl and g.gcap = r.rcap and g.gparams = r.rparams
  settle[r, none]
  asking' = asking - r.rl -> r.rcap and refused' = refused - r.rl -> r.rcap -> Int and blocked' = blocked
  some samePort[g] & Live implies (Forwarded' = Forwarded and Closing' = Closing)
  else r.rl in Failing implies (Forwarded' = Forwarded + g and Closing' = Closing + g)
  else (Forwarded' = Forwarded - (Closing & samePort[g]) and Closing' = Closing - samePort[g])
  Live' = Live and Ended' = Ended and Mounted' = Mounted
  left' = left and mdir' = mdir and lockFile' = lockFile
  keepCalls and keepConns
  keepDaemons and keepEnv and ended' = ended
}

pred unblock[l: Launcher, c: Capability] {
  c in l.blocked
  blocked' = blocked - l -> c and asking' = asking and refused' = refused
  keepDaemons and keepEnv and keepGrants and keepReqs and ended' = ended
}

// ---------------------------------------------------------------------
// Calls (runCall, call.go).

// What a call is told its output may be valid for (callValidity): what is
// left of a duration lease, at most maxValidity.
fun validity[g: Grant]: Int {
  (g.glease = LDuration and g.left < g.gcap.maxV) implies g.left else g.gcap.maxV
}

// The call's slot is free. The grant must still be live, its instance
// there and time left (isLive, inList, callValidity); then its unit
// starts.
pred startCall[r: Req] {
  r in Queued
  r.under in Live
  some r.under.gparams.(r.under.gcap.matches) & Listed
  validity[r.under] > 0
  Queued' = Queued - r and Running' = Running + r and under' = under
  keepLive and keepConns
  keepDaemons and keepGates and keepEnv and keepReqs and ended' = ended
}

// The call is answered: its unit exited, or it failed before it ran (no
// slot in time, the grant ended, its instance gone). Its output is handed
// out only while the grant is live (runCall checks isLive again). A once
// grant ends with its call (call: defer g.end).
pred answerCall[r: Req] {
  r in Queued + Running
  let E = r.under & Live & glease.LOnce {
    change[none, E]
    calls[none, none, r, E]
    keepDaemons and keepGates and keepEnv and keepReqs
    ended' = ended
  }
}

// ---------------------------------------------------------------------
// Connections to host sockets (splice.go).

// The sandbox connects to an address the broker listens at: spliced to
// the host socket under the live grant that covers it (connectUnder), or
// closed at once (no grant, or the host socket refused).
pred connect[k: Conn, g: lone Grant] {
  k.kl in Up - Gone and k.kcap.dtype = Socket
  k not in Spliced + Closed
  some g implies (connectUnder[k, g] and Spliced' = Spliced + k and Closed' = Closed and via' = via + k -> g)
  else (Spliced' = Spliced and Closed' = Closed + k and via' = via)
  keepLive and keepCalls
  keepDaemons and keepGates and keepEnv and keepReqs and ended' = ended
}

// Either side closes a spliced connection.
pred hangup[k: Conn] {
  k in Spliced
  Spliced' = Spliced - k and Closed' = Closed + k and via' = via
  keepLive and keepCalls
  keepDaemons and keepGates and keepEnv and keepReqs and ended' = ended
}

// ---------------------------------------------------------------------
// Ends of grants.

// release from inside (release, leases.go): ends the grant, which only
// takes access away. A standing grant it ends is ended for the rest of
// the daemon's life.
pred release[g: Grant] {
  g in Live
  change[none, g]
  calls[none, none, none, g]
  keepDaemons and keepGates and keepEnv and keepReqs
  ended' = ended + standingOf[g]
}
// revoke in the window (leases.go): a standing grant is ended for the
// rest of the daemon's life.
pred revoke[g: Grant, w: Principal] {
  hostOnly[w] and g in Live
  change[none, g]
  calls[none, none, none, g]
  keepDaemons and keepGates and keepEnv and keepReqs
  ended' = ended + standingOf[g]
}
pred expire[g: Grant] { g in Live and g.glease = LDuration and g.left = 0 and endOnly[g] }

// watchInstance (commands.go): on its timer, a grant of a host command or
// host socket whose instance the glob no longer finds ends.
pred instanceGone[l: Launcher] {
  endOnly[{ g: Live & gl.l - typed[Attach] | no g.gparams.(g.gcap.matches) & Listed }]
}

pred tick {
  all g: Grant | (g in Live and g.glease = LDuration and g.left > 0)
    implies g.left' = minus[g.left, 1] else g.left' = g.left
  Live' = Live and Ended' = Ended and Mounted' = Mounted and Forwarded' = Forwarded and Closing' = Closing
  mdir' = mdir and lockFile' = lockFile and keepCalls and keepConns
  keepDaemons and keepGates and keepEnv and keepReqs and ended' = ended
}

// Lock, LockedHint or PrepareForSleep (lockEvent, leases.go).
pred lockEv[l: Launcher] {
  let E = Live & gl.l & glease.LLock {
    change[none, E]
    calls[none, none, none, E]
  }
  keepDaemons and keepGates and keepEnv and keepReqs and ended' = ended
}

// The system bus lost: lockOK off, lock leases end (lockSignals,
// leases.go).
pred lockLost[l: Launcher] {
  l in Watched
  Watched' = Watched - l
  Up' = Up and Dirty' = Dirty and SharedDir' = SharedDir and Gone' = Gone
  let E = Live & gl.l & glease.LLock {
    change[none, E]
    calls[none, none, none, E]
  }
  keepGates and keepEnv and keepReqs and ended' = ended
}

pred lockGained[l: Launcher] {
  l in Up - Watched
  Watched' = Watched + l
  Up' = Up and Dirty' = Dirty and SharedDir' = SharedDir and Gone' = Gone
  keepGates and keepEnv and keepGrants and keepReqs and ended' = ended
}
