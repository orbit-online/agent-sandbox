/*
 * Consent: P1, P2, P6, P7, P14 over the system in protocol.als. Each
 * claim has a `run` that shows its premise happens (so the check isn't
 * vacuous) and names the code that enforces it. "Revert:" says which
 * check of protocol.als was dropped to see the claim fail, and that it
 * did (2026-10-31).
 */
open protocol_system

// HIDE: Id Cap UserNS OwnedNS MountNS NetNS IpcNS UtsNS CgroupNS PidNS Pid Process File MountFlag Mount PeerCheck Socket Domain

// A host principal allows g in this step: on the notification, or on
// control.sock (`by` records who answered).
pred allowedByHost[g: Grant] {
  some r: Req {
    notifAllow[r, g] or (some ls: Lease, p: Param | windowAllow[r, r.by', ls, p, g])
    r.by'.domain = Host
  }
}

// A standing grant of the config with exactly g's capability and
// parameters, which the user hasn't ended in this daemon's life, or which
// a start grants (start clears what was ended).
pred fromConfigNow[g: Grant] {
  g.glease = LStanding
  g.gparams in g.gl.standing[g.gcap]
  start[g.gl] or g.gparams not in g.gl.ended[g.gcap]
}

// P1. No grant without consent: a grant is born from an Allow by a host
// principal (the notification's action or a control.sock client) for its
// capability and parameters, or from the config as a standing grant with
// exactly its parameters that the user hasn't ended in this daemon's life
// (isStanding, standing.go; start, run.go; answers from the host only,
// sockets.go).
// Revert: hostOnly true, or isStanding matching any standing parameters
// of the capability: counterexample either way.
assert P1noGrantWithoutConsent {
  always all g: Grant | born[g] implies allowedByHost[g] or fromConfigNow[g]
}
check P1noGrantWithoutConsent for 3 but 0 Process, 2 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 0
// P1's premise: grants born from the notification, the window, a start
// and a request a standing grant covers.
run P1grants {
  eventually some r: Req, g: Grant | notifAllow[r, g]
  eventually some r: Req, w: Principal, ls: Lease, p: Param, g: Grant | windowAllow[r, w, ls, p, g]
  eventually some l: Launcher | start[l] and some Live' & gl.l
  eventually some r: Req, g: Grant | fromConfig[r, g]
} for 3 but 0 Process, 2 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 1

// The user ends a standing grant of (l, c, p) in this step: revokes it,
// or the sandbox releases it.
pred userEnds[l: Launcher, c: Capability, p: Param] {
  some h: Live & glease.LStanding {
    h.gl = l and h.gcap = c and h.gparams = p
    (some w: Principal | revoke[h, w]) or release[h]
  }
}

// P1: a standing grant the user ended stays ended until the daemon
// restarts. Revoke and release record it as ended
// (revoke, release, leases.go), so the sandbox's next request with the
// same parameters asks again; only a start grants it again. Holds.
// Revert: revoke or release not recording it: request() grants it back
// without asking (counterexample, tried 2026-11-01).
assert P1endedStandingAsks {
  always all g: Grant | (born[g] and g.glease = LStanding and not start[g.gl]) implies
    not ((not start[g.gl]) since userEnds[g.gl, g.gcap, g.gparams])
}
check P1endedStandingAsks for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  3 Grant, 3 Req, 0 Conn, 1 Text, 3 Int, 1..7 steps expect 0
// P1's premise: a revoked standing grant asked for again, and back after
// a restart.
run P1standingBackAfterRestart {
  some l: Launcher, c: Capability, p: Param | eventually (userEnds[l, c, p]
    and after eventually ((some r: Req | r.rl = l and r.rcap = c and r.rparams = p and ask[r])
      and after eventually (start[l] and after (some g: Live | g.gl = l and g.gcap = c and g.gparams = p))))
} for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  3 Grant, 3 Req, 0 Conn, 1 Text, 3 Int, 1..9 steps expect 1

// P2. A standing grant comes only from the config: every grant with lease
// standing is one the launcher's config declares, and no request or
// answer picks lease standing (request() and windowDecision, consent.go);
// none is of type attach (the module's assertion).
// Revert: windowAllow without `ls != LStanding`: the window's answer makes
// a standing grant of what the config doesn't declare (counterexample,
// tried 2026-11-01).
assert P2standingFromConfigOnly {
  always all g: Live & glease.LStanding | g.gparams in g.gl.standing[g.gcap] and g.gcap.dtype != Attach
}
check P2standingFromConfigOnly for 3 but 0 Process, 2 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 0
// P2's premise: standing grants of a host socket and a host command.
run P2standing {
  eventually some g: Live & glease.LStanding | g.gcap.dtype = Socket
  eventually some g: Live & glease.LStanding | g.gcap.dtype = Command
} for 3 but 0 Process, 2 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 1

// P6. Only host principals answer: a pending request leaves by the
// notification's action once it has been up a second (askOn, notify.go),
// by a control.sock client in the daemon's user namespace (handleControl,
// sockets.go), by
// a refusal (deny, timeout), or with the daemon or the sandbox.
// Revert: actionMature true, or hostOnly true: counterexample either way.
assert P6onlyHostAnswers {
  always all r: Req {
    (some g: Grant | notifAllow[r, g]) implies r in Mature
    all w: Principal, ls: Lease, p: Param, g: Grant | windowAllow[r, w, ls, p, g] implies w.domain = Host
    options[r] implies r in Mature
  }
}
check P6onlyHostAnswers for 3 but 0 Process, 2 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 0
run P6answers {
  eventually some r: Req, w: Principal, ls: Lease, p: Param, g: Grant | r in Opened and windowAllow[r, w, ls, p, g]
} for 3 but 0 Process, 2 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 1

// P7. Consent text is the daemon's: what the broker's notification shows
// is the summary the daemon built (describe, describeAttach; reason quoted and
// escaped, notify.go, capability.go). Holds: the sandbox's notifications go
// through the portal, which keeps each app's to itself (no RawNotify).
// Revert: P7consentTextRawNotify.
assert P7consentTextIsDaemons {
  no RawNotify implies always all r: Pending - Opened | r.shows = r.summary
}
check P7consentTextIsDaemons for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Grant, 2 Req, 0 Conn, 2 Text, 3 Int, 1..4 steps expect 0
// P7 with the sandbox on the notification server itself, as it was
// (B4, confirmed against Plasma 6.6's source, not tried live): it calls
// Notify with replaces_id set to the broker's notification id
// (xdg-dbus-proxy let Notify through whole), and Plasma swaps it for the
// sandbox's text and buttons (server_p.cpp Notify keeps no owner per id).
// Ids are sequential, so the sandbox learned the broker's by posting one
// of its own right after its request. Counterexample found.
assert P7consentTextRawNotify {
  always all r: Pending - Opened | r.shows = r.summary
}
check P7consentTextRawNotify for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Grant, 2 Req, 0 Conn, 2 Text, 3 Int, 1..4 steps expect 1
// P7 as a grant: no Allow on a notification the sandbox drew. Holds: the
// broker's buttons have random action keys per notification, and only
// ActionInvoked from the server's connection counts (askOn, notify.go),
// so a replacement's "Deny" with the key `allow` is a refusal.
// Revert: notifAllow without `r not in Forged` (fixed keys, as with
// notify-send before): counterexample found.
assert P7noAllowOnForged {
  always all r: Req, g: Grant | notifAllow[r, g] implies r not in Forged
}
check P7noAllowOnForged for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Grant, 2 Req, 0 Conn, 2 Text, 3 Int, 1..7 steps expect 0

// P14. The sandbox can't keep the user from answering: at most one
// pending request per capability and launcher (openGate, consent.go),
// and none while a capability is blocked after three refusals.
// The connection budgets (64 per socket and per host socket address,
// 10 s, 1 MiB) are counting, left to the Go tests.
// Revert: gateOpen true: two pending requests for one capability.
assert P14onePendingPerCapability {
  always all l: Launcher, c: Capability | lone r: Pending | r.rl = l and r.rcap = c
  always all r: Req | ask[r] implies r.rcap not in r.rl.blocked
  always all r: Req | (refuse[r] and nref[r.rl, r.rcap] = 2) implies after r.rcap in r.rl.blocked
}
check P14onePendingPerCapability for 3 but 0 Process, 2 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 4 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 0
// P14's premise: a capability blocked after three refusals, and two
// capabilities pending at once.
run P14blocks {
  eventually some l: Launcher | some l.blocked
} for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Grant, 3 Req, 0 Conn, 1 Text, 3 Int, 1..8 steps expect 1
