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

// P1. No grant without consent: a grant is born from an Allow by a host
// principal (the notification's action or a control.sock client) for its
// capability and parameters, or from the store, with exactly its
// parameters (isAlways, broker.go:697-707; answer from the host only,
// broker.go:386).
// Revert: hostOnly true, or isAlways matching any stored parameters of
// the capability: counterexample either way.
assert P1noGrantWithoutConsent {
  always all g: Grant | born[g] implies
    allowedByHost[g] or g.gparams in g.gl.stored[g.gcap]
}
check P1noGrantWithoutConsent for 3 but 0 Process, 2 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 0
// P1's premise: grants born from the notification, the window and the store.
run P1grants {
  eventually some r: Req, g: Grant | notifAllow[r, g]
  eventually some r: Req, w: Principal, ls: Lease, p: Param, g: Grant | windowAllow[r, w, ls, p, g]
  eventually some r: Req, g: Grant | fromStore[r, g]
} for 3 but 0 Process, 2 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 1

// Known, consent confusion (P1, P8), by design per docs/permissions.md
// ("session ties are counted"): a session lease the user allowed "for this
// session" gains every other session that asks for the same parameters,
// without asking (addSession, broker.go:569-572), so it lasts as long as
// the longest of them. Any process can be a session: an anchor is any
// binary named `claude` above a process with CLAUDE_CODE_SESSION_ID set.
assert P1sessionLeaseNotWidened {
  always all g: Grant | g in Live implies g.gsess' in g.gsess
}
check P1sessionLeaseNotWidened for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Session, 2 Grant, 3 Req, 1 Text, 3 Int, 1..6 steps expect 1

// Known, consent confusion (P1), by the docs' design: Revoke on an always
// grant ends the live grant but keeps its store entry (revoke,
// broker.go:995-1004; only Forget removes it), so the sandbox's next
// request with the same parameters gets it back without a notification.
assert P1revokedStaysRevoked {
  always all r: Req, g: Grant | fromStore[r, g] implies
    not (once some h: Grant, w: Principal | revoke[h, w] and h.gl = g.gl and h.gcap = g.gcap and h.gparams = g.gparams)
}
check P1revokedStaysRevoked for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Session, 3 Grant, 3 Req, 1 Text, 3 Int, 1..6 steps expect 1

// P2. always enters the store only from a window answer with lease always
// (broker.go:588-595: the notification offers session or an hour instead;
// 632-634: addAlways only for the answer's lease).
// Revert: offered[] with asked = rlease: the notification's Allow stores it.
assert P2alwaysFromWindowOnly {
  always all l: Launcher, c: Capability, p: Param |
    (p not in l.stored[c] and after p in l.stored[c]) implies
      some r: Req, w: Principal, g: Grant | r.rl = l and r.rcap = c and windowAllow[r, w, LAlways, p, g]
}
check P2alwaysFromWindowOnly for 3 but 0 Process, 2 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 0
// P2's premise: a request for always, allowed on the notification, and one
// stored from the window.
run P2stores {
  eventually some r: Req, g: Grant | r.rlease = LAlways and notifAllow[r, g]
  eventually some l: Launcher, c: Capability | some l.stored[c]
} for 3 but 0 Process, 2 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 1

// P6. Only host principals answer: a pending request leaves by the
// notification's action once it has been up a second (broker.go:1237), by
// a control.sock client in the daemon's user namespace (broker.go:386), by
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
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 0
run P6answers {
  eventually some r: Req, w: Principal, ls: Lease, p: Param, g: Grant | r in Opened and windowAllow[r, w, ls, p, g]
} for 3 but 0 Process, 2 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 1

// P7. Consent text is the daemon's: what the broker's notification shows
// is the summary the daemon built (describe, describeC; reason quoted and
// escaped, broker.go:1194-1195, plugins.go:175-200).
// Known, a finding (B4), confirmed against Plasma 6.6's and libnotify's
// source, not tried live: the sandbox may call Notify with replaces_id set
// to the broker's notification id (xdg-dbus-proxy lets Notify through
// whole), and Plasma swaps it for the sandbox's text and buttons
// (server_p.cpp Notify keeps no owner per id). notify-send takes any
// ActionInvoked for its id (libnotify notification.c:813-827), so a button
// labelled Deny whose key is `allow` grants. The 1 s guard doesn't help:
// the swap can come any time later. Ids are sequential, so the sandbox
// learns the broker's by posting one of its own right after its request.
// With forge[] dropped from the traces, the claim holds.
assert P7consentTextIsDaemons {
  always all r: Pending - Opened | r.shows = r.summary
}
check P7consentTextIsDaemons for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Session, 2 Grant, 2 Req, 2 Text, 3 Int, 1..4 steps expect 1
// The same finding as a grant: an Allow on a notification the sandbox drew.
assert P7noAllowOnForged {
  always all r: Req, g: Grant | notifAllow[r, g] implies r not in Forged
}
check P7noAllowOnForged for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Session, 2 Grant, 2 Req, 2 Text, 3 Int, 1..7 steps expect 1

// P14. The sandbox can't keep the user from answering: at most one
// pending request per capability and launcher (openGate, broker.go:
// 711-740), and none while a capability is blocked after three refusals.
// The connection budgets (64 per socket, 10 s, 64 KiB) are counting, left
// to the Go tests.
// Revert: gateOpen true: two pending requests for one capability.
assert P14onePendingPerCapability {
  always all l: Launcher, c: Capability | lone r: Pending | r.rl = l and r.rcap = c
  always all r: Req | ask[r] implies r.rcap not in r.rl.blocked
  always all r: Req | (refuse[r] and nref[r.rl, r.rcap] = 2) implies after r.rcap in r.rl.blocked
}
check P14onePendingPerCapability for 3 but 0 Process, 2 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 4 Req, 2 Text, 3 Int, 1..8 steps expect 0
// P14's premise: a capability blocked after three refusals, and two
// capabilities pending at once.
run P14blocks {
  eventually some l: Launcher | some l.blocked
} for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  1 Session, 1 Grant, 3 Req, 1 Text, 3 Int, 1..8 steps expect 1
