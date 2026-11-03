/*
 * Host command calls and host socket connections: P16 and P17 over the
 * system in protocol.als (P4, P10 and P11 in protocol-life.als hold their
 * ends, validity and instances). As in protocol-consent.als, each claim
 * has a `run` for its premise, and "Revert:" names the check dropped to
 * see it fail (tried 2026-11-03).
 *
 * Sources: call.go (call, runCall), consent.go (obtain, matching),
 * splice.go (splice, connectUnder, closeConns), hostsockets.go.
 */
open protocol_system

// HIDE: Id Cap UserNS OwnedNS MountNS NetNS IpcNS UtsNS CgroupNS PidNS Pid Process File MountFlag Mount PeerCheck Socket Domain

// P16. A once grant covers only the call it was made for, and ends when
// that call is answered: a live once grant always has exactly its own
// call waiting or running. matching passes over once grants and obtain
// refuses once to a request (consent.go); call ends the grant when its
// call returns (defer g.end, call.go). Holds.
// Revert: covers without `g.glease != LOnce`: a second call runs under
// it; answerCall not ending it: it outlives its call; reqOK without
// onceForCalls: a request gets a once grant no call ends (a counterexample
// each).
assert P16onceCoversItsCall {
  always all g: Live & glease.LOnce | one under.g & (Queued + Running)
}
check P16onceCoversItsCall for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Grant, 3 Req, 0 Conn, 1 Text, 3 Int, 1..8 steps expect 0
// P16's premise: a call allowed once, run and answered, and a second call
// with the same bounding values asked about while it runs.
run P16once {
  eventually some r, q: Req, g: Grant | r != q and g.glease = LOnce and notifAllow[r, g]
    and after eventually (r in Running and q in CallReq and ask[q] and after eventually answerCall[r])
} for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Grant, 3 Req, 0 Conn, 1 Text, 3 Int, 1..10 steps expect 1

// P16. A grant covers calls with exactly its bounding values: every call
// waiting or running runs under a grant of its own launcher, capability
// and parameters. matching compares the parameters whole, and an answer
// may change a host command grant's lease, never its bounding values
// (obtain, consent.go). Holds.
// Revert: windowAllow without boundingFixed: the window answers a call
// with other bounding values and the call runs under them
// (counterexample).
assert P16boundingExact {
  always all r: Queued + Running | r.under.gl = r.rl and r.under.gcap = r.rcap and r.under.gparams = r.rparams
}
check P16boundingExact for 3 but 0 Process, 1 Launcher, 1 Capability, 2 Param, 2 Instance, 1 Dir,
  2 Grant, 2 Req, 0 Conn, 1 Text, 3 Int, 1..6 steps expect 0
// P16's premise: the window answers a call with a lease of its own.
run P16windowLease {
  eventually some r: CallReq, w: Principal, ls: Lease, p: Param, g: Grant |
    ls != r.rlease and windowAllow[r, w, ls, p, g]
} for 3 but 0 Process, 1 Launcher, 1 Capability, 2 Param, 2 Instance, 1 Dir,
  2 Grant, 2 Req, 0 Conn, 1 Text, 3 Int, 1..6 steps expect 1

// P16. A call checks its arguments before asking: a call that names no
// host command or whose arguments don't validate is never asked about,
// covered or run (call validates before obtain, call.go). Holds.
// Revert: reqOK without callChecks: counterexample.
assert P16argsBeforeAsking {
  always all r: CallReq - ArgsOK | r not in Asked + Queued + Running
  always all r: CallReq & Asked | r.rcap.dtype = Command
}
check P16argsBeforeAsking for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 1 Dir,
  2 Grant, 2 Req, 0 Conn, 1 Text, 3 Int, 1..6 steps expect 0
run P16callAsked {
  eventually some r: CallReq | ask[r]
  eventually some r: CallReq, g: Grant | matchLive[r, g]
} for 3 but 0 Process, 1 Launcher, 1 Capability, 1 Param, 1 Instance, 1 Dir,
  2 Grant, 2 Req, 0 Conn, 1 Text, 3 Int, 1..8 steps expect 1

// P17. A connection to a host socket's address is spliced only while a
// live grant covers that address: the launcher's, of its capability and
// parameters (the instance). connectUnder (splice.go) looks for that
// grant, not ending, when the connection comes; without one the
// connection is closed at once. g.end closes what was spliced under it
// (closeConns), a crash closes everything with the daemon's process.
// Holds.
// Revert: connectUnder without `g in Live`: a connection is spliced under
// a grant that ended; connectUnder by capability alone: a grant of one
// instance splices a connection to another's address; closeConns
// closing nothing: a connection outlives its grant (a counterexample
// each).
assert P17splicedUnderCover {
  always all k: Spliced | k.via in Live and k.via.gl = k.kl and k.via.gcap = k.kcap and k.via.gparams = k.kparams
}
check P17splicedUnderCover for 3 but 0 Process, 1 Launcher, 1 Capability, 2 Param, 2 Instance, 1 Dir,
  2 Grant, 2 Req, 2 Conn, 1 Text, 3 Int, 1..7 steps expect 0
// P17's premise: a connection spliced under a grant, another to the same
// address closed at once after the grant ended.
run P17connections {
  eventually some disj k, j: Conn, g: Grant | connect[k, g] and after eventually
    (g in Ended and connect[j, none] and j.kparams = k.kparams)
} for 3 but 0 Process, 1 Launcher, 1 Capability, 2 Param, 2 Instance, 1 Dir,
  2 Grant, 2 Req, 2 Conn, 1 Text, 3 Int, 1..7 steps expect 1
