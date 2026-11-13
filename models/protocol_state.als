/*
 * The protocol model's state (protocol.als): signatures, the checks the
 * daemon makes, and the frames and grant bookkeeping every event shares.
 * protocol_events.als adds requests, calls, answers, connections and ends
 * of grants, protocol_system.als the daemon's life and the traces.
 */
module protocol_state
open sandbox

// Host sockets, host commands, folders, ports (capability.go, ports.go).
abstract sig DType {}
one sig Socket, Command, Attach, Fwd extends DType {}

// Requested or granted lease. A duration is LDuration with a counter.
// LStanding only for a standing grant from the config: no request or
// answer picks it. LOnce only for a call's grant (obtain, consent.go).
abstract sig Lease {}
one sig LOnce, LLock, LDuration, LStanding extends Lease {}

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
  // validate() passes: the bounding values
  wellFormed: set Param,
  // the instances its instances glob finds that these parameters match
  // (instancesOf, instances.go)
  matches: Param -> Instance,
  // command: maxValidity
  maxV: one Int,
  // the exclusive lock files, by capability and instance
  var lockFile: Instance -> lone Launcher
}
// Exclusive capabilities are host commands and host sockets, whose
// instances glob names the instances locked (an attach one would lock by
// its parameters; none is).
sig Exclusive in Capability {}
fact { no Exclusive & dtype.(Attach + Fwd) }
// What an attach parameter resolves to now: the attacker renames
// directories under a ceiling root at will.
sig Param { var resolves: lone Dir }
sig Instance {}
var sig Listed in Instance {}
// A directory. InCeiling: beneath a ceiling root reached without links or
// mount crossings, not denied, no submounts (S11, clone-tree).
sig Dir {}
sig InCeiling in Dir {}
sig Text {}

sig Grant {
  gl: one Launcher, gcap: one Capability, gparams: one Param, glease: one Lease,
  // a duration lease's remaining time
  var left: lone Int,
  // attach: the directory mounted
  var mdir: lone Dir
}
// Mounted: the attach mount in M1 and everywhere it propagated.
// Forwarded: the port of a port grant on in the ports map of the sandbox
// (netns-netkit grant). Closing: an ended port grant whose revoke failed,
// its port on until a try in the background succeeds (portState.closing,
// ports.go).
var sig Live, Ended, Mounted, Forwarded, Closing in Grant {}
// Failing: the helper fails to revoke the ports of the sandbox of the
// launcher now; free in every step.
var sig Failing in Launcher {}

// One request on request.sock: what the sandbox sends and the daemon
// derives from it. summary: the
// daemon's text (describe, describeAttach). shows: what the notification with
// the request's id draws now.
sig Req {
  rl: one Launcher, rcap: one Capability, rparams: one Param, rlease: one Lease,
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

// A call (op call, call.go): a request that runs one of a host command
// capability's commands, its parameters the bounding values, with free
// arguments. ArgsOK: they validate against the command's schema
// (validateArgs).
// under: the grant that covers it, once it is served.
sig CallReq in Req { var under: lone Grant }
sig ArgsOK in CallReq {}
// A call served: waiting for its slot (callSlot), then its transient unit
// running (runCall).
var sig Queued, Running in CallReq {}

// A connection from the sandbox to a host socket's address in the grant
// directory (sockets/<capability>[/<instance>], hostsockets.go), of a
// launcher's sandbox, to the address of a capability and parameters.
// Spliced: through to the host socket, under the grant via. Closed: by
// either side or the broker; a connection isn't opened again.
sig Conn { kl: one Launcher, kcap: one Capability, kparams: one Param, var via: lone Grant }
var sig Spliced, Closed in Conn {}

fact static {
  all i: Instance | lone c: Capability | i in Param.(c.matches)
  all c: Capability | c.matches.Instance in c.wellFormed
  all c: Capability | c.maxV > 0
  // the summary is the daemon's, a function of capability and parameters
  all r, q: Req | (r.rcap = q.rcap and r.rparams = q.rparams) implies r.summary = q.summary
  // request() refuses lease standing (consent.go)
  no rlease.LStanding
  // standing grants are of host commands and host sockets only: folders
  // that should always be there are binds (the module's assertion)
  all l: Launcher | no l.standing.Param & dtype.Attach
}

// Not ended by the user in this daemon's life: request() grants it
// without asking (isStanding, standing.go). Exact parameters only.
pred standingNow[l: Launcher, c: Capability, p: Param] {
  p in l.standing[c] - l.ended[c]
}

// ---------------------------------------------------------------------
// Checks the daemon makes, each named so a revert check can drop it.

// The parameters validate, and match an instance the instances glob finds
// (host commands, host sockets: inList), or resolve beneath the ceiling
// (attach): obtain before asking, and again on the answer (consent.go,
// instances.go, ceiling.go).
pred passes[c: Capability, p: Param] {
  p in c.wellFormed
  c.dtype = Attach implies (some p.resolves and p.resolves in InCeiling)
  c.dtype != Attach implies some p.(c.matches) & Listed
}

// checkLease (leases.go): a lock lease needs a watched logind.
pred leaseOK[l: Launcher, ls: Lease] {
  ls = LLock implies l in Watched
}

// call (call.go): a call names one of a host command capability's
// commands, and its arguments validate, before obtain asks.
pred callChecks[r: Req] {
  r in CallReq implies (r.rcap.dtype = Command and r in ArgsOK)
}

// obtain (consent.go): a once lease only for a call, asked for or answered.
pred onceForCalls[r: Req, ls: Lease] { ls = LOnce implies r in CallReq }

// obtain (consent.go): the window may change a host command grant's lease,
// never its bounding values.
pred boundingFixed[r: Req, p: Param] { r.rcap.dtype = Command implies p = r.rparams }

// matching (consent.go): a live grant of the same capability and exactly
// the same parameters covers a request or call; a once grant covers the
// call it was made for only.
pred covers[g: Grant, l: Launcher, c: Capability, p: Param] {
  g in Live and g.gl = l and g.gcap = c and g.gparams = p and g.glease != LOnce
}

// openGate (consent.go): one open request per capability, none while
// blocked.
pred gateOpen[l: Launcher, c: Capability] { c not in l.asking + l.blocked }

// control.sock answers only peers in the daemon's user namespace
// (handleControl, sockets.go).
pred hostOnly[w: Principal] { w.domain = Host }

// share only from M1 (handleRequest, sockets.go): bwrap's init and the
// FHS env script.
pred inM1[w: Principal] { w in BwrapInitP }

// askOn ignores an action within a second of the notification appearing
// (notify.go).
pred actionMature[r: Req] { r in Mature }

// attachGrant resolves again and clone-tree checks what it opens
// (attach.go, tree.go): an attach grant mounts only what is in the
// ceiling now.
pred mountChecks[N: set Grant] {
  all g: N & typed[Attach] | some g.gparams.resolves and g.gparams.resolves in InCeiling
}

// exclusiveLock (instances.go): O_EXCL on a file per instance the
// parameters match. A lock of this launcher's is shared only with a live
// grant of it with the same parameters (a once grant beside another).
// The locks of L were removed first (a start's cleanup of its own
// launcher's).
pred exclusiveLockFree[N: set Grant, L: set Launcher] {
  all g: N & gcap.Exclusive, i: g.gparams.(g.gcap.matches) | some i.(g.gcap.lockFile) - L implies
    (i.(g.gcap.lockFile) = g.gl and some h: Live | h.gl = g.gl and h.gcap = g.gcap and h.gparams = g.gparams)
  all disj g, h: N & gcap.Exclusive | g.gcap != h.gcap or no g.gparams.(g.gcap.matches) & h.gparams.(h.gcap.matches)
}

// runCall (call.go): a grant's end stops the units of its calls (the
// goroutine on g.ended); D are the calls answered in this step.
pred stopCalls[D: set Req, E: set Grant] { Running' = Running - D - under.E }

// g.end (leases.go) runs closeConns (splice.go): the connections spliced
// under a grant that ends are closed.
pred closeConns[E: set Grant] {
  Spliced' = Spliced - via.E
  Closed' = Closed + (Spliced & via.E)
}

// connectUnder (splice.go): a connection to an address is spliced under
// the live grant of that address's capability and parameters.
pred connectUnder[k: Conn, g: Grant] {
  g in Live and g.gl = k.kl and g.gcap = k.kcap and g.gparams = k.kparams
}

// call units are BindsTo= the daemon's unit (runCall, call.go): they stop
// when it does.
pred bindsTo[l: Launcher] { Running' = Running - under.(gl.l) }

// cleanup (attach.go): stops the launcher's call units, removes its locks,
// detaches its folders and removes their mountpoints and the host sockets'
// addresses, and last switches its ports off (revokePorts, ports.go), with
// or without the sandbox found: revoke --all needs only the launcher name.
// While the helper fails, the ports stay on and the cleanup tries again
// (retry): it isn't done.
pred cleanup[l: Launcher] {
  Mounted' = Mounted - gl.l
  Forwarded' = Forwarded - gl.(l - Failing)
  Closing' = Closing - gl.l
  Running' = Running - under.(gl.l)
  lockFile' = lockFile - (Capability -> Instance -> l)
}

// ---------------------------------------------------------------------
// Frames and the grant bookkeeping every event shares.

fun typed[t: DType]: set Grant { (gcap.dtype).t }
// The port grants of the same launcher and port as one of G.
fun samePort[G: set Grant]: set Grant {
  { g: typed[Fwd] | some x: G & typed[Fwd] | g.gl = x.gl and g.gcap = x.gcap and g.gparams = x.gparams }
}
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
pred keepEnv { Listed' = Listed and resolves' = resolves }
pred keepReqs {
  Pending' = Pending and Mature' = Mature and Opened' = Opened and Asked' = Asked and Forged' = Forged
  shownDir' = shownDir and shows' = shows and by' = by
}
pred keepCalls { Queued' = Queued and Running' = Running and under' = under }
pred keepConns { Spliced' = Spliced and Closed' = Closed and via' = via }
pred keepLive {
  Live' = Live and Ended' = Ended and Mounted' = Mounted and Forwarded' = Forwarded and Closing' = Closing
  left' = left and mdir' = mdir and lockFile' = lockFile
}
pred keepGrants { keepLive and keepCalls and keepConns }

// N are made live and E end in this step; the locks of E are released
// unless a live grant of the same holds them, and E's connections close.
// grant() and g.end (leases.go). The calls are the caller's: calls[].
pred change[N, E: set Grant] {
  no N & (Live + Ended)
  E in Live
  exclusiveLockFree[N, none]
  mountChecks[N]
  Live' = Live - E + N
  Ended' = Ended + E
  Mounted' = Mounted - E + (N & typed[Attach])
  // live and end of portKind (ports.go): a port grant that can't switch its
  // port on isn't made, and one that does clears a closing record of its
  // port; the port of an ended one goes off unless a live grant holds it,
  // or the helper fails to revoke it, all tries of portOff, and it's
  // closing. The runs of the helper for a port are serialized
  // (portState.mu), so a grant and the revoke of another don't interleave
  let F = (E & typed[Fwd] & gl.Failing) - samePort[Live - E + N] {
    Forwarded' = Forwarded - E - (Closing & samePort[N]) + F + (N & typed[Fwd])
    Closing' = Closing - samePort[N] + F
  }
  all g: N & typed[Attach] | g.mdir' = g.gparams.resolves
  all g: Grant - (N & typed[Attach]) | g.mdir' = g.mdir
  all g: N | g.glease = LDuration implies g.left' > 0 else no g.left'
  all g: Grant - N | g.left' = g.left
  lockFile' = lockFile - locksOf[E] + locksOf[Live - E + N]
  closeConns[E] and via' = via
}

// The calls after this step: the call r (none, or a request that isn't
// one: nothing) is served under g and waits for its slot, D are answered,
// and the units of E's calls are stopped.
pred calls[r: lone Req, g: lone Grant, D: set Req, E: set Grant] {
  Queued' = Queued - D + (r & CallReq)
  under' = under + (r & CallReq) -> g
  stopCalls[D, E]
}

// Ends E, nothing else changes.
pred endOnly[E: set Grant] {
  change[none, E]
  calls[none, none, none, E]
  keepDaemons and keepGates and keepEnv and keepReqs and ended' = ended
}

// A request leaves the daemon: answered, refused, failed.
pred settle[r: Req, w: lone Principal] {
  Pending' = Pending - r and Mature' = Mature and Opened' = Opened and Asked' = Asked
  Forged' = Forged and shownDir' = shownDir and shows' = shows
  by' = by - r -> Principal + r -> w
}

pred init {
  no Up + Dirty + Gone
  no Live + Ended + Mounted + Forwarded + Closing
  no Pending + Mature + Opened + Asked + Forged
  no Queued + Running + Spliced + Closed
  no under and no via
  no asking and no refused and no blocked and no lockFile
  no ended
  no left and no mdir and no shownDir and no shows
}
