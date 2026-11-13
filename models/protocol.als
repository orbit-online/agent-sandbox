/*
 * Step 3: the permissions broker's protocol over time (README.md, P1-P17).
 * This file holds the system: requests and host command calls, consent,
 * grants per delivery type, leases, calls running, connections to host
 * sockets, standing grants from the config, the daemon's crashes and
 * restarts, several launchers, and the attacker's moves interleaved; its
 * own commands only test the encoding. protocol-consent.als checks
 * consent (P1, P2, P6, P7, P14), protocol-life.als the grants'
 * lifecycle (P3, P4, P9-P13), protocol-calls.als calls and host sockets
 * (P16, P17), protocol-tree.als the process tree (P5),
 * protocol-window.als the window's view. The system is in
 * protocol_state.als, protocol_events.als and protocol_system.als, which
 * the checks `open` (Alloy module names can't contain '-'); this file
 * holds the encoding's own runs.
 *
 * Sources: cmd/permissions-broker/*.go at acbceda (consent.go, call.go,
 * leases.go, standing.go, instances.go, commands.go, hostsockets.go,
 * splice.go, attach.go, run.go, sockets.go, notify.go); the code wins
 * where docs/permissions.md differs.
 *
 * Time is abstract: a step is one event. The 1 s guard on notification
 * actions is the event `mature`, a lease's clock the event `tick`, the
 * 2 minute block the event `unblock`. Answer timeouts are refusals.
 *
 * The attacker is the sandbox: it picks every request's and call's
 * capability, parameters, arguments and lease, releases any grant,
 * connects to every host socket address as often as it likes and hangs
 * up, renames directories under a ceiling root (`env` changes what a
 * parameter resolves to), sends `share` from M1, and posts
 * notifications. It can't reach control.sock
 * (S6), so window answers come from host principals.
 */
module protocol
open protocol_system

// HIDE: Id Cap UserNS OwnedNS MountNS NetNS IpcNS UtsNS CgroupNS PidNS Pid Process File MountFlag Mount PeerCheck Socket Domain

// ---------------------------------------------------------------------
// Checks of the encoding itself: every delivery type is granted and ends,
// a call runs and a connection is spliced, and a daemon crashes, is
// cleaned up and starts again. No claim about the broker; protocol-*.als
// hold those.

run deliveries {
  all t: DType | eventually some g: Grant | g.gcap.dtype = t and born[g]
  eventually some g: Grant | g in Ended and g.gcap.dtype = Attach
} for 3 but 0 Process, 1 Launcher, 3 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 1 Conn, 2 Text, 3 Int, 1..8 steps expect 1

run callsAndConnections {
  eventually some r: Req | startCall[r] and after answerCall[r]
  eventually some k: Conn, g: Grant | connect[k, g] and after eventually (k in Spliced and revoke[g, WindowP])
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 1 Dir,
  2 Grant, 2 Req, 1 Conn, 2 Text, 3 Int, 1..8 steps expect 1

run restart {
  some l: Launcher | eventually (crash[l] and some Mounted & gl.l and after (stopPost[l] and after start[l]))
  eventually some l: Launcher, w: Principal | share[l, w] and w in BwrapInitP
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  3 Grant, 3 Req, 0 Conn, 2 Text, 3 Int, 1..8 steps expect 1
