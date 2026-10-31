/*
 * Step 3: the permissions broker's protocol over time (README.md, P1-P14).
 * This file holds the system: requests, consent, grants per delivery type,
 * leases, the store, the daemon's crashes and restarts, several launchers,
 * and the attacker's moves interleaved; its own commands only test the
 * encoding. protocol-consent.als checks consent (P1, P2, P6, P7, P14),
 * protocol-life.als the grants' lifecycle (P3, P4, P9-P13),
 * protocol-tree.als the process tree (P5, P8), protocol-window.als the
 * window's view. The system is in protocol_state.als, protocol_events.als
 * and protocol_system.als, which the checks `open` (Alloy module names
 * can't contain '-'); this file holds the encoding's own runs.
 *
 * Sources: nix/packages/permissions-broker/{broker,plugins,mounts,sandbox}.go
 * at 9a902c9; the code wins where docs/permissions.md differs.
 *
 * Time is abstract: a step is one event. The 1 s guard on notification
 * actions is the event `mature`, a lease's clock the event `tick`, the
 * 2 minute block the event `unblock`. Answer timeouts are refusals.
 *
 * The attacker is the sandbox: it picks every request's capability,
 * parameters, lease and session (forged CLAUDE_CODE_SESSION_ID included),
 * releases any grant, ends its sessions, renames directories under a
 * ceiling root (`env` changes what a parameter resolves to), sends `share`
 * from M1 (udhcpc), and posts notifications. It can't reach control.sock
 * (S6), so window answers come from host principals.
 */
module protocol
open protocol_system

// HIDE: Id Cap UserNS OwnedNS MountNS NetNS IpcNS UtsNS CgroupNS PidNS Pid Process File MountFlag Mount PeerCheck Socket Domain

// ---------------------------------------------------------------------
// Checks of the encoding itself: every delivery type is granted and ends,
// and a daemon crashes, is cleaned up and replays. No claim about the
// broker; protocol-*.als hold those.

run deliveries {
  all t: DType | eventually some g: Grant | g.gcap.dtype = t and born[g]
  eventually some g: Grant | g in Ended and g.gcap.dtype = TypeC
} for 3 but 0 Process, 1 Launcher, 3 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 1

run restart {
  some l: Launcher | eventually (crash[l] and some Mounted & gl.l and after (stopPost[l] and after start[l]))
  eventually some l: Launcher, w: Principal | share[l, w] and w in UdhcpcP
} for 3 but 0 Process, 1 Launcher, 2 Capability, 2 Param, 2 Instance, 2 Dir,
  2 Session, 3 Grant, 3 Req, 2 Text, 3 Int, 1..8 steps expect 1
