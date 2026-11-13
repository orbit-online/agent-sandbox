/*
 * Step 4: the launch path over time, the outer bwrap through the app
 * (README.md, L1, L4 and L9). This file has the shared signatures and the
 * outer stage (L1 for U1); launch-fhs.als the FHS env's stage
 * (L1 for U2, L4, L9). Re-entries, the handle on the sandbox and
 * lifetimes are in launch-reentry.als, what the host-side launcher does
 * to files the sandbox writes in launch-host.als.
 *
 * Two stages, each its own initial state:
 *
 * - outer: nixpak's launcher runs bwrap through the launcher's bwrap
 *   (cmd/launcher bwrap.go, mode subid): bwrap's child waits on
 *   --userns-block-fd while its helper (helper.go) writes U1's maps with
 *   newuidmap and newgidmap and kills it if they fail. Then the helper
 *   unblocks it, runs `netns-netkit up`, which puts eth0 in N, and sets up
 *   eth0 with an nsenter into U1 and N that is gone before the app starts
 *   (netSetup.run). Only then does it forward the info that names the
 *   child to nixpak, which holds the child on its --block-fd until it has
 *   it (launcher/main.go: its pasta slot is a no-op now).
 * - fhs: the FHS env's script in U1 asks the broker to `share`, its bwrap
 *   (the launcher's bwrap, mode parent) copies M1 into M2 and waits for
 *   U2's maps, app-pid.sh sets ns_last_pid with CAP_CHECKPOINT_RESTORE
 *   and starts the app.
 *
 * Each enforcing step of the code is a Guard, so a revert check is the
 * same system without it.
 */
module launch

open sandbox

// HIDE: File Mount MountFlag Socket PeerCheck IpcNS UtsNS CgroupNS Guard

// ---------------------------------------------------------------------
// The namespaces of default.nix's diagram. U2, M2 and P2 are there from
// the start; nothing runs in them before the fhs stage.

one sig U1, U2 extends UserNS {}
one sig HostMnt, M1, M2 extends MountNS {}
one sig HostNet, N extends NetNS {}
one sig P, P2 extends PidNS {}
// The user's /etc/subuid and /etc/subgid range, as one atom
one sig SubIds extends Id {}

fact launchShape {
  UserNS = InitUserNS + U1 + U2
  MountNS = HostMnt + M1 + M2
  NetNS = HostNet + N
  PidNS = InitPidNS + P + P2
  no IpcNS + UtsNS + CgroupNS
  no Mount + File + Socket
  Id = HostUser + HostRoot + Overflow + SubIds
  U1.parent = InitUserNS and U1.owner = HostUser
  (HostMnt + HostNet).ownedBy = InitUserNS
  (M1 + N + P).ownedBy = U1
  P.pparent = InitPidNS
  U2.parent = U1 and U2.owner = HostUser
  M2.ownedBy = U2 and P2.ownedBy = U2 and P2.pparent = P
}

// ---------------------------------------------------------------------
// State beyond the base's processes and maps

abstract sig Flag {}
one sig
  RootFinal,       // bwrap pivoted: /.flatpak-info shows in the child's root
  NetDone,         // the helper set up the network and forwarded the info, so nixpak may write the block fd
  ShareTried,      // the FHS env's script ran `permissions-broker share`
  M1Shared,        // /run/permissions is a shared mount in M1
  BrokerShared,          // the broker's b.shared: it accepts attach requests
  M2Copied,        // the FHS env's bwrap copied M1 into M2
  M2Slave,         // M2's /run/permissions receives what M1's gets
  LastPidFail      // app-pid.sh's write to ns_last_pid failed
  extends Flag {}
var sig On in Flag {}

// Waiting on --userns-block-fd (bwrap.go's fd 21)
var sig Blocked in Process {}
// Waiting on nixpak's --block-fd
var sig Held in Process {}
// Roles: the outer bwrap's child (pid 1 in P, bwrapinfo's child-pid), the
// FHS env's script, the FHS env's bwrap child, app-pid.sh
var sig Root, Fhs, FhsChild, AppPidS in Process {}

abstract sig Guard {}
one sig
  KillOnMapFail,      // helper.go:55-59 kills the child and bwrap, and fd 21 written only after (:88)
  DropCapsBeforeFork, // app-pid.sh:9-10 setpriv --inh-caps=-all --ambient-caps=-all, then setsid
  DropCapsOnFail,     // app-pid.sh:12 the same setpriv when the ns_last_pid write fails
  ShareBeforeCopy     // bwrap.go:119-123 share before line 177's exec of bwrap
  extends Guard {}

fun launcher: set Process { principal.LauncherP }

// ---------------------------------------------------------------------
// Frames

pred same[p: Process] {
  p in Process'
  p.pid' = p.pid and p.ppid' = p.ppid and p.uid' = p.uid and p.caps' = p.caps
  p.userns' = p.userns and p.mnt' = p.mnt and p.net' = p.net and p.pidns' = p.pidns
}

// p keeps all but its uid and caps
pred sameNs[p: Process] {
  p in Process'
  p.pid' = p.pid and p.ppid' = p.ppid
  p.userns' = p.userns and p.mnt' = p.mnt and p.net' = p.net and p.pidns' = p.pidns
}

pred born[n: Process, pr: Principal, par: Process, u: UserNS, m: MountNS,
    nt: NetNS, pn: PidNS, id: Id, cs: set Cap] {
  n not in Process
  n.principal' = pr and n.ppid' = par and n.uid' = id and n.caps' = cs
  n.userns' = u and n.mnt' = m and n.net' = nt and n.pidns' = pn
}

// Processes: born join, changed set their own fields, the rest stay
pred only[b, changed: set Process] {
  Process' = Process + b
  all p: Process - changed | same[p]
}

pred tags[r, f, d, a: set Process] {
  Root' = Root + r and Fhs' = Fhs + f and FhsChild' = FhsChild + d and AppPidS' = AppPidS + a
}

pred keepMaps { all u: UserNS | u.mapped' = u.mapped }
pred keepWaits { Blocked' = Blocked and Held' = Held }

pred skip {
  only[none, none] and tags[none, none, none, none]
  keepMaps and keepWaits and On' = On
}

// ---------------------------------------------------------------------
// Events, outer stage

// bwrap.go:177: bwrap clones its child into U1, N, M1, P. Unmapped,
// it runs as the overflow id, with every capability in U1
pred clone {
  no Root
  some c: Process' - Process {
    born[c, BwrapInitP, launcher, U1, M1, N, P, Overflow, Cap]
    only[c, none] and tags[c, none, none, none]
    Blocked' = Blocked + c and Held' = Held + c
  }
  keepMaps and On' = On
}

// The helper (helper.go:78-87) writes the waiting child's maps: U1's from
// /etc/subuid (maps.go:29), U2's as U1's ids (maps.go:46, through the
// subid-broker shims)
pred writeMap {
  some c: Blocked | no c.userns.mapped and {
    c.userns.mapped' = (c.userns = U1 implies HostUser + SubIds else c.userns.parent.mapped)
    all u: UserNS - c.userns | u.mapped' = u.mapped
  }
  only[none, none] and tags[none, none, none, none]
  keepWaits and On' = On
}

// newuidmap or newgidmap failed: kill -KILL the child (it has no children
// yet). Without the guard the helper isn't there, and the next line
// unblocks the child anyway
pred mapFail[g: set Guard] {
  KillOnMapFail in g
  some c: Blocked | no c.userns.mapped and {
    Process' = Process - c
    all p: Process - c | same[p]
    Blocked' = Blocked - c and Held' = Held - c
    Root' = Root - c and FhsChild' = FhsChild - c and Fhs' = Fhs and AppPidS' = AppPidS
  }
  keepMaps and On' = On
}

// `echo >&21`: the child goes on, as the user's id if mapped
pred unblock[g: set Guard] {
  some c: Blocked {
    KillOnMapFail in g implies some c.userns.mapped
    Blocked' = Blocked - c and Held' = Held
    sameNs[c] and c.caps' = c.caps
    c.uid' = (some c.userns.mapped implies HostUser else Overflow)
    only[none, c]
  }
  tags[none, none, none, none]
  keepMaps and On' = On
}

// bwrap's last pivot_root: from here /proc/<child>/root is the sandbox's,
// with /.flatpak-info. bwrap drops its capabilities
pred pivot {
  some c: Root - Blocked | RootFinal not in On and {
    On' = On + RootFinal
    sameNs[c] and c.uid' = c.uid and no c.caps'
    only[none, c]
  }
  tags[none, none, none, none]
  keepMaps and keepWaits
}

// The helper's network setup (helper.go netSetup.run), after the maps and
// before it forwards the info: netns-netkit up into the child's netns,
// then nsenter -U -n --keep-caps ip, which exits before the helper goes
// on. Nothing of it stays in the sandbox namespaces
pred netSetup {
  some c: Root & Held | some U1.mapped and NetDone not in On and On' = On + NetDone
  only[none, none] and tags[none, none, none, none]
  keepMaps and keepWaits
}

// nixpak writes its block fd once the pasta slot exited
pred release {
  some c: Root & Held | NetDone in On and {
    Held' = Held - c and Blocked' = Blocked
  }
  only[none, none] and tags[none, none, none, none]
  keepMaps and On' = On
}

// ---------------------------------------------------------------------
// The two stages

pred hostProcess[l: Process] {
  l.principal = LauncherP and no l.ppid and l.uid = HostUser and no l.caps
  l.userns = InitUserNS and l.mnt = HostMnt and l.net = HostNet and l.pidns = InitPidNS
}

pred outerInit {
  no U2.mapped
  one Process and hostProcess[Process]
  no U1.mapped
  no Blocked + Held + On + Root + Fhs + FhsChild + AppPidS
}

pred outer[g: set Guard] {
  outerInit
  always (clone or writeMap or mapFail[g] or unblock[g] or pivot or netSetup
    or release or skip)
}

// ---------------------------------------------------------------------
// Properties

// L1: nothing of the sandbox runs as the overflow id (helper.go:55-88:
// the child stays on fd 21 until the maps are written, and dies if they
// can't be), and the maps are exactly the subuid range plus the user's
// ids (U1, maps.go:29) and U1's ids (U2, maps.go:46).
pred l1 {
  always all p: Process - Blocked | p.principal.domain = Sandbox implies p.uid != Overflow
  always (some U1.mapped implies U1.mapped = HostUser + SubIds)
  always (some U2.mapped implies U2.mapped = U1.mapped)
}

// L1, outer stage: U1's maps.
assert L1outer { outer[Guard] implies l1 }
check L1outer for 4 but 9 OwnedNS, 1..8 steps expect 0

// L1, outer stage, revert: without KillOnMapFail the child is unblocked
// with no maps and bwrap's init runs as the overflow id.
assert L1outerRevert { outer[Guard - KillOnMapFail] implies l1 }
check L1outerRevert for 4 but 9 OwnedNS, 1..8 steps expect 1

// Vacuity: the outer stage reaches the network and the release of bwrap's
// child.
run outerRuns {
  outer[Guard]
  eventually (NetDone in On and no Held and some Root)
} for 4 but 9 OwnedNS, 1..8 steps expect 1
