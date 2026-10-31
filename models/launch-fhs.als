/*
 * Step 4, the launch path's second stage (README.md, L1 for U2, L4, L9):
 * the FHS env's script in U1 asks the broker to `share`, its bwrap
 * (bwrap-subid.sh, SUBID_MAP=parent) copies M1 into M2 and waits for U2's
 * maps, app-pid.sh sets ns_last_pid with CAP_CHECKPOINT_RESTORE and starts
 * the app. It starts where launch.als's outer stage ends, with udhcpc
 * running as the attacker; the signatures, frames and l1 are launch.als's.
 */
// SLOW: about 4 minutes for the file with SAT4J, mostly the checks that hold.
module launch_fhs

open sandbox
open launch

// HIDE: File Mount MountFlag Socket PeerCheck IpcNS UtsNS CgroupNS Guard Move

// ---------------------------------------------------------------------
// Events, fhs stage

// bwrap-subid.sh:78-82: the FHS env's script asks for `share`. It may
// fail (the broker isn't up within the client's 10 s); the launch goes on
pred fhsShare {
  ShareTried not in On
  On' = On + ShareTried or On' = On + ShareTried + M1Shared + BrokerShared
  only[none, none] and tags[none, none, none, none]
  keepMaps and keepWaits and Eth0In' = Eth0In
}

// The same request from udhcpc, also in M1, at any time:
// broker.go:485 shareFrom only checks the client's mount namespace
pred lateShare {
  some principal.UdhcpcP & mnt.M1
  On' = On + M1Shared + BrokerShared
  only[none, none] and tags[none, none, none, none]
  keepMaps and keepWaits and Eth0In' = Eth0In
}

// bwrap-subid.sh:112 in parent mode: the FHS env's bwrap child in U2, M2
// (a copy of M1: a shared mount there turns a slave, a private one stays
// private), P2
pred fhsCopy[g: set Guard] {
  M2Copied not in On
  ShareBeforeCopy in g implies ShareTried in On
  some f: Fhs, d: Process' - Process {
    born[d, BwrapInitP, f, U2, M2, N, P2, Overflow, Cap]
    only[d, none] and tags[none, none, d, none]
    Blocked' = Blocked + d and Held' = Held
  }
  On' = On + M2Copied + (M1Shared in On implies M2Slave else none)
  keepMaps and Eth0In' = Eth0In
}

// The FHS env's init runs app-pid.sh, with CAP_CHECKPOINT_RESTORE raised
// as ambient (default.nix: extraBwrapArgs --cap-add)
pred appPidStart {
  no AppPidS
  some d: FhsChild - Blocked, a: Process' - Process {
    born[a, BwrapInitP, d, d.userns, d.mnt, d.net, d.pidns, HostUser, CheckpointRestore]
    only[a, none] and tags[none, none, none, a]
  }
  keepMaps and keepWaits and On' = On and Eth0In' = Eth0In
}

// app-pid.sh:8-12. When the write succeeds, setpriv clears the ambient
// set before setsid forks the app. When it fails, the same setpriv runs
// the app in app-pid.sh's place (modelled as a child, since a principal
// never changes)
pred appStart[g: set Guard] {
  no principal.AppP
  some a: AppPidS, n: Process' - Process {
    {
      On' = On
      born[n, AppP, a, a.userns, a.mnt, a.net, a.pidns, a.uid,
        (DropCapsBeforeFork in g implies none else a.caps)]
    } or {
      On' = On + LastPidFail
      born[n, AppP, a, a.userns, a.mnt, a.net, a.pidns, a.uid,
        (DropCapsOnFail in g implies none else a.caps)]
    }
    only[n, none]
  }
  tags[none, none, none, none]
  keepMaps and keepWaits and Eth0In' = Eth0In
}

// The app and the sessions start shells, servers, anything: caps carry
// over through ambient
pred sessionFork {
  some s: principal.(AppP + SessionP), n: Process' - Process {
    born[n, SessionP, s, s.userns, s.mnt, s.net, s.pidns, s.uid, s.caps]
    only[n, none]
  }
  tags[none, none, none, none]
  keepMaps and keepWaits and On' = On and Eth0In' = Eth0In
}

// started by bwrap's init
pred fhsInit {
  U1.mapped = HostUser + SubIds and no U2.mapped
  On = RootFinal + NetDone and Eth0In = N
  no Blocked + Held + FhsChild + AppPidS
  some disj l, c, u, f: Process {
    Process = l + c + u + f
    hostProcess[l]
    c.principal = BwrapInitP and c.ppid = l and no c.caps
    u.principal = UdhcpcP and u.ppid = c and u.caps = NetAdmin + NetRaw
    f.principal = BwrapInitP and f.ppid = c and no f.caps
    all p: c + u + f | p.uid = HostUser and p.userns = U1 and p.mnt = M1 and p.net = N and p.pidns = P
    Root = c and Fhs = f
  }
}

pred fhs[g: set Guard, m: set Move] {
  fhsInit
  always (fhsShare or (LateShare in m and lateShare) or fhsCopy[g] or writeMap
    or mapFail[g] or unblock[g] or appPidStart or appStart[g] or sessionFork
    or udhcpcFork or skip)
}


// ---------------------------------------------------------------------
// Properties

// L1, fhs stage: U2's maps through the shims and subid-broker.
assert L1fhs { fhs[Guard, Move] implies l1 }
check L1fhs for 7 but 8 OwnedNS, 1..9 steps expect 0

// L1, fhs stage, revert: the same without KillOnMapFail.
assert L1fhsRevert { fhs[Guard - KillOnMapFail, Move] implies l1 }
check L1fhsRevert for 7 but 8 OwnedNS, 1..9 steps expect 1

// Vacuity: the fhs stage reaches the app with the grant directory shared
// into M2.
run fhsRuns {
  fhs[Guard, none]
  eventually (some principal.AppP and M2Slave in On)
} for 7 but 8 OwnedNS, 1..9 steps expect 1

// L4: the app and everything it starts hold no capability in U2, whether
// or not app-pid.sh's write to ns_last_pid succeeds. Holds.
pred l4 { always all p: principal.(AppP + SessionP) | no p.caps }
assert L4 { fhs[Guard, Move] implies l4 }
check L4 for 7 but 8 OwnedNS, 1..9 steps expect 0

// L4, revert: without DropCapsOnFail, as before the fix, a failed write
// left the ambient CAP_CHECKPOINT_RESTORE bwrap raised (default.nix:
// --cap-add) with the app and all it starts.
assert L4failRevert { fhs[Guard - DropCapsOnFail, Move] implies l4 }
check L4failRevert for 7 but 8 OwnedNS, 1..9 steps expect 1

// L4 when the write succeeds: setpriv drops the capability before the fork.
assert L4writeOk { (fhs[Guard, Move] and always LastPidFail not in On) implies l4 }
check L4writeOk for 7 but 8 OwnedNS, 1..9 steps expect 0

// L4, revert: without DropCapsBeforeFork the app keeps it either way.
assert L4revert { (fhs[Guard - DropCapsBeforeFork, Move] and always LastPidFail not in On) implies l4 }
check L4revert for 7 but 8 OwnedNS, 1..9 steps expect 1

// L9: once the broker takes type C requests (b.shared), M2's
// /run/permissions receives what it mounts in M1.
//
// Known: when the FHS env's own `share` failed (the launch goes on,
// bwrap-subid.sh:80-81), udhcpc can send `share` after the copy:
// shareFrom (broker.go:485) checks only that the client is in M1, and
// adoptShared (broker.go:500) would take the same state over after a
// restart. The broker then grants type C into M1, where nothing but bwrap's
// init and udhcpc sees it. Consent is still asked; the grant just never
// reaches the app. Low: the user sees a grant that does nothing.
pred l9 { always ((BrokerShared + M2Copied) in On implies M2Slave in On) }
assert L9 { fhs[Guard, Move] implies l9 }
check L9 for 7 but 8 OwnedNS, 1..9 steps expect 1

// L9 when only the FHS env's script sends `share`.
assert L9noLateShare { fhs[Guard, none] implies l9 }
check L9noLateShare for 7 but 8 OwnedNS, 1..9 steps expect 0

// L9, revert: without ShareBeforeCopy the script's own `share` can come
// after the copy.
assert L9revert { fhs[Guard - ShareBeforeCopy, none] implies l9 }
check L9revert for 7 but 8 OwnedNS, 1..9 steps expect 1
