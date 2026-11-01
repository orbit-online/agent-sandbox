/*
 * The process tree as the broker reads it from the host's /proc: the
 * session walk (P8) and the holders of a revoked folder (P5). A snapshot
 * (sandbox.als's `frozen`): the walks read /proc once, and pid reuse
 * during them is S13's.
 *
 * Sources: session.go (sessionOf), members.go (contains, members: the
 * sandbox's processes by user namespace), mountinfo.go (grantMounts,
 * holdersAfter), leases.go (endHolders), claude-desktop.sh:48-88
 * (re-entries through nsenter after `env -i`).
 */
open sandbox

// HIDE: Id Cap UserNS OwnedNS MountNS NetNS IpcNS UtsNS CgroupNS PidNS Pid File MountFlag Mount PeerCheck Socket

one sig Tree {
  // the sandbox's pid (bwrapinfo.json's child-pid) and the host's pid 1
  var top: one Process,
  var hostInit: one Process,
  // CLAUDE_CODE_SESSION_ID in /proc/<pid>/environ
  var hasVar: set Process,
  // /proc/<pid>/exe's name is `claude`
  var claudeExe: set Process,
  // the init of its own pid namespace (innermost NSpid 1)
  var nsInit: set Process,
  // after an attach grant's detach: cwd, open file or mapping on it, or a
  // mount of its filesystem and root in the process's mount namespace
  var holds: set Process,
  // processes holdersAfter didn't get to before its 10 s deadline
  var unscanned: set Process
}

fun sandboxProcs: set Process { principal.domain.Sandbox }
// The sandbox's processes as the broker finds them (members.go): those
// whose user namespace is the sandbox pid's or below it, re-entries
// included, whoever their parent is.
fun inside: set Process { userns.(Tree.top.userns.*~parent) }

fact shape {
  frozen
  always { cause' = cause and top' = top and hostInit' = hostInit and hasVar' = hasVar and claudeExe' = claudeExe
    and nsInit' = nsInit and holds' = holds and unscanned' = unscanned }
  no p: Process | p in p.^ppid
  let t = Tree.top, h = Tree.hostInit {
    t.principal = BwrapInitP and t.ppid.principal.domain = Host and t in Tree.nsInit
    h.principal.domain = Host and no h.ppid and h.pidns = InitPidNS and h in Tree.nsInit
    all p: Process - h | some p.ppid
    // host processes descend from host processes
    all p: Process | p.principal.domain = Host implies p.ppid.principal.domain in Host
    // a sandbox process is below the sandbox's pid, or a re-entry: its
    // parent is the launcher's nsenter on the host
    all p: sandboxProcs - t | p in inside or p.ppid.principal = LauncherP
    // the launcher's processes (bash, env, nsenter) and what nsenter
    // starts run under `env -i` with the filtered variables only
    // (claude-desktop.sh:48, 75, 88, 123)
    no Tree.hasVar & (principal.LauncherP + ppid.(principal.LauncherP))
    no Tree.claudeExe & principal.LauncherP
    // the sandbox's processes are in U1 or below (a re-entry joins U2),
    // the host's in none of them
    t.userns != InitUserNS
    sandboxProcs in inside
    no principal.domain.Host & inside
  }
  Tree.holds + Tree.unscanned in sandboxProcs
  // bwrap's init only reaps: no cwd, file or mount of a grant
  Tree.top not in Tree.holds
}

// sessionOf's walk from p: q is read when every process from p up to q,
// q excluded, lacked the variable and wasn't the sandbox's pid, pid 1 or
// outside the sandbox, and q is none of them (the loop condition,
// session.go).
pred stopsAt[q: Process] { q = Tree.top or q = Tree.hostInit or q not in inside }
pred reads[p, q: Process] {
  q in p.*ppid and not stopsAt[q]
  all r: p.*ppid - q | q in r.^ppid implies (r not in Tree.hasVar and not stopsAt[r])
}
// The anchor: the parent of the first process read with the variable, if
// it isn't a pid namespace's init, the sandbox's pid or pid 1, and runs
// `claude` (sandbox.go:159-164).
fun anchorOf[p: Process]: set Process {
  { a: Process | some q: Process | reads[p, q] and q in Tree.hasVar and a = q.ppid and anchorOK[a] }
}
pred anchorOK[a: Process] {
  a not in Tree.nsInit and a != Tree.top and a != Tree.hostInit and a in Tree.claudeExe and a in inside
}

// P8. A session lease's anchor is a process inside the sandbox, named
// `claude`, not a pid namespace's init and not the sandbox's pid,
// whatever variables the sandbox sets. `claude-desktop --shell` joins the
// app's namespaces from the host (claude-desktop.sh:75), so the shell's
// parent is nsenter, a host process, and above it may be a host Claude
// Code session's shell with CLAUDE_CODE_SESSION_ID. The walk stops at the
// first process outside the sandbox's user namespaces and the anchor must
// be inside (session.go). Holds. Revert: stopsAt and anchorOK without
// their `inside` (as before the fix): the walk reads the host shell and
// anchors at the host's claude (counterexample found).
assert P8anchorInside {
  always all p: sandboxProcs, a: anchorOf[p] | a in inside and a.principal.domain = Sandbox
}
check P8anchorInside for 7 but 0 Mount, 0 File, 0 Socket, 2 UserNS, 4 OwnedNS, 1 steps expect 0

// P8 without re-entries: for a process below the sandbox's pid the walk
// never leaves the sandbox, whatever the sandbox sets.
// Revert: stopsAt without the sandbox's pid: the walk climbs past it into
// the launcher's host shell.
assert P8anchorInsideNoReentry {
  always (all p: sandboxProcs - Tree.top | p in inside) implies
    (all p: sandboxProcs, a: anchorOf[p] | a in inside and a not in Tree.nsInit and a in Tree.claudeExe)
}
check P8anchorInsideNoReentry for 7 but 0 Mount, 0 File, 0 Socket, 2 UserNS, 4 OwnedNS, 1 steps expect 0
// P8's premise: a forged session inside, anchored at a binary the sandbox
// named `claude`.
run P8forgedInside {
  some p: sandboxProcs | some anchorOf[p] & inside
} for 7 but 0 Mount, 0 File, 0 Socket, 2 UserNS, 4 OwnedNS, 1 steps expect 1

// What holdersAfter lists (mountinfo.go): the sandbox's processes it
// reached that hold the grant. endHolders ends only the sandbox's too
// (contains, members.go).
fun listed: set Process { (inside - Tree.unscanned) & Tree.holds }

// P5. After an attach grant ends, every sandbox process that still holds
// it is listed. The broker finds the sandbox's processes by user
// namespace (members.go), so a --shell process (and what it starts),
// whose parent is nsenter on the host, is among them. Tree.holds is
// holding as /proc shows it, on any thread (cwd, root, fds and mount
// namespace per task, mountinfo.go): an fd queued in an SCM_RIGHTS
// message or registered with io_uring holds the grant too and shows
// nowhere, so P5 is best effort, outside this model; only the sandbox's
// end ends those (docs/permissions.md). Holds. Revert:
// `inside` as the sandbox pid's descendants (as before the fix): a cwd on
// the grant or a re-bind in a re-entry's own mount namespace isn't
// listed (counterexample found).
assert P5holdersListed {
  always no Tree.unscanned implies Tree.holds in listed
}
check P5holdersListed for 6 but 0 Mount, 0 File, 0 Socket, 2 UserNS, 3 OwnedNS, 1 steps expect 0

// P5 for processes below the sandbox's pid. Known, a finding: the scan
// stops after 10 s (holdersTimeout, mounts.go:483-490) and the sandbox
// decides how many processes and open files it walks through, breadth
// first from the sandbox's pid, so a holder placed after enough decoys
// isn't listed.
// With `no Tree.unscanned` assumed, the claim holds.
assert P5holdersListedInside {
  always Tree.holds in inside implies Tree.holds in listed
}
check P5holdersListedInside for 6 but 0 Mount, 0 File, 0 Socket, 2 UserNS, 3 OwnedNS, 1 steps expect 1
// How the grant ended, and what reaches the user: holdersAfter runs on
// every end (detachGrant, attach.go), and the daemon keeps them for the
// window's state however the grant ended (recordHeld, holders.go).
abstract sig Cause {}
one sig Revoked, ReleasedInside, LeaseRanOut extends Cause {}
one sig End { var cause: one Cause }
fun shownToUser: set Process { listed }

// P5 as the user sees it: the sandbox releases its own folder grant (or
// lets the lease run out) while a process of its keeps a cwd or a
// re-bind in a nested mount namespace on it; the window shows the
// holders all the same. Holds. Revert: shownToUser only for Revoked (as
// before the fix, when only revoke's answer carried them): the window
// shows no holder and the folder stays reachable (counterexample found).
assert P5holdersShown {
  always (all p: sandboxProcs - Tree.top | p in inside) and no Tree.unscanned implies Tree.holds in shownToUser
}
check P5holdersShown for 6 but 0 Mount, 0 File, 0 Socket, 2 UserNS, 3 OwnedNS, 1 steps expect 0

run P5holders {
  some listed
} for 6 but 0 Mount, 0 File, 0 Socket, 2 UserNS, 3 OwnedNS, 1 steps expect 1
