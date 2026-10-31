/*
 * The process tree as the broker reads it from the host's /proc: the
 * session walk (P8) and the holders of a revoked folder (P5). A snapshot
 * (sandbox.als's `frozen`): the walks read /proc once, and pid reuse
 * during them is S13's.
 *
 * Sources: sandbox.go:148-178 (sessionOf), mounts.go:457-616 (grantMounts,
 * holdersAfter, descendants, isDescendant), broker.go:1006-1023
 * (endHolders), claude-desktop.sh:48-88 (re-entries through nsenter after
 * `env -i`).
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
  // after a type C grant's detach: cwd, open file or mapping on it, or a
  // mount of its filesystem and root in the process's mount namespace
  var holds: set Process,
  // processes holdersAfter didn't get to before its 10 s deadline
  var unscanned: set Process
}

fun sandboxProcs: set Process { principal.domain.Sandbox }
fun inside: set Process { Tree.top.^~ppid }

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
  }
  Tree.holds + Tree.unscanned in sandboxProcs
  // bwrap's init only reaps: no cwd, file or mount of a grant
  Tree.top not in Tree.holds
}

// sessionOf's walk from p: q is read when every process from p up to q,
// q excluded, lacked the variable and wasn't the sandbox's pid or pid 1,
// and q is neither (the loop condition, sandbox.go:149).
pred stopsAt[q: Process] { q = Tree.top or q = Tree.hostInit }
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
  a not in Tree.nsInit and a != Tree.top and a != Tree.hostInit and a in Tree.claudeExe
}

// P8. A session lease's anchor is a process inside the sandbox (below its
// pid), named `claude`, not a pid namespace's init and not the sandbox's
// pid, whatever variables the sandbox sets. Known, lead 2 confirmed:
// `claude-desktop --shell` joins the app's namespaces from the host
// (claude-desktop.sh:75), so the shell's parent is nsenter, a host
// process. The walk passes nsenter (`env -i`, no variable) and reads the
// host shell that ran claude-desktop; started from a host Claude Code
// session's Bash tool, that shell has CLAUDE_CODE_SESSION_ID, and its
// parent is the host's `claude`. A permissions request from the --shell
// (or anything it starts that unsets the variable) gets a session lease
// anchored at the host process. The stop at the sandbox's pid never
// comes: a re-entry's ancestry doesn't pass it. Bounded by P11.
assert P8anchorInside {
  always all p: sandboxProcs, a: anchorOf[p] | a in inside and a.principal.domain = Sandbox
}
check P8anchorInside for 7 but 0 Mount, 0 File, 0 Socket, 2 UserNS, 4 OwnedNS, 1 steps expect 1

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

// What holdersAfter lists (mounts.go:482-508): the sandbox pid's
// descendants it reached that hold the grant. endHolders ends only
// descendants too (isDescendant, mounts.go:604-616).
fun listed: set Process { (inside - Tree.unscanned) & Tree.holds }

// P5. After a type C grant ends, every sandbox process that still holds
// it is listed. Known, lead 1 confirmed: a --shell process (and what it
// starts) has nsenter as parent, so descendants() never reaches it: a cwd
// on the grant or a re-bind in a mount namespace of its own isn't listed
// (grantMounts doesn't read its namespace either), and the window can't
// end it (isDescendant refuses).
assert P5holdersListed {
  always no Tree.unscanned implies Tree.holds in listed
}
check P5holdersListed for 6 but 0 Mount, 0 File, 0 Socket, 2 UserNS, 3 OwnedNS, 1 steps expect 1

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
// every end (unmountC, mounts.go:721-736), but only revoke's answer
// carries the holders (broker.go:1002-1003), and the window shows only
// those (window.go:90-95). Other ends log them to the journal.
abstract sig Cause {}
one sig Revoked, ReleasedInside, LeaseRanOut extends Cause {}
one sig End { var cause: one Cause }
fun shownToUser: set Process { End.cause = Revoked implies listed else none }

// P5 as the user sees it. Known, a finding: the sandbox releases its own
// folder grant (or lets the lease run out) while a process of its keeps a
// cwd or a re-bind in a nested mount namespace on it; the window then
// shows no grant and no holder, and the folder stays reachable. With
// the holders shown on every end (shownToUser = listed), the claim holds.
assert P5holdersShown {
  always (all p: sandboxProcs - Tree.top | p in inside) and no Tree.unscanned implies Tree.holds in shownToUser
}
check P5holdersShown for 6 but 0 Mount, 0 File, 0 Socket, 2 UserNS, 3 OwnedNS, 1 steps expect 1

run P5holders {
  some listed
} for 6 but 0 Mount, 0 File, 0 Socket, 2 UserNS, 3 OwnedNS, 1 steps expect 1
