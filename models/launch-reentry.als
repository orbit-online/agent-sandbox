/*
 * Step 4, the running sandbox from the host's side (README.md, L5-L7):
 * how the launcher (cmd/launcher enter.go) finds the sandbox and the app to re-enter
 * (sandbox_pid, app_pid, then nsenter by pid), what `--permissions` does
 * instead, and the broker's handle on the sandbox (sandbox.go:39
 * lookupSandbox). The launch itself is in launch.als.
 *
 * The state starts with the sandbox running: the outer bwrap's child
 * (Root, pid 1 in P), the FHS env's init (pid 1 in P2), setsid, the app at
 * APP_PID in P2, and udhcpc. The attacker adds processes; the host's
 * launcher and broker look them up. Pids are the host's (base), and a
 * dead process's pid can come back on any new one.
 */
module launch_reentry

open sandbox

// HIDE: File Mount MountFlag Socket PeerCheck IpcNS UtsNS CgroupNS Guard Move Mode

one sig U1, U2, U3, UB extends UserNS {}
one sig HostMnt, M1, M2, M3, MB extends MountNS {}
one sig HostNet, N extends NetNS {}
one sig P, P2, P3, PB extends PidNS {}
one sig SubIds extends Id {}
fact reentryShape {
  UserNS = InitUserNS + U1 + U2 + U3 + UB
  MountNS = HostMnt + M1 + M2 + M3 + MB
  NetNS = HostNet + N
  PidNS = InitPidNS + P + P2 + P3 + PB
  no IpcNS + UtsNS + CgroupNS
  no Mount + File + Socket
  Id = HostUser + HostRoot + Overflow + SubIds
  // U3: one the attacker made below U2 (unshare -Urp). UB: another
  // launcher's sandbox (README.md, B3)
  U1.parent = InitUserNS and U2.parent = U1 and U3.parent = U2 and UB.parent = InitUserNS
  (U1 + U2 + U3 + UB).owner = HostUser
  (HostMnt + HostNet).ownedBy = InitUserNS
  (M1 + N + P).ownedBy = U1
  (M2 + P2).ownedBy = U2
  (M3 + P3).ownedBy = U3
  (MB + PB).ownedBy = UB
  P.pparent = InitPidNS and P2.pparent = P and P3.pparent = P2 and PB.pparent = InitPidNS
  // Every map is written by now; U3 maps the user's own id (as 0, so a
  // process of the user's id there keeps capabilities through exec)
  always (U1 + U2 + UB).mapped = HostUser + SubIds
  always U3.mapped = HostUser
}

abstract sig Mode {}
// claude:// (the branch at enter.go:41-48), --shell (:38), --permissions (:28)
one sig Url, Shell, Perms extends Mode {}
one sig Cfg {
  mode: one Mode,
  // child-pids of instance dirs whose launcher died without its deferred
  // Cleanup (nixpak launcher/main.go:100; Go skips defers on SIGTERM and
  // SIGKILL)
  stale: set Pid
}

abstract sig Guard {}
one sig
  AppLevel,         // internal/sandbox find.go:99, AppPid: the match's pid ns is one below the sandbox's, and it's the only one
  NnpOnEntry,       // enter.go:111: setpriv --no-new-privs on the host, ahead of nsenter, for both modes
  PermissionsFirst, // enter.go:28-37, ahead of sandbox.Find
  MntCheck          // internal/sandbox find.go:35: not in our mount ns, for the broker and the launcher
  extends Guard {}

abstract sig Move {}
one sig
  NestPid,      // a process in a pid ns of its own below P2, at APP_PID there
  SpawnInP,     // udhcpc's child in P, at any pid there, APP_PID included
  AppExit,      // the app exits
  HostReuse,    // a host process takes a free pid
  OtherSandbox, // another launcher's sandbox process takes a free pid
  SandboxEnds   // the outer bwrap's child exits, and P with it
  extends Move {}

var sig Root, AtApp, Reentry, NoNewPrivs, Handle in Process {}
// Instance dirs naming a live run's child-pid, until the launcher cleans up
var sig LiveDir in Pid {}
one sig L { var looked: lone Pid }

fun launcher: set Process { principal.LauncherP }
fun dirs: set Pid { LiveDir + Cfg.stale }

// ---------------------------------------------------------------------
// Frames

pred same[p: Process] {
  p in Process'
  p.pid' = p.pid and p.ppid' = p.ppid and p.uid' = p.uid and p.caps' = p.caps
  p.userns' = p.userns and p.mnt' = p.mnt and p.net' = p.net and p.pidns' = p.pidns
}

pred born[n: Process, pr: Principal, par: lone Process, u: UserNS, m: MountNS,
    nt: NetNS, pn: PidNS, cs: set Cap] {
  n not in Process
  n.principal' = pr and n.ppid' = par and n.uid' = HostUser and n.caps' = cs
  n.userns' = u and n.mnt' = m and n.net' = nt and n.pidns' = pn
}

// Processes: b join, d leave (with no children left behind), the rest stay
pred only[b, d: set Process] {
  Process' = Process - d + b
  all p: Process - d | same[p]
}

// Tags keep their live members; b joins at most AtApp (ab), Reentry (rb),
// NoNewPrivs (nb), Handle (hb)
pred tags[ab, rb, nb, hb: set Process] {
  Root' = Root & Process'
  AtApp' = (AtApp & Process') + ab
  Reentry' = (Reentry & Process') + rb
  NoNewPrivs' = (NoNewPrivs & Process') + nb
  Handle' = (Handle & Process') + hb
}

pred quiet { LiveDir' = LiveDir and L.looked' = L.looked }

pred skip { only[none, none] and tags[none, none, none, none] and quiet }

// ---------------------------------------------------------------------
// Attacker and environment

// Tested inside the sandbox (2026-10-31): a process unshares a user and
// pid namespace, forks the new namespace's init and then until a child
// is at APP_PID there, and exits. The child is reparented to the FHS
// env's init, one level above the app.
pred nest[m: set Move] {
  NestPid in m
  some i: principal.BwrapInitP & pidns.P2, q: Process' - Process {
    i.ppid in Root  // P2's init
    born[q, NestedP, i, U3, M3, N, P3, Cap]
    only[q, none]
    tags[q, none, none, none] or tags[none, none, none, none]
  }
  quiet
}

pred spawnInP[m: set Move] {
  SpawnInP in m
  some u: principal.UdhcpcP, q: Process' - Process {
    born[q, UdhcpcP, u, U1, M1, N, P, NetAdmin + NetRaw]
    only[q, none]
    tags[q, none, none, none] or tags[none, none, none, none]
  }
  quiet
}

pred appExit[m: set Move] {
  AppExit in m
  some a: principal.AppP | no ppid.a and only[none, a]
  tags[none, none, none, none] and quiet
}

pred hostSpawn[m: set Move] {
  HostReuse in m
  some h: Process' - Process {
    born[h, HostUserP, none, InitUserNS, HostMnt, HostNet, InitPidNS, none]
    only[h, none]
  }
  tags[none, none, none, none] and quiet
}

pred otherSpawn[m: set Move] {
  OtherSandbox in m
  some o: Process' - Process {
    born[o, BwrapInitP, none, UB, MB, HostNet, PB, none]
    only[o, none]
  }
  tags[none, none, none, none] and quiet
}

// The outer bwrap's child exits; the kernel kills P and everything below
pred sandboxEnds[m: set Move] {
  SandboxEnds in m
  some Root
  only[none, pidns.(P.*~pparent)]
  tags[none, none, none, none] and quiet
}

// nixpak's deferred Cleanup removes the instance dir
pred cleanup {
  no Root and some LiveDir
  LiveDir' = none and L.looked' = L.looked
  only[none, none] and tags[none, none, none, none]
}

// ---------------------------------------------------------------------
// The host's lookups

// The old app_pid's breadth-first walk: the first match is one at the
// least depth
fun depth[top, p: Process]: Int { #(p.^ppid & top.*~ppid) }

// sandbox_pid then app_pid. Without a match the launcher sleeps and tries
// again, which skip covers; with two at the app's level it gives up
pred lookup[g: set Guard] {
  Cfg.mode != Perms or PermissionsFirst not in g
  no L.looked and no Reentry
  some x: pid.dirs & Process, c: AppTarget[g, x] {
    MntCheck in g implies x.mnt != HostMnt
    AppLevel in g implies one AppTarget[g, x]
    else no c2: AppTarget[g, x] | depth[x, c2] < depth[x, c]
    L.looked' = c.pid
  }
  LiveDir' = LiveDir
  only[none, none] and tags[none, none, none, none]
}

fun AppTarget[g: set Guard, x: Process]: set Process {
  { c: x.*~ppid & AtApp | AppLevel in g implies c.pidns.pparent = x.pidns }
}

// nsenter -U -m -p -n -i -u -C -r -w -t <pid>, by the pid found before.
// Joining a user namespace gives every capability in it; the exec keeps
// them only where the user's id is 0 (U3, which the attacker mapped)
pred enter[g: set Guard] {
  some L.looked and no Reentry
  some t: pid.(L.looked) & Process, e: Process' - Process {
    born[e, ReentryP, launcher, t.userns, t.mnt, t.net, t.pidns, e.caps']
    t.userns != U3 implies no e.caps'
    only[e, none]
    tags[none, e, (NnpOnEntry in g) implies e else none, none]
  }
  quiet
}

// --permissions: exec the window, on the host, before any lookup
pred permissions[g: set Guard] {
  Cfg.mode = Perms and PermissionsFirst in g
  no principal.WindowP
  some w: Process' - Process {
    born[w, WindowP, none, InitUserNS, HostMnt, HostNet, InitPidNS, none]
    only[w, none]
  }
  tags[none, none, none, none] and quiet
}

// lookupSandbox: an instance dir's child-pid, pidfd_open, read again, the
// mount ns checked after the pidfd is taken
pred brokerLookup[g: set Guard] {
  no Handle
  some x: pid.dirs & Process {
    MntCheck in g implies x.mnt != HostMnt
    only[none, none] and tags[none, none, none, x]
  }
  quiet
}

// ---------------------------------------------------------------------
// The system

pred init {
  no L.looked and no Reentry + NoNewPrivs + Handle
  some disj l, r, i, s, a, u: Process {
    Process = l + r + i + s + a + u
    l.principal = LauncherP and no l.ppid and no l.caps
    l.userns = InitUserNS and l.mnt = HostMnt and l.net = HostNet and l.pidns = InitPidNS
    r.principal = BwrapInitP and no r.ppid and no r.caps
    r.userns = U1 and r.mnt = M1 and r.net = N and r.pidns = P
    u.principal = UdhcpcP and u.ppid = r and u.caps = NetAdmin + NetRaw
    u.userns = U1 and u.mnt = M1 and u.net = N and u.pidns = P
    i.principal = BwrapInitP and i.ppid = r
    s.principal = BwrapInitP and s.ppid = i
    a.principal = AppP and a.ppid = s
    all p: i + s + a | no p.caps and p.userns = U2 and p.mnt = M2 and p.net = N and p.pidns = P2
    Process.uid = HostUser
    Root = r and AtApp = a and LiveDir = r.pid
  }
}

pred system[g: set Guard, m: set Move] {
  init
  always (nest[m] or spawnInP[m] or appExit[m] or hostSpawn[m] or otherSpawn[m]
    or sandboxEnds[m] or cleanup or lookup[g] or enter[g] or permissions[g]
    or brokerLookup[g] or skip)
}

// ---------------------------------------------------------------------
// L5: a re-entry joins the app's U2, M2, P2 and N, holds no capability
// after its exec, and runs with no_new_privs, claude:// and --shell alike:
// it execs paths in M2, where the sandbox can put a binary with file
// capabilities whose root id is U2's root (a user namespace it maps root
// to U2's 0 through subid-broker), and nsenter holds every capability in
// U2 until that exec.
pred l5 {
  always all e: Reentry {
    e.userns = U2 and e.mnt = M2 and e.pidns = P2 and e.net = N and no e.caps
    e in NoNewPrivs
  }
}

// L5, with a process at APP_PID in a pid ns of the attacker's below P2
// (see nest) and udhcpc's children at any pid in P: app_pid takes only a
// process whose NSpid has one entry more than the sandbox's pid 1, so in a
// pid ns right below P, and none if two qualify. Holds without stale
// instance dirs: with one, sandbox_pid can name another process (L7), the
// FHS env's init for one, and app_pid then looks below that.
assert L5 { (system[Guard, NestPid + SpawnInP] and no Cfg.stale) implies l5 }
check L5 for 8 but 13 OwnedNS, 1..6 steps expect 0

// L5, revert: the old app_pid took the first process breadth-first whose
// last NSpid is APP_PID outside P. The app is at depth 4 below the outer
// child, the attacker's process at depth 3 (confirmed live), and the
// re-entry joined the attacker's user, mount and pid namespaces: a
// claude:// URL or the user's --shell terminal landed there instead of
// the app's.
assert L5nestRevert { system[Guard - AppLevel, NestPid] implies l5 }
check L5nestRevert for 8 but 13 OwnedNS, 1..6 steps expect 1

// L5 without nested pid namespaces. Known: the launcher names the app by
// pid, and nsenter -t uses that number later. If the app exits in
// between and its host pid comes back on a host process, or on udhcpc's
// child in U1, the re-entry joins that. The attacker can't see host pids,
// and the window is the launcher's few exec's, so this needs luck.
assert L5noNest { system[Guard, SpawnInP + AppExit + HostReuse] implies l5 }
check L5noNest for 8 but 13 OwnedNS, 1..6 steps expect 1

// L5 when the app stays and the attacker has no pid ns of its own: the
// match outside P is the app.
assert L5stable { system[Guard, SpawnInP] implies l5 }
check L5stable for 8 but 13 OwnedNS, 1..6 steps expect 0

// L5, revert: without AppLevel udhcpc's child at APP_PID in P is a
// match, at depth 2, and the re-entry joins U1 and M1.
assert L5stableRevert { system[Guard - AppLevel, SpawnInP] implies l5 }
check L5stableRevert for 8 but 13 OwnedNS, 1..6 steps expect 1

// L5, revert: without NnpOnEntry a re-entry runs without no_new_privs.
assert L5nnpRevert { system[Guard - NnpOnEntry, SpawnInP] implies l5 }

// L5, revert for --shell, which ran without no_new_privs before: a
// --shell re-entry without NnpOnEntry.
assert L5nnpShellRevert {
  (system[Guard - NnpOnEntry, SpawnInP] and Cfg.mode = Shell) implies l5
}
check L5nnpShellRevert for 8 but 13 OwnedNS, 1..6 steps expect 1
check L5nnpRevert for 8 but 13 OwnedNS, 1..6 steps expect 1

// Vacuity: a claude:// re-entry happens.
run reentryRuns {
  system[Guard, SpawnInP] and Cfg.mode = Url and eventually some Reentry
} for 8 but 13 OwnedNS, 1..6 steps expect 1

// L6: --permissions never enters the sandbox: its only process is the
// window, on the host (enter.go:28-37).
pred l6 {
  Cfg.mode = Perms implies always no Reentry
  always all w: principal.WindowP | w.userns = InitUserNS and w.mnt = HostMnt and w.pidns = InitPidNS
}
assert L6 { system[Guard, Move - NestPid] implies l6 }
check L6 for 8 but 13 OwnedNS, 1..6 steps expect 0

// L6, revert: with the check after sandbox_pid the flag takes the
// claude:// branch into the app.
assert L6revert { system[Guard - PermissionsFirst, none] implies l6 }
check L6revert for 8 but 13 OwnedNS, 1..6 steps expect 1

// Vacuity: the window opens.
run permissionsRuns {
  system[Guard, none] and Cfg.mode = Perms and eventually some principal.WindowP
} for 8 but 13 OwnedNS, 1..6 steps expect 1

// L7: the broker's handle is the outer bwrap's child.
pred l7 { always Handle in Root }

// L7. Known: a stale instance dir (its launcher killed, or the sandbox
// ended and nixpak's Cleanup not yet run) names a pid that a process
// outside the host's mount ns can hold: one in a pid ns of the sandbox's
// own, or another launcher's sandbox. lookupSandbox takes the first dir in
// glob order whose pid passes, so a broker started or restarted then
// serves that process: `share` and attach go into its mount ns, and its
// exit ends the broker. Not tried: needs a stale dir and the pid.
assert L7 { system[Guard, NestPid + OtherSandbox + HostReuse + SandboxEnds] implies l7 }
check L7 for 8 but 13 OwnedNS, 1..6 steps expect 1

// L7 without stale dirs: the live dir names the outer child until it
// exits, and nothing looks after that.
assert L7noStale {
  (system[Guard, NestPid + OtherSandbox + HostReuse + AppExit] and no Cfg.stale) implies l7
}
check L7noStale for 8 but 13 OwnedNS, 1..6 steps expect 0

// L7 when a stale dir's pid can come back only on a host process (no
// process holds it at first, and no re-entry starts): the mount ns check
// turns it away.
assert L7hostOnly {
  (system[Guard, HostReuse + AppExit] and no Cfg.stale & Process.pid and Cfg.mode = Perms) implies l7
}
check L7hostOnly for 8 but 13 OwnedNS, 1..6 steps expect 0

// L7, revert: without MntCheck that host process becomes the handle.
assert L7hostOnlyRevert {
  (system[Guard - MntCheck, HostReuse + AppExit] and no Cfg.stale & Process.pid and Cfg.mode = Perms) implies l7
}
check L7hostOnlyRevert for 8 but 13 OwnedNS, 1..6 steps expect 1

// Vacuity: the broker finds the sandbox, with a stale dir around.
run brokerRuns {
  system[Guard, HostReuse] and some Cfg.stale and eventually some Handle
} for 8 but 13 OwnedNS, 1..6 steps expect 1
