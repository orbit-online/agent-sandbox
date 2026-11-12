/*
 * A journald namespace per launcher, as of f44e791 (README.md, Crossings,
 * S15); the fix below is not built. The host enables systemd-journald@claude-desktop; the
 * sandbox gets its `socket`, `stdout` and `dev-log` at
 * /run/systemd/journal/socket, /run/systemd/journal/stdout and /dev/log,
 * and its storage read-only. The host helpers (supervise and
 * the D-Bus proxy in supervisor/, the permissions broker's and
 * subid-broker's units, through systemd-cat: internal/journal) log into
 * the same namespace, udhcpc too (helper.go, identifier udhcpc).
 *
 * journald (systemd 260.5, src/journal) stamps the trusted fields of an
 * entry from the sender's credentials and from /proc/<pid> of the pid in
 * them, by pid: journald-context.c:280-326 reads the cgroup with
 * cg_pid_get_path_shifted(c->pid), and there's no pidfd in journald-*.c.
 * A stream's line is stamped when it's flushed, with the pid of the last
 * write's SCM_CREDENTIALS (journald-stream.c:579-600, 231-233), at EOF
 * too: a sandbox process writes a line without its newline and exits, a
 * second one keeps the stream open for as long as it likes and then
 * closes it. Fields a client sends with a leading `_` are dropped
 * (journald-native.c:158,226: journal_field_valid without protected
 * fields), a stream's unit id and OBJECT_PID are taken only from uid 0
 * (journald-stream.c:352, journald-native.c:35-37), and SCM_CREDENTIALS
 * names only a process in the sender's own pid namespace (the kernel's
 * scm_check_creds), so the attacker's entries can name only its own
 * processes, and only through pid reuse a host one. A sandbox process
 * can't leave sandbox/ (its cgroup namespace and the delegation's
 * containment rule). udhcpc runs in the dhcp unit (helper.go:159), a
 * cgroup outside sandbox/, and counts as the attacker's (README.md,
 * Principals 12).
 *
 * The host's other processes (the desktop's) and pid wrap-around's
 * timing are left out: the attacker can count through pid_max (4194304)
 * by forking, learn where the host's pids are from the entries it reads
 * (_PID is the host's), and ask subid-broker for a map, which forks an
 * nsenter in its unit (subid-broker main.go:245) on the pid it lined up.
 */
module journal

abstract sig Cgroup {}
one sig
  Supervisor,  // <app unit>/supervisor: supervise, nixpak's launcher, bwrap's parent half (helper.go:90), the D-Bus proxy
  PermUnit,    // claude-desktop[-<name>]-permissions.service
  SubidUnit,   // claude-desktop[-<name>]-subid.service
  DhcpUnit,    // claude-desktop[-<name>]-dhcp.service, udhcpc's
  SandboxApp,  // <app unit>/sandbox/app (helper.go:90, enter.go:120)
  SandboxUser  // <app unit>/sandbox/user: the planned systemd --user manager's
  extends Cgroup {}
fun helperCgs: set Cgroup { Supervisor + PermUnit + SubidUnit }
fun attackerCgs: set Cgroup { DhcpUnit + SandboxApp + SandboxUser }

// Journal namespaces: the one bound into the sandbox, and one it can't
// reach (the host's default, or a second one, not bound)
abstract sig NS {}
one sig SbxNS, HostNS extends NS {}

abstract sig Side {}
one sig Host, Attacker extends Side {}

sig Pid {}
sig Proc { cg: one Cgroup, var pid: lone Pid }
fun side[p: Proc]: Side { p.cg in attackerCgs implies Attacker else Host }
var sig Live, Born in Proc {}

// An entry: who wrote it, the SYSLOG_IDENTIFIER or COMPONENT it claims
// (any, for the attacker), the pid in its credentials, the namespace whose
// socket it came in on, and the cgroup journald stamped
sig Msg {
  ident: one Side,
  var author: lone Proc,
  var mpid: lone Pid,
  var mns: lone NS,
  var mcg: lone Cgroup
}
var sig Sent, Stamped in Msg {}

// How a reader tells host-side entries from the sandbox's
abstract sig Reader {}
one sig
  ByIdent,    // SYSLOG_IDENTIFIER or COMPONENT
  NotSandbox, // _SYSTEMD_CGROUP not under sandbox/ (a missing one too)
  ByCgroup,   // _SYSTEMD_CGROUP present and one of the helpers' (the plan)
  ByNs        // _NAMESPACE (journald-manager.c:2216) is the helpers' own
  extends Reader {}

abstract sig Guard {}
one sig
  HelpersApart, // the fix: the helpers' units log into HostNS (LogNamespace=)
  DhcpInSbx,    // the fix: the dhcp unit logs into SbxNS, being the attacker's
  OnlySbxBound  // only SbxNS's sockets are bound into the sandbox
  extends Guard {}

fun nsOf[g: set Guard, p: Proc]: set NS {
  p.cg in SandboxApp + SandboxUser implies (OnlySbxBound in g implies SbxNS else NS)
  else p.cg = DhcpUnit implies ((HelpersApart in g and DhcpInSbx not in g) implies HostNS else SbxNS)
  else (HelpersApart in g implies HostNS else SbxNS)
}

pred hostSide[r: Reader, m: Msg] {
  r = ByIdent implies m.ident = Host
  else r = NotSandbox implies m.mcg not in SandboxApp + SandboxUser
  else r = ByCgroup implies (some m.mcg and m.mcg in helperCgs)
  else m.mns = HostNS
}

pred keepProcs { Live' = Live and Born' = Born and pid' = pid }
pred keepMsgs { Sent' = Sent and Stamped' = Stamped and author' = author and mpid' = mpid and mns' = mns and mcg' = mcg }

// A process starts on a free pid, a reused one included
pred spawn {
  some p: Proc - Born, x: Pid - Live.pid {
    Live' = Live + p and Born' = Born + p and pid' = pid ++ p -> x
  }
  keepMsgs
}
pred exit { some p: Live | Live' = Live - p and Born' = Born and pid' = pid and keepMsgs }
pred send[g: set Guard] {
  some p: Live, m: Msg - Sent, n: nsOf[g, p] {
    side[p] = Host implies m.ident = Host
    Sent' = Sent + m and author' = author + m -> p and mpid' = mpid + m -> p.pid and mns' = mns + m -> n
  }
  Stamped' = Stamped and mcg' = mcg and keepProcs
}
// journald stamps it: the cgroup of whatever runs at the pid now
pred stamp {
  some m: Sent - Stamped {
    Stamped' = Stamped + m and mcg' = mcg + m -> (Live & pid.(m.mpid)).cg
  }
  Sent' = Sent and author' = author and mpid' = mpid and mns' = mns and keepProcs
}
pred stay { keepProcs and keepMsgs }

pred sys[g: set Guard] {
  no Live + Born and no pid and no Sent + Stamped and no author and no mpid and no mns and no mcg
  always (spawn or exit or send[g] or stamp or stay)
}
pred noReuse { always all disj p, q: Born | p.pid != q.pid }

// S15: no entry the reader counts as host-side was written by the attacker.
pred s15[r: Reader] { always all m: Stamped | hostSide[r, m] implies side[m.author] = Host }

// S15, known finding in the plan: a sandbox process writes a line to the
// stdout socket and exits before journald flushes it; the pid goes to a
// helper (subid-broker's nsenter, which a map request starts), and the
// flush stamps the helper's cgroup, unit, comm and exe.
assert S15plan { sys[OnlySbxBound] implies s15[ByCgroup] }
check S15plan for 4 but 1..8 steps expect 1

// S15 in the plan without pid reuse. Holds: the attacker's own cgroups,
// or none once its process is gone.
assert S15noReuse { (sys[OnlySbxBound] and noReuse) implies s15[ByCgroup] }
check S15noReuse for 4 but 1..8 steps expect 0

// S15, revert: a reader of everything outside sandbox/ takes udhcpc's
// entries (the dhcp unit), and those whose sender was gone (no cgroup).
assert S15notSandboxRevert { (sys[OnlySbxBound] and noReuse) implies s15[NotSandbox] }
check S15notSandboxRevert for 4 but 1..8 steps expect 1

// S15, revert: a reader by SYSLOG_IDENTIFIER or COMPONENT takes whatever
// the sandbox claims.
assert S15identRevert { (sys[OnlySbxBound] and noReuse) implies s15[ByIdent] }
check S15identRevert for 4 but 1..8 steps expect 1

// S15 with the fix: the helpers in a namespace of their own, read by
// _NAMESPACE, which is the receiving instance's, so pid reuse changes
// nothing. Holds.
pred fixed { sys[HelpersApart + DhcpInSbx + OnlySbxBound] }
assert S15 { fixed implies s15[ByNs] }
check S15 for 4 but 1..8 steps expect 0

// S15 fix, revert: the dhcp unit logs with the helpers, and udhcpc
// writes into their namespace.
assert S15dhcpRevert { sys[HelpersApart + OnlySbxBound] implies s15[ByNs] }
check S15dhcpRevert for 4 but 1..8 steps expect 1

// S15 fix, revert: with the helpers' sockets bound in, the sandbox
// writes there.
assert S15boundRevert { sys[HelpersApart + DhcpInSbx] implies s15[ByNs] }
check S15boundRevert for 4 but 1..8 steps expect 1

// Vacuity: in the plan a helper's entry is host-side and the sandbox's
// isn't.
run planRun {
  sys[OnlySbxBound] and noReuse
  eventually (some m, n: Stamped | hostSide[ByCgroup, m] and side[n.author] = Attacker and not hostSide[ByCgroup, n])
} for 4 but 1..8 steps expect 1

// Vacuity: with the fix too.
run fixRun {
  fixed
  eventually (some m, n: Stamped | hostSide[ByNs, m] and side[n.author] = Attacker and not hostSide[ByNs, n])
} for 4 but 1..8 steps expect 1
