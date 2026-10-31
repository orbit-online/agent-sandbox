/*
 * Step 4, the host side around the sandbox (README.md, L8 and a proposed
 * L10): what ends with the sandbox, and what the host-side launcher does
 * with files in the sandbox's home before the next launch.
 *
 * Lifetimes are abstract: each helper is alive or not, with the kernel's
 * and systemd's rules for ending them. Host helpers react with weak
 * fairness, so "eventually" claims hold on lasso traces.
 *
 * Files are abstract too: a path the launcher touches in the sandbox's
 * home (stateDir/home, bound rw at the sandbox's $HOME) can be a link the
 * sandbox planted, to any host file the user can read or write.
 */
module launch_host

open sandbox

// HIDE: File Mount MountFlag Socket PeerCheck Guard Move

// ---------------------------------------------------------------------
// L8: lifetimes

abstract sig Thing {}
one sig
  Shell,     // bwrap-subid.sh before line 112's exec
  BwrapHost, // the same pid as bwrap, its parent half on the host
  SubidB,    // subid-broker, started at line 44
  Sandbox,   // the outer bwrap's child, with P and all in it
  Udhcpc,    // in P (net-setup.sh:26)
  Reentry,   // in P2, under a host nsenter
  Broker,    // the permissions broker's unit
  TypeA      // a type A plugin unit
  extends Thing {}
var sig Alive in Thing {}

abstract sig Mark {}
one sig Armed, Exec, Found, Ended extends Mark {}
var sig Marks in Mark {}

abstract sig Guard {}
one sig
  Pdeathsig, // subid-broker main.go:132 PR_SET_PDEATHSIG, fired when its parent exits
  PidfdExit, // broker.go:227-234: run returns when the sandbox's pidfd turns readable
  BindsTo,   // type A units BindsTo= the daemon's unit (README.md, Principals 9)
  ParentCheck // getppid() after the prctl: not in the code, the proposed fix
  extends Guard {}

pred live[t: Thing] { t in Alive }
pred become[add, del: set Thing, m: set Mark] {
  Alive' = Alive - del + add and Marks' = Marks + m
}

// claude-desktop.sh:109-117: the broker's unit starts ahead of nixpak
pred brokerStart { no Marks and not live[Broker] and become[Broker, none, none] }
pred subidSpawn { live[Shell] and not live[SubidB] and no Marks & (Armed + Exec) and become[SubidB, none, none] }
// serve's first step. Without ParentCheck a parent gone by now never
// sends the signal
pred subidArm[g: set Guard] {
  live[SubidB] and Armed not in Marks
  (ParentCheck in g and not live[Shell + BwrapHost]) implies become[none, SubidB, Armed]
  else become[none, none, Armed]
}
// bwrap-subid.sh:45-52: no socket within 5 s, exit 1
pred shellAbort { live[Shell] and Exec not in Marks and become[none, Shell, Ended] }
// The socket shows only after the prctl (listen follows it), so the exec
// follows the arming
pred execBwrap { live[Shell] and Armed in Marks and Exec not in Marks and become[BwrapHost, Shell, Exec] }
pred sandboxStart { live[BwrapHost] and Ended not in Marks and not live[Sandbox] and become[Sandbox, none, none] }
pred udhcpcStart { live[Sandbox] and not live[Udhcpc] and become[Udhcpc, none, none] }
pred reentryStart { live[Sandbox] and not live[Reentry] and become[Reentry, none, none] }
// findSandbox: its pidfd
pred brokerFinds { live[Broker + Sandbox] and Found not in Marks and become[none, none, Found] }
pred typeAStart { live[Broker] and Found in Marks and not live[TypeA] and become[TypeA, none, none] }
// P's init exits: the kernel kills P and P2, re-entries included
pred sandboxEnds { live[Sandbox] and become[none, Sandbox + Udhcpc + Reentry, Ended] }
// bwrap's parent half exits with its child; the death signal takes
// subid-broker with it
pred bwrapExit[g: set Guard] {
  live[BwrapHost] and not live[Sandbox] and Ended in Marks
  become[none, BwrapHost + (Pdeathsig in g and Armed in Marks implies SubidB else none), none]
}
// The broker's poll returns; systemd stops the units bound to it
pred brokerExit[g: set Guard] {
  live[Broker] and Found in Marks and not live[Sandbox] and PidfdExit in g
  become[none, Broker + (BindsTo in g implies TypeA else none), none]
}
pred stay { Alive' = Alive and Marks' = Marks }

pred lifetimes[g: set Guard] {
  Alive = Shell and no Marks
  always (brokerStart or subidSpawn or subidArm[g] or shellAbort or execBwrap
    or sandboxStart or udhcpcStart or reentryStart or brokerFinds or typeAStart
    or sandboxEnds or bwrapExit[g] or brokerExit[g] or stay)
  // Weak fairness for the host's own reactions
  (eventually always (live[SubidB] and Armed not in Marks)) implies always eventually Armed in Marks
  (eventually always (live[BwrapHost] and not live[Sandbox] and Ended in Marks)) implies always eventually not live[BwrapHost]
  (eventually always (live[Broker] and Found in Marks and not live[Sandbox])) implies always eventually not live[Broker]
}

// L8: once the sandbox ended (or never came up), the broker and its type A
// units, subid-broker, udhcpc and the re-entries end too.
pred l8 { always (Ended in Marks implies eventually no Alive & (Broker + TypeA + SubidB + Udhcpc + Reentry)) }

// L8. Known, two leaks when the sandbox never came up, neither reachable
// from inside: (1) bwrap-subid.sh gives up on the socket after 5 s and
// exits while subid-broker hasn't reached its prctl yet; the death
// signal is set after the parent is gone and never fires, so subid-broker
// listens on a socket no sandbox binds until logout. (2) The broker's
// findSandbox gives up after a minute and exits non-zero, and
// Restart=on-failure (claude-desktop.sh:114) starts it again, forever.
// (2) is the same as (1) for the model: Found never comes.
assert L8 { lifetimes[Guard - ParentCheck] implies l8 }
check L8 for 4 but 1..15 steps expect 1

// L8 for a sandbox that ran: everything ends with it.
assert L8ran { (lifetimes[Guard - ParentCheck] and always (Ended in Marks implies Found in Marks)) implies l8 }
check L8ran for 4 but 1..15 steps expect 0

// L8, revert: without BindsTo a type A unit outlives the broker.
assert L8ranRevert { (lifetimes[Guard - ParentCheck - BindsTo] and always (Ended in Marks implies Found in Marks)) implies l8 }
check L8ranRevert for 4 but 1..15 steps expect 1

// Vacuity: a sandbox with all of them runs and ends.
run lifetimesRun {
  lifetimes[Guard - ParentCheck]
  eventually (live[Udhcpc + Reentry + TypeA + SubidB]) and eventually Ended in Marks
} for 4 but 1..15 steps expect 1

// ---------------------------------------------------------------------
// L10 (proposed): host files through the sandbox's home

abstract sig Path {}
one sig
  Config,    // $CONFIG, claude_desktop_config.json (claude-desktop.sh:92-96)
  ConfigTmp, // $CONFIG.tmp, jq's output before the mv
  UserDirs   // .config/user-dirs.dirs (claude-desktop.sh:14)
  extends Path {}
// A host file the user can read and write: ~/.claude/.credentials.json,
// ~/.claude.json, another launcher's state
sig HostFile {}
one sig Links { var link: Path -> lone HostFile }
var sig Leaked, Clobbered in HostFile {}

one sig NoFollow extends Guard {}
// Where the launcher is: 0 before line 14, 1 before line 94, 2 done
abstract sig Stage {}
one sig BeforeDirs, BeforeMerge, Done extends Stage {}
one sig Cur { var at: one Stage }

pred filesKeep { Leaked' = Leaked and Clobbered' = Clobbered }

// The sandbox, while it ran: a link at any path, to any host file
pred plant {
  some p: Path, h: HostFile | Links.link' = Links.link ++ p -> h
  Cur.at' = Cur.at and filesKeep
}

// echo ... >"$SANDBOX_HOME/.config/user-dirs.dirs": the redirection
// follows a link and truncates its target
pred writeDirs[g: set Guard] {
  Cur.at = BeforeDirs and Cur.at' = BeforeMerge
  Clobbered' = Clobbered + (NoFollow in g implies none else UserDirs.(Links.link))
  Leaked' = Leaked and Links.link' = Links.link
}

// jq reads $CONFIG (a link: the host file's JSON), writes $CONFIG.tmp
// (a link: the host file gets the merged JSON, the sandbox's keys
// included), and mv renames $CONFIG.tmp over $CONFIG: the link itself
// moves, or the regular file with the host file's content lands where
// the sandbox reads it
pred merge[g: set Guard] {
  Cur.at = BeforeMerge and Cur.at' = Done
  NoFollow in g implies filesKeep else {
    Leaked' = Leaked + (no ConfigTmp.(Links.link) implies Config.(Links.link) else none)
    Clobbered' = Clobbered + ConfigTmp.(Links.link)
  }
  Links.link' = (Path - Config - ConfigTmp) <: Links.link + Config -> ConfigTmp.(Links.link)
}

pred launchFiles[g: set Guard] {
  no Links.link and no Leaked + Clobbered and Cur.at = BeforeDirs
  always (plant or writeDirs[g] or merge[g] or (Links.link' = Links.link and Cur.at' = Cur.at and filesKeep))
}

// L10 (proposed): no host-side launch step reads a host file into the
// sandbox, or writes one, through a path the sandbox can write.
//
// Known, confirmed against the code's bash and jq (a scratch copy of
// lines 92-96 with planted links): with $CONFIG a link to a host JSON
// file, the next launch copies it into the sandbox's home (the host's
// Claude Code credentials, another launcher's config); with $CONFIG.tmp a
// link, it overwrites the target with JSON the sandbox chose (a host
// ~/.claude.json with a project's mcpServers would run a command on the
// host; not tried). Line 14 truncates any host file the same way. The
// same pattern: line 11's touch, gtk-theme.sh's keyfile through
// .config/glib-2.0, store-sync.sh's nix copy into stateDir/nix (not
// modelled).
pred l10 { always no Leaked + Clobbered }
assert L10 { launchFiles[none] implies l10 }
check L10 for 3 but 1..6 steps expect 1

// L10 with the proposed fix: the launcher refuses or replaces links.
assert L10noFollow { launchFiles[NoFollow] implies l10 }
check L10noFollow for 3 but 1..6 steps expect 0

// Vacuity: links planted, launch done.
run filesRun {
  launchFiles[NoFollow] and eventually (Cur.at = Done and some Links.link)
} for 3 but 1..6 steps expect 1
