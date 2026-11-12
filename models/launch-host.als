/*
 * Step 4, the host side around the sandbox (README.md, L8 and L10): what
 * ends with the sandbox, and what the host-side launcher does with files
 * in the sandbox's home and store.
 *
 * Lifetimes are abstract: each helper is alive or not, with the kernel's
 * and systemd's rules for ending them. Host helpers react with weak
 * fairness, so "eventually" claims hold on lasso traces.
 *
 * Files are abstract too: a path the launcher touches in the sandbox's
 * home or store (stateDir/home and stateDir/nix, bound rw) can be a link
 * the sandbox planted, to any host file the user can read or write.
 */
module launch_host

open sandbox

// HIDE: File Mount MountFlag Socket PeerCheck Guard Move

// ---------------------------------------------------------------------
// L8: lifetimes
//
// As of de94126: subid-broker and udhcpc are transient units in the
// launcher's slice with BindsTo= the app's unit (helper.go:46-57,
// hostUnits.start), no After=. subid-broker gets the launcher's pid (which
// then execs into bwrap) and pidfd_opens it before it creates the socket.

abstract sig Thing {}
one sig
  AppUnit,   // the app's unit, supervise (supervise.go): waits for nixpak's launcher (:119),
             // then, when it failed, for the user to close the error window (splash.go:98-106)
  Shell,     // the launcher's bwrap (bwrap.go runBwrap) before its exec at :178
  BwrapHost, // the same process after the exec, bwrap's parent half on the host
  SubidB,    // subid-broker's unit, started at bwrap.go:197
  Sandbox,   // the outer bwrap's child, with P and all in it
  Udhcpc,    // the dhcp unit (helper.go:159), its udhcpc in P
  Reentry,   // in P2, under a host nsenter
  Broker,    // the permissions broker's unit
  CallUnit,  // a host command call's transient unit
  Other      // any host process that takes the launcher's pid once it's free
  extends Thing {}
var sig Alive in Thing {}

abstract sig Mark {}
one sig Spawned, Listening, Exec, Found, Ended extends Mark {}
var sig Marks in Mark {}

// The pid bwrap.go:197 passes (os.Getpid()): the process it names now
one sig LPid { var names: lone Thing }
// subid-broker's pidfd (subid-broker main.go:139): the process it names
one sig Pidfd { var on: lone Thing }

abstract sig Guard {}
one sig
  PidfdOpen,  // subid-broker serve: pidfd_open at :139 before ListenUnix at :144, so the launcher,
              // which waits for the socket (bwrap.go:200-205), is still the process at that pid
  PidfdWatch, // serve :155-158: the listener closes once the pidfd turns readable
  BindsToApp, // helper.go:48: BindsTo= the app's unit, for the subid and dhcp units
  PidfdExit,  // run.go: run returns when the sandbox's pidfd turns readable
  BindsTo,    // call units BindsTo= the daemon's unit (README.md, Principals 9)
  StartLimit, // launcher supervise.go:195-196: the broker unit's StartLimitBurst=3 in 10 min
  StopOnAbort // bwrap.go startSubidBroker: giving up, the launcher stops the subid unit (systemctl waits for it)
              // before it exits, while the pid is still its own
  extends Guard {}

pred live[t: Thing] { t in Alive }
pred become[add, del: set Thing, m: set Mark] {
  Alive' = Alive - del + add and Marks' = Marks + m
  LPid.names' = LPid.names - del and Pidfd.on' = Pidfd.on
}

// supervise.go prepare, ahead of nixpak's launcher: the broker's unit starts first
pred brokerStart { no Marks and not live[Broker] and become[Broker, none, none] }
// bwrap.go:197: systemd-run returns once the unit's process is forked.
// Without PidfdOpen the socket would show before the pidfd is open
pred subidSpawn[g: set Guard] {
  live[Shell] and Spawned not in Marks
  become[SubidB, none, Spawned + (PidfdOpen in g implies none else Listening)]
}
// serve's first step: pidfd_open on whatever has the pid now; a free pid
// fails and the broker exits 1. With PidfdOpen the socket follows
pred subidOpen {
  live[SubidB] and no Pidfd.on
  some LPid.names & Alive implies {
    Alive' = Alive and Marks' = Marks + Listening
    LPid.names' = LPid.names and Pidfd.on' = LPid.names
  } else become[none, SubidB, none]
}
// The pidfd turns readable: the listener closes, the unit ends
pred subidEnd[g: set Guard] {
  PidfdWatch in g and live[SubidB] and some Pidfd.on - Alive
  become[none, SubidB, none]
}
// bwrap.go startSubidBroker: no socket within 5 s, the launcher stops the
// subid unit and exits 1 (the pid is free once supervise reaps it)
pred shellAbort[g: set Guard] {
  live[Shell] and Listening not in Marks
  become[none, Shell + (StopOnAbort in g implies SubidB else none), Ended]
}
// The exec keeps the pid, and the pidfd names the same process
pred execBwrap {
  live[Shell] and Listening in Marks
  Alive' = Alive - Shell + BwrapHost and Marks' = Marks + Exec
  LPid.names' = BwrapHost and Pidfd.on' = (Pidfd.on = Shell implies BwrapHost else Pidfd.on)
}
// The kernel hands the free pid to another host process
pred reuse { no LPid.names and not live[Other] and Alive' = Alive + Other and Marks' = Marks
  LPid.names' = Other and Pidfd.on' = Pidfd.on }
pred otherExit { live[Other] and become[none, Other, none] }
pred sandboxStart { live[BwrapHost] and Ended not in Marks and not live[Sandbox] and become[Sandbox, none, none] }
pred udhcpcStart { live[Sandbox] and not live[Udhcpc] and become[Udhcpc, none, none] }
pred reentryStart { live[Sandbox] and not live[Reentry] and become[Reentry, none, none] }
// findSandbox: its pidfd
pred brokerFinds { live[Broker + Sandbox] and Found not in Marks and become[none, none, Found] }
pred callStart { live[Broker] and Found in Marks and not live[CallUnit] and become[CallUnit, none, none] }
// P's init exits: the kernel kills P and P2, udhcpc and re-entries included
pred sandboxEnds { live[Sandbox] and become[none, Sandbox + Udhcpc + Reentry, Ended] }
// bwrap's parent half exits with its child
pred bwrapExit { live[BwrapHost] and not live[Sandbox] and Ended in Marks and become[none, BwrapHost, none] }
// supervise returns once nixpak's launcher is gone, after the error window
// when it failed: the app's unit ends
pred appEnds { live[AppUnit] and no (Shell + BwrapHost) & Alive and become[none, AppUnit, Ended] }
// systemd stops what's bound to the app's unit once that is inactive
pred bindsStop[g: set Guard] {
  BindsToApp in g and not live[AppUnit] and some (SubidB + Udhcpc) & Alive
  become[none, SubidB + Udhcpc, none]
}
// The broker's poll returns; systemd stops the units bound to it
pred brokerExit[g: set Guard] {
  live[Broker] and Found in Marks and not live[Sandbox] and PidfdExit in g
  become[none, Broker + (BindsTo in g implies CallUnit else none), none]
}
// findSandbox gives up after a minute and the broker exits non-zero;
// Restart=on-failure starts it again until the start limit stops it.
// Without the limit it stays, restarting, which the model keeps alive
pred brokerGivesUp[g: set Guard] {
  live[Broker] and Found not in Marks and Ended in Marks and StartLimit in g
  become[none, Broker, none]
}
pred stay { Alive' = Alive and Marks' = Marks and LPid.names' = LPid.names and Pidfd.on' = Pidfd.on }

pred lifetimes[g: set Guard] {
  Alive = AppUnit + Shell and no Marks and LPid.names = Shell and no Pidfd.on
  always (brokerStart or subidSpawn[g] or subidOpen or subidEnd[g] or shellAbort[g] or execBwrap
    or reuse or otherExit or sandboxStart or udhcpcStart or reentryStart or brokerFinds or callStart
    or sandboxEnds or bwrapExit or appEnds or bindsStop[g] or brokerExit[g] or brokerGivesUp[g] or stay)
  // Weak fairness for the host's own reactions. Not for appEnds (the
  // user closes the error window, or doesn't) nor Other (lives as long as
  // it likes)
  (eventually always live[Shell]) implies always eventually not live[Shell]
  (eventually always (live[SubidB] and no Pidfd.on)) implies always eventually not (live[SubidB] and no Pidfd.on)
  (eventually always (PidfdWatch in g and live[SubidB] and some Pidfd.on - Alive)) implies always eventually not live[SubidB]
  (eventually always (live[BwrapHost] and not live[Sandbox] and Ended in Marks)) implies always eventually not live[BwrapHost]
  (eventually always (BindsToApp in g and not live[AppUnit] and some (SubidB + Udhcpc) & Alive))
    implies always eventually no (SubidB + Udhcpc) & Alive
  (eventually always (live[Broker] and Found in Marks and not live[Sandbox])) implies always eventually not live[Broker]
  StartLimit in g implies
    ((eventually always (live[Broker] and Found not in Marks and Ended in Marks)) implies always eventually not live[Broker])
}
// The user closes the error window, or the app exited cleanly: the app's
// unit ends once nixpak's launcher has
pred userCloses {
  (eventually always (live[AppUnit] and no (Shell + BwrapHost) & Alive)) implies always eventually not live[AppUnit]
}

// L8: once the sandbox ended (or never came up), the broker and its call
// units, subid-broker, udhcpc and the re-entries end too.
pred l8 { always (Ended in Marks implies eventually no Alive & (Broker + CallUnit + SubidB + Udhcpc + Reentry)) }

// L8, also when the sandbox never came up, given the app's unit ends.
// Holds.
assert L8 { (lifetimes[Guard] and userCloses) implies l8 }
check L8 for 4 but 1..18 steps expect 0

// L8 whether or not the user closes the error window: the launcher that
// gives up on the socket stops the subid unit first, so no broker is left
// to open a pidfd on whatever takes the pid next. Holds.
assert L8window { lifetimes[Guard] implies l8 }
check L8window for 4 but 1..18 steps expect 0

// L8window, revert: without the stop, the launcher gives up after 5 s
// and exits before subid-broker's pidfd_open, another host process takes
// its pid, and the broker opens a pidfd on that one. It serves until that
// process exits or the app's unit stops, which waits for the user to
// close the error window. Its socket is in the launchers' runtime dir,
// which no sandbox binds, unless the process that took the pid is another
// launcher's own (the socket is named by pid alone): that one's sandbox
// would use this broker until this app's unit stops.
assert L8stopRevert { lifetimes[Guard - StopOnAbort] implies l8 }
check L8stopRevert for 4 but 1..18 steps expect 1

// L8 without pid reuse, error window or not: the broker exits at once
// when the pid is free. Holds, so the reuse is L8stopRevert's cause.
assert L8noReuse { (lifetimes[Guard] and always not live[Other]) implies l8 }
check L8noReuse for 4 but 1..18 steps expect 0

// L8, revert: BindsTo= the app's unit is the backstop for a launcher
// that didn't get to stop the subid unit: without both, the broker on a
// reused pid outlives the app's unit.
assert L8bindsRevert { (lifetimes[Guard - BindsToApp - StopOnAbort] and userCloses) implies l8 }
check L8bindsRevert for 4 but 1..18 steps expect 1

// L8, revert: without StartLimit the broker that never finds a sandbox
// restarts forever.
assert L8limitRevert { (lifetimes[Guard - StartLimit] and userCloses) implies l8 }
check L8limitRevert for 4 but 1..18 steps expect 1

// L8 for a sandbox that ran: everything ends with it, the app's unit or
// not (its error window may stay up). Holds.
pred ran { always (Ended in Marks implies Found in Marks) }
assert L8ran { (lifetimes[Guard] and ran) implies l8 }
check L8ran for 4 but 1..18 steps expect 0

// L8 ran, revert: without the pidfd's watch subid-broker stays until the
// app's unit stops.
assert L8watchRevert { (lifetimes[Guard - PidfdWatch] and ran) implies l8 }
check L8watchRevert for 4 but 1..18 steps expect 1

// L8 ran, revert: with the socket before the pidfd, the launcher execs
// bwrap before the broker opened it; the sandbox runs and ends, the pid
// goes to another process, and the broker watches that one.
assert L8openRevert { (lifetimes[Guard - PidfdOpen] and ran) implies l8 }
check L8openRevert for 4 but 1..18 steps expect 1

// L8 ran, revert: without BindsTo a call unit outlives the broker.
assert L8ranRevert { (lifetimes[Guard - BindsTo] and ran) implies l8 }
check L8ranRevert for 4 but 1..18 steps expect 1

// Vacuity: a sandbox with all of them runs and ends.
run lifetimesRun {
  lifetimes[Guard] and userCloses
  eventually (live[Udhcpc + Reentry + CallUnit + SubidB]) and eventually Ended in Marks
} for 4 but 1..18 steps expect 1

// Vacuity: the launcher gives up and, without the stop, the broker finds
// its pid free.
run subidGoneRun {
  lifetimes[Guard - StopOnAbort] and always not live[Other]
  eventually (Ended in Marks and live[SubidB] and no Pidfd.on)
} for 4 but 1..18 steps expect 1

// ---------------------------------------------------------------------
// L10: host files through the sandbox's home and store

abstract sig Path {}
one sig
  Config,     // $CONFIG, claude_desktop_config.json, merged with jq at launch
  ConfigTmp,  // $CONFIG.tmp, jq's output before the mv (before the fix)
  UserDirs,   // .config/user-dirs.dirs, written at launch
  ResolvConf, // .config/resolv.conf, touched at launch
  Keyfile,    // .config/glib-2.0/settings/keyfile, which the theme watcher
              // writes while the sandbox runs
  StoreDir    // stateDir/nix/store: Nix imports into it at launch, and
              // nixpak binds it on its own at /nix/store
  extends Path {}
// A host file the user can read and write: ~/.claude/.credentials.json,
// ~/.claude.json, another launcher's state
sig HostFile {}
one sig Links { var link: Path -> lone HostFile }
var sig Leaked, Clobbered in HostFile {}

one sig
  // state.sh through confine.sh: a bwrap holding only its closure and the
  // directories it works in, where a planted link reaches no host file,
  // and files replaced by a rename, which replaces a link
  Confined,
  // launcher store.go:24-26: a store dir that's a link stops the launch, before
  // nixpak's bind would follow it on the host
  StoreLinkRefused
  extends Guard {}
// Where the launcher is
abstract sig Stage {}
one sig BeforeDirs, BeforeMerge, BeforeStore, Done, Refused extends Stage {}
one sig Cur { var at: one Stage }

pred filesKeep { Leaked' = Leaked and Clobbered' = Clobbered }

// The sandbox, any time: a link at any path, to any host file
pred plant {
  some p: Path, h: HostFile | Links.link' = Links.link ++ p -> h
  Cur.at' = Cur.at and filesKeep
}

// user-dirs.dirs written and resolv.conf touched: before the fix the
// redirection and touch followed a link to its target
pred writeDirs[g: set Guard] {
  Cur.at = BeforeDirs and Cur.at' = BeforeMerge
  Confined in g implies {
    filesKeep
    Links.link' = (Path - UserDirs - ResolvConf) <: Links.link
  } else {
    Clobbered' = Clobbered + (UserDirs + ResolvConf).(Links.link)
    Leaked' = Leaked and Links.link' = Links.link
  }
}

// jq reads $CONFIG (a link: the host file's JSON), writes $CONFIG.tmp
// (a link: the host file gets the merged JSON, the sandbox's keys
// included), and mv renames $CONFIG.tmp over $CONFIG: the link itself
// moves, or the regular file with the host file's content lands where
// the sandbox reads it. Confined, both links resolve to nothing of the
// host's, the temp file is a fresh one, and the rename replaces $CONFIG
pred merge[g: set Guard] {
  Cur.at = BeforeMerge and Cur.at' = BeforeStore
  Confined in g implies {
    filesKeep
    Links.link' = (Path - Config) <: Links.link
  } else {
    Leaked' = Leaked + (no ConfigTmp.(Links.link) implies Config.(Links.link) else none)
    Clobbered' = Clobbered + ConfigTmp.(Links.link)
    Links.link' = (Path - Config - ConfigTmp) <: Links.link + Config -> ConfigTmp.(Links.link)
  }
}

// The store sync, then nixpak. Nix follows a link at the store dir and
// writes the closure there, unless confined; nixpak's bwrap then binds
// what the link points to, rw at /nix/store
pred store[g: set Guard] {
  Cur.at = BeforeStore
  (StoreLinkRefused in g and some StoreDir.(Links.link)) implies {
    Cur.at' = Refused and filesKeep
  } else {
    Cur.at' = Done
    Clobbered' = Clobbered + StoreDir.(Links.link)
    Leaked' = Leaked + StoreDir.(Links.link)
  }
  Links.link' = Links.link
}

// The theme watcher's gsettings, at any time: before the fix it read the
// keyfile through a link and wrote it back to the target
pred theme[g: set Guard] {
  Confined in g implies {
    filesKeep
    Links.link' = (Path - Keyfile) <: Links.link
  } else {
    Leaked' = Leaked + Keyfile.(Links.link)
    Clobbered' = Clobbered + Keyfile.(Links.link)
    Links.link' = Links.link
  }
  Cur.at' = Cur.at
}

pred launchFiles[g: set Guard] {
  no Links.link and no Leaked + Clobbered and Cur.at = BeforeDirs
  always (plant or writeDirs[g] or merge[g] or store[g] or theme[g]
    or (Links.link' = Links.link and Cur.at' = Cur.at and filesKeep))
}

// L10: no host-side step reads a host file into the sandbox, or writes
// one, through a path the sandbox can write. Holds.
pred l10 { always no Leaked + Clobbered }
assert L10 { launchFiles[Confined + StoreLinkRefused] implies l10 }
check L10 for 3 but 1..8 steps expect 0

// L10, revert: the launcher as it was, confirmed against its bash and
// jq (a scratch copy with planted links): with $CONFIG a link to a host
// JSON file, the next launch copied it into the sandbox's home (the
// host's Claude Code credentials, another launcher's config); with
// $CONFIG.tmp a link, it overwrote the target with JSON the sandbox chose
// (a host ~/.claude.json with a project's mcpServers would run a command
// on the host; not tried). user-dirs.dirs truncated any host file the
// same way, and nix copy wrote through links in the store.
assert L10revert { launchFiles[none] implies l10 }
check L10revert for 3 but 1..8 steps expect 1

// L10, revert: confined alone, Nix writes nothing of the host's, but
// nixpak's bind of a store dir that's a link still gives the sandbox the
// host directory it names.
assert L10storeRevert { launchFiles[Confined] implies l10 }
check L10storeRevert for 3 but 1..8 steps expect 1

// Vacuity: links planted, launch done.
run filesRun {
  launchFiles[Confined + StoreLinkRefused] and eventually (Cur.at = Done and some Links.link)
} for 3 but 1..8 steps expect 1
