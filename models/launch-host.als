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

abstract sig Thing {}
one sig
  Shell,     // bwrap-subid.sh before line 112's exec
  BwrapHost, // the same pid as bwrap, its parent half on the host
  SubidB,    // subid-broker, started at line 44
  Sandbox,   // the outer bwrap's child, with P and all in it
  Udhcpc,    // in P (net-setup.sh:26)
  Reentry,   // in P2, under a host nsenter
  Broker,    // the permissions broker's unit
  CallUnit         // a host command call's transient unit
  extends Thing {}
var sig Alive in Thing {}

abstract sig Mark {}
one sig Armed, Exec, Found, Ended extends Mark {}
var sig Marks in Mark {}

abstract sig Guard {}
one sig
  Pdeathsig,   // subid-broker dieWith: PR_SET_PDEATHSIG, fired when its parent exits
  PidfdExit,   // run.go: run returns when the sandbox's pidfd turns readable
  BindsTo,     // call units BindsTo= the daemon's unit (README.md, Principals 9)
  ParentCheck, // subid-broker dieWith: getppid() after the prctl, against the pid bwrap-subid.sh passes
  StartLimit   // claude-desktop.sh: the broker unit's StartLimitBurst=3 in 10 min
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
  (ParentCheck in g and no (Shell + BwrapHost) & Alive) implies become[none, SubidB, Armed]
  else become[none, none, Armed]
}
// bwrap-subid.sh: no socket within 5 s, exit 1. An armed subid-broker
// gets its death signal
pred shellAbort[g: set Guard] {
  live[Shell] and Exec not in Marks
  become[none, Shell + (Pdeathsig in g and Armed in Marks implies SubidB else none), Ended]
}
// The socket shows only after the prctl (listen follows it), so the exec
// follows the arming
pred execBwrap { live[Shell] and Armed in Marks and Exec not in Marks and become[BwrapHost, Shell, Exec] }
pred sandboxStart { live[BwrapHost] and Ended not in Marks and not live[Sandbox] and become[Sandbox, none, none] }
pred udhcpcStart { live[Sandbox] and not live[Udhcpc] and become[Udhcpc, none, none] }
pred reentryStart { live[Sandbox] and not live[Reentry] and become[Reentry, none, none] }
// findSandbox: its pidfd
pred brokerFinds { live[Broker + Sandbox] and Found not in Marks and become[none, none, Found] }
pred callStart { live[Broker] and Found in Marks and not live[CallUnit] and become[CallUnit, none, none] }
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
  become[none, Broker + (BindsTo in g implies CallUnit else none), none]
}
// findSandbox gives up after a minute and the broker exits non-zero;
// Restart=on-failure starts it again until the start limit stops it.
// Without the limit it stays, restarting, which the model keeps alive
pred brokerGivesUp[g: set Guard] {
  live[Broker] and Found not in Marks and Ended in Marks and StartLimit in g
  become[none, Broker, none]
}
pred stay { Alive' = Alive and Marks' = Marks }

pred lifetimes[g: set Guard] {
  Alive = Shell and no Marks
  always (brokerStart or subidSpawn or subidArm[g] or shellAbort[g] or execBwrap
    or sandboxStart or udhcpcStart or reentryStart or brokerFinds or callStart
    or sandboxEnds or bwrapExit[g] or brokerExit[g] or brokerGivesUp[g] or stay)
  // Weak fairness for the host's own reactions
  (eventually always (live[SubidB] and Armed not in Marks)) implies always eventually Armed in Marks
  (eventually always (live[BwrapHost] and not live[Sandbox] and Ended in Marks)) implies always eventually not live[BwrapHost]
  (eventually always (live[Broker] and Found in Marks and not live[Sandbox])) implies always eventually not live[Broker]
  StartLimit in g implies
    ((eventually always (live[Broker] and Found not in Marks and Ended in Marks)) implies always eventually not live[Broker])
}

// L8: once the sandbox ended (or never came up), the broker and its call
// units, subid-broker, udhcpc and the re-entries end too.
pred l8 { always (Ended in Marks implies eventually no Alive & (Broker + CallUnit + SubidB + Udhcpc + Reentry)) }

// L8, also when the sandbox never came up. Holds.
assert L8 { lifetimes[Guard] implies l8 }
check L8 for 4 but 1..15 steps expect 0

// L8, revert: without ParentCheck, bwrap-subid.sh gives up on the socket
// after 5 s and exits while subid-broker hasn't reached its prctl yet;
// the death signal is set after the parent is gone and never fires, so
// subid-broker listens on a socket no sandbox binds until logout.
assert L8parentRevert { lifetimes[Guard - ParentCheck] implies l8 }
check L8parentRevert for 4 but 1..15 steps expect 1

// L8, revert: without StartLimit the broker that never finds a sandbox
// restarts forever.
assert L8limitRevert { lifetimes[Guard - StartLimit] implies l8 }
check L8limitRevert for 4 but 1..15 steps expect 1

// L8 for a sandbox that ran: everything ends with it.
assert L8ran { (lifetimes[Guard] and always (Ended in Marks implies Found in Marks)) implies l8 }
check L8ran for 4 but 1..15 steps expect 0

// L8, revert: without BindsTo a call unit outlives the broker.
assert L8ranRevert { (lifetimes[Guard - BindsTo] and always (Ended in Marks implies Found in Marks)) implies l8 }
check L8ranRevert for 4 but 1..15 steps expect 1

// Vacuity: a sandbox with all of them runs and ends.
run lifetimesRun {
  lifetimes[Guard]
  eventually (live[Udhcpc + Reentry + CallUnit + SubidB]) and eventually Ended in Marks
} for 4 but 1..15 steps expect 1

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
  // store-sync.sh: a store dir that's a link stops the launch, before
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
