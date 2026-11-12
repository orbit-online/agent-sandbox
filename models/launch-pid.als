/*
 * Planned, not built: a `systemd --user` manager inside the sandbox
 * (README.md, Principals 18, L11), and the app's pid. app-pid.sh
 * (nix/home/claude-desktop/app-pid.sh:9-10) writes APP_PID-1 to
 * ns_last_pid in P2 and forks the app, which then gets APP_PID as long as
 * nothing else in P2 forks in between: the D-Bus proxy's tray rule names
 * StatusNotifierItem-<APP_PID>-1 (dbus.nix:129), and the re-entries look
 * for the app at APP_PID (L5, launch-reentry.als).
 *
 * The manager runs in U2, M2, P2 like the app, in sandbox/user, and is the
 * attacker's: its units come from the sandbox's home, which the sandbox
 * writes (Attacker 1, 11). Decided against U1, M1, P, where its forks
 * wouldn't touch P2's pids: there the sandbox's jobs would run in U1 with
 * the owner's capabilities over U2, M2, P2 (README.md, Namespaces), which
 * nothing the app starts has today (B2).
 *
 * The kernel's allocation (kernel/pid.c alloc_pid, idr_alloc_cyclic): the
 * next fork in a pid ns takes the first free pid above ns_last_pid. So
 * once a fork took APP_PID, or a pid above it because APP_PID was taken,
 * APP_PID comes back only after the pids wrap at pid_max (4194304 here),
 * which the model leaves out.
 */
module launch_pid

abstract sig Proc {}
one sig
  App,     // the app (or app-pid.sh's stub for it, under Retry)
  Manager, // systemd --user
  Job      // what the manager forks and what that forks: its generators,
           // default.target's units (it sends READY=1 at basic.target,
           // systemd 260.5 src/core/manager.c:3888, before them), a timer's
           // Persistent= catch-up (immediate at the timer's start,
           // systemd.timer(5)), the .path unit when gc-pending exists at
           // start (systemd.path(5)), any unit the sandbox planted in its home
  extends Proc {}
var sig Running in Proc {}
// The process at APP_PID in P2
one sig Slot { var holder: lone Proc }

abstract sig Flag {}
one sig
  Primed,     // ns_last_pid is APP_PID-1: the next fork in P2 gets APP_PID if it's free
  Wrote,      // app-pid.sh wrote it
  AppForked,
  MgrStarted,
  Ready       // the manager's READY=1
  extends Flag {}
var sig Flags in Flag {}

// How app-pid.sh orders its steps
abstract sig Order {}
one sig
  ManagerFirst, // the plan: the manager, its READY=1, the write, the app's fork
  Retry,        // the plan, and a stub forked in the app's place exits when its pid isn't APP_PID, and the write and fork are tried again
  AppFirst      // the write, the app's fork, then the manager
  extends Order {}

// A fork in P2: the child takes APP_PID when the cursor is right below it
// and it's free; either way the cursor moves past it
pred forkBy[child: Proc, add: set Flag] {
  Running' = Running + child
  Slot.holder' = ((Primed in Flags and no Slot.holder) implies child else Slot.holder)
  Flags' = Flags - Primed + add
}
pred keep { Running' = Running and Slot.holder' = Slot.holder }

pred startManager[o: Order] {
  MgrStarted not in Flags
  o = AppFirst implies AppForked in Flags else Wrote not in Flags
  forkBy[Manager, MgrStarted]
}
pred ready { Manager in Running and Ready not in Flags and keep and Flags' = Flags + Ready }
// app-pid.sh:9, with CAP_CHECKPOINT_RESTORE
pred write[o: Order] {
  Wrote not in Flags
  o != AppFirst implies Ready in Flags
  keep and Flags' = Flags + Wrote + Primed
}
// app-pid.sh:10 (setsid --fork, or the shell's own fork under AppFirst)
pred forkApp { Wrote in Flags and AppForked not in Flags and forkBy[App, AppForked] }
// The stub at the wrong pid exits; app-pid.sh writes again
pred retry[o: Order] {
  o = Retry and App in Running and Slot.holder != App
  Running' = Running - App and Slot.holder' = Slot.holder and Flags' = Flags - AppForked - Wrote
}
pred jobFork { Manager in Running and forkBy[Job, none] }
pred jobExit { Job in Running and Running' = Running - Job and Slot.holder' = Slot.holder - Job and Flags' = Flags }
pred stay { keep and Flags' = Flags }

pred sys[o: Order] {
  no Running and no Slot.holder and no Flags
  always (startManager[o] or ready or write[o] or forkApp or retry[o] or jobFork or jobExit or stay)
  // Weak fairness for app-pid.sh and the manager's start; none for the
  // jobs, which fork and live as they like
  (eventually always (MgrStarted not in Flags and (o = AppFirst implies AppForked in Flags else Wrote not in Flags)))
    implies always eventually MgrStarted in Flags
  (eventually always (Manager in Running and Ready not in Flags)) implies always eventually Ready in Flags
  (eventually always (Wrote not in Flags and (o != AppFirst implies Ready in Flags)))
    implies always eventually Wrote in Flags
  (eventually always (Wrote in Flags and AppForked not in Flags)) implies always eventually AppForked in Flags
  (eventually always (o = Retry and App in Running and Slot.holder != App))
    implies always eventually not (App in Running and Slot.holder != App)
}

// L11: the app ends up at APP_PID in P2 and stays there (app-pid.sh's
// write succeeds; L4 covers the failure).
pred l11 { eventually always (App in Running and Slot.holder = App) }

// L11, known finding in the plan: the manager or a job forks between the
// write and the app's fork and takes APP_PID; the app runs at another pid.
// Its tray item's name (StatusNotifierItem-<pid>-1) isn't the one the
// proxy lets it own, so the tray icon is refused and the app runs without
// it; re-entries find the job at APP_PID instead (L5: a job that unshared
// its user and mount namespaces, such as a planted unit with
// PrivateUsers=, takes a claude:// URL or the user's --shell there). A
// unit planted in the home forks on purpose, so OnStartupSec= delays on
// the module's own timers don't close it.
assert L11plan { sys[ManagerFirst] implies l11 }
check L11plan for 3 but 1..10 steps expect 1

// L11, retry: the stub sees the wrong pid and exits, but while a job
// holds APP_PID every retry gets another pid.
assert L11retry { sys[Retry] implies l11 }
check L11retry for 3 but 1..10 steps expect 1

// L11 with the manager started after the app's fork: between the write
// and the fork nothing else runs in P2 but bwrap's init. Holds. Its
// revert, the manager first, is L11plan.
assert L11 { sys[AppFirst] implies l11 }
check L11 for 3 but 1..10 steps expect 0

// Vacuity: the manager is up and a job runs, with the app at APP_PID.
run appFirstRun {
  sys[AppFirst] and eventually (Job in Running and Ready in Flags and Slot.holder = App)
} for 3 but 1..10 steps expect 1

// Vacuity: the plan does work when nothing forks in the window.
run planRun { sys[ManagerFirst] and eventually Slot.holder = App } for 3 but 1..10 steps expect 1
