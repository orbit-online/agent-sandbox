# The permissions broker's state machine tests against the work launcher's live daemon and sandbox
{
  brokerLive,
  workStateDir,
  ...
}:
''
  import os, time

  work_home = "${workStateDir}/home"
  start_portal()
  make_folders()
  start_echo()
  launch("claude-desktop-work", work_home)
  workstation.wait_until_succeeds("systemctl --user -M alice@ is-active claude-desktop-work-permissions", timeout=60)

  with subtest("the broker's state machine tests, live"):
      # The state machine tests live (TestLiveMachine): rapid's sequences of requests and connections to the echo
      # socket from a copy of the test binary in the sandbox, answers and revoke through control.sock, releases,
      # restarts and lock events, the live state checked against the reference model after every step. A fixed seed;
      # LIVE_RAPID replaces the rapid flags in the interactive driver, -rapid.seed=0 for a random one, and LIVE_TIMEOUT its
      # 15 minutes
      workstation.succeed("mkdir -p /srv/notes/sub /srv/outside && chown alice /srv/notes/sub /srv/outside")
      workstation.succeed(
          f"install -D -m755 -o alice ${brokerLive}/bin/permissions-broker-live {work_home}/live/agent"
      )
      # A graphical session of alice's, whose Lock the daemon watches from its start
      workstation.succeed(
          "systemd-run --unit fake-session -p PAMName=login -p User=alice -p TTYPath=/dev/tty3"
          " -E XDG_SESSION_TYPE=wayland -E XDG_SESSION_CLASS=user -- /run/current-system/sw/bin/sleep infinity"
      )
      workstation.wait_until_succeeds("loginctl show-user alice -P Display | grep -q .", timeout=30)
      lock_session = workstation.succeed("loginctl show-user alice -P Display").strip()
      exec_start = workstation.succeed("systemctl --user -M alice@ show -P ExecStart claude-desktop-work-permissions")
      live_config = exec_start.split(" serve ")[1].split()[0]
      rapid_flags = os.environ.get("LIVE_RAPID", "-rapid.seed=1")
      started = time.monotonic()
      status, out = workstation.execute(alice_cmd(
          "/run/current-system/sw/bin/env PATH=/run/current-system/sw/bin"
          f" LIVE_CONFIG={live_config} LIVE_LAUNCHER=/etc/profiles/per-user/alice/bin/claude-desktop-work"
          f" LIVE_BIN=/home/alice/live/agent LIVE_ROOT=/srv/notes LIVE_OUTSIDE=/srv/outside LIVE_LOCK_SESSION={lock_session}"
          f" ${brokerLive}/bin/permissions-broker-live -test.run '^TestLiveMachine$' -test.v -rapid.nofailfile {rapid_flags}"
      ) + " 2>&1", timeout=int(os.environ.get("LIVE_TIMEOUT", "900")))
      print(out)
      assert status == 0 and "--- PASS: TestLiveMachine" in out, f"TestLiveMachine failed after {time.monotonic() - started:.0f} s"
      print(f"TestLiveMachine took {time.monotonic() - started:.0f} s")
      workstation.succeed("systemctl stop fake-session")
''
