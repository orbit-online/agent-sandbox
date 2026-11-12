# The default launcher launched launches times in a row (20 in the flake check, 100 in CI's vm-loop-full), each to the
# stub app's log, then stopped: none may fail. nixpak's
# launcher without nix/patches/nixpak-launcher-reaper.patch panics in some ("panic: waitid: no child processes": its
# reaper took the pasta child StartPasta waits for)
{ sandboxHome, launches, ... }:
''
  start_portal()
  workstation.succeed("mkdir -p /srv/project")
  n = ${toString launches}
  applog = "${sandboxHome}/stub-app.log"
  failed = []
  with subtest(f"{n} launches of the default launcher"):
      for i in range(n):
          workstation.succeed(f"rm -f {applog}")
          # As launch() starts it. It returns once the app is up, or fails when nixpak's launcher did
          workstation.execute(
              "systemd-run --user -M alice@ --wait --pipe --quiet -E WAYLAND_DISPLAY=wayland-0"
              " -- /etc/profiles/per-user/alice/bin/claude-desktop"
          )
          workstation.wait_until_succeeds(
              f"test -s {applog} || ! systemctl --user -M alice@ -q is-active claude-desktop-app", timeout=300
          )
          if workstation.execute(f"test -s {applog}")[0] != 0:
              failed.append(i)
              print(f"launch {i} failed:\n" + workstation.succeed("journalctl --namespace=claude-desktop_sandbox _UID=1000 --no-pager -n 40 -o cat"))
          workstation.execute("systemctl --user -M alice@ kill --kill-whom=main -s KILL claude-desktop-app")
          workstation.wait_until_succeeds("! systemctl --user -M alice@ -q is-active claude-desktop-app", timeout=60)
          workstation.execute("systemctl --user -M alice@ reset-failed claude-desktop-app")
          workstation.wait_until_succeeds("! pgrep -x bwrap && ! pgrep -x udhcpc", timeout=60)
      panics = workstation.succeed("journalctl --namespace=claude-desktop_sandbox _UID=1000 --no-pager -o cat | grep -c 'waitid: no child' || true").strip()
      print(f"loop: {n - len(failed)} of {n} launches ok, failed: {failed}, waitid panics: {panics}")
      assert not failed, f"{len(failed)} of {n} launches failed: {failed}"
''
