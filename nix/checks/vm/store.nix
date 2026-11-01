# The default launcher's store dir: one the sandbox swapped for its own refused, and without a record of it, nix/ set aside
# and the closure synced afresh. Then --shell starting the app
{
  stateDir,
  sandboxHome,
  ...
}:
''
  start_portal()
  workstation.succeed("mkdir /srv/project")
  launch()
  sandbox_pid = bwrap_info()["child-pid"]
  workstation.succeed("systemctl --user -M alice@ kill --kill-whom=main claude-desktop")

  with subtest("the launcher refuses a store dir the sandbox swapped for its own"):
      workstation.wait_until_fails(f"test -e /proc/{sandbox_pid}", timeout=30)
      # As the sandbox can from a nested namespace (models/README.md, S12): the store dir renamed, a directory in its
      # place
      as_alice("/run/current-system/sw/bin/sh -c 'cd ${stateDir}/nix && mv store store.orig && mkdir store'")
      status, out = workstation.execute(
          "systemd-run --user -M alice@ --wait --pipe --quiet -p RuntimeMaxSec=600"
          " -- /etc/profiles/per-user/alice/bin/claude-desktop 2>&1"
      )
      assert status != 0 and "isn't the store directory this launcher made" in out, f"{status} {out}"
      as_alice("/run/current-system/sw/bin/sh -c 'cd ${stateDir}/nix && rmdir store && mv store.orig store'")

  with subtest("without a record of its store dir, the launcher sets nix/ aside and syncs afresh"):
      # An install from before the launcher kept the record, its store dir swapped by the sandbox
      as_alice("/run/current-system/sw/bin/sh -c 'cd ${stateDir}/nix && mv store store.orig && mkdir store"
               " && touch store/planted && rm ${stateDir}/nix-store.id'")
      sync = workstation.succeed(
          "nix-store -qR $(readlink -f /etc/profiles/per-user/alice/bin/claude-desktop)"
          " | grep -- '-claude-desktop-store-sync$'"
      ).strip()
      out = as_alice(f"/run/current-system/sw/bin/sh -c '{sync}/bin/claude-desktop-store-sync 2>&1'")
      assert "is set aside as" in out and "Copying the sandbox closure" in out, out
      aside = workstation.succeed("ls -d ${stateDir}/nix.quarantine-*").strip()
      workstation.succeed(f"test -e {aside}/store/planted -a -d {aside}/store.orig")
      workstation.fail("test -e ${stateDir}/nix/store/planted")
      recorded = workstation.succeed("cat ${stateDir}/nix-store.id").strip()
      assert recorded == workstation.succeed("stat -c %d:%i ${stateDir}/nix/store").strip(), recorded
      workstation.succeed("test -L ${stateDir}/nix/var/nix/gcroots/claude-desktop")
      # The next sync finds it current
      out = as_alice(f"/run/current-system/sw/bin/sh -c '{sync}/bin/claude-desktop-store-sync 2>&1'")
      assert out.strip() == "", out

  with subtest("--shell starts the app when it isn't running"):
      out = sandbox_shell("readlink /proc/self/ns/net")
      # --shell enters as soon as bwrap forks the app, which may not have logged yet
      workstation.wait_until_succeeds("test $(wc -l <${sandboxHome}/stub-app.log) -ge 2", timeout=30)
      launches = workstation.succeed("cat ${sandboxHome}/stub-app.log").splitlines()
      assert len(launches) == 2, launches
      assert out.splitlines()[-1] == launches[1].split()[1], f"{out} {launches}"
''
