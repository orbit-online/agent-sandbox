# The default launcher's store dir: one the sandbox swapped for its own refused, and without a record of it, nix/ deleted
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

  with subtest("the launcher deletes a store dir the sandbox swapped for its own and syncs afresh"):
      workstation.wait_until_fails(f"test -e /proc/{sandbox_pid}", timeout=30)
      # As the sandbox can from a nested namespace (models/README.md, S12): the store dir renamed, a directory in its
      # place
      as_alice("/run/current-system/sw/bin/sh -c 'cd ${stateDir}/nix && mv store store.orig && mkdir store'")
      sync = workstation.succeed(
          "nix-store -qR $(readlink -f /etc/profiles/per-user/alice/bin/claude-desktop)"
          " | grep -- '-claude-desktop-store-sync$'"
      ).strip()
      out = as_alice(f"/run/current-system/sw/bin/sh -c '{sync}/bin/claude-desktop-store-sync 2>&1'")
      assert "is deleted" in out and "Copying the sandbox closure" in out, out
      workstation.fail("test -e ${stateDir}/nix/store.orig")
      recorded = workstation.succeed("cat ${stateDir}/nix-store.id").strip()
      assert recorded == workstation.succeed("stat -c %d:%i ${stateDir}/nix/store").strip(), recorded

  with subtest("without a record of its store dir, the launcher deletes nix/ and syncs afresh"):
      # An install from before the launcher kept the record, its store dir swapped by the sandbox, and a file in it that
      # a container made, owned by one of alice's subuids
      as_alice("/run/current-system/sw/bin/sh -c 'cd ${stateDir}/nix && mv store store.orig && mkdir store"
               " && touch store/planted && rm ${stateDir}/nix-store.id"
               " && PATH=$PATH:/run/wrappers/bin /run/current-system/sw/bin/unshare --map-auto --map-root-user"
               " /run/current-system/sw/bin/sh -c \"mkdir store/sub && touch store/sub/f && chown -R 1000:1000 store/sub\"'")
      owner = workstation.succeed("stat -c %u ${stateDir}/nix/store/sub/f").strip()
      assert owner != workstation.succeed("id -u alice").strip(), owner
      out = as_alice(f"/run/current-system/sw/bin/sh -c '{sync}/bin/claude-desktop-store-sync 2>&1'")
      assert "is deleted" in out and "Copying the sandbox closure" in out, out
      workstation.fail("test -e ${stateDir}/nix/store/planted -o -e ${stateDir}/nix/store/sub -o -e ${stateDir}/nix/store.orig")
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
