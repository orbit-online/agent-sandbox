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
  workstation.succeed("systemctl --user -M alice@ kill --kill-whom=main claude-desktop-app")

  with subtest("the launcher deletes a store dir the sandbox swapped for its own and syncs afresh"):
      workstation.wait_until_fails(f"test -e /proc/{sandbox_pid}", timeout=30)
      # As the sandbox can from a nested namespace (models/README.md, S12): the store dir renamed, a directory in its
      # place
      as_alice("/run/current-system/sw/bin/sh -c 'cd ${stateDir}/nix && mv store store.orig && mkdir store'")
      # The launcher's store sync, with the config the wrapper runs it with
      start = workstation.succeed(
          "grep -oP '/nix/store/\\S+/bin/launcher start --config=\\S+\\.json'"
          " $(readlink -f /etc/profiles/per-user/alice/bin/claude-desktop)"
      ).strip()
      sync = start.replace(" start ", " store-sync ")
      out = as_alice(f"/run/current-system/sw/bin/sh -c '{sync} 2>&1'")
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
      out = as_alice(f"/run/current-system/sw/bin/sh -c '{sync} 2>&1'")
      assert "is deleted" in out and "Copying the sandbox closure" in out, out
      workstation.fail("test -e ${stateDir}/nix/store/planted -o -e ${stateDir}/nix/store/sub -o -e ${stateDir}/nix/store.orig")
      recorded = workstation.succeed("cat ${stateDir}/nix-store.id").strip()
      assert recorded == workstation.succeed("stat -c %d:%i ${stateDir}/nix/store").strip(), recorded
      workstation.succeed("test -L ${stateDir}/nix/var/nix/gcroots/claude-desktop")
      # The next sync finds it current
      out = as_alice(f"/run/current-system/sw/bin/sh -c '{sync} 2>&1'")
      assert out.strip() == "", out

  with subtest("--shell starts the app when it isn't running"):
      out = sandbox_shell("readlink /proc/self/ns/net")
      # --shell enters as soon as bwrap forks the app, which may not have logged yet
      workstation.wait_until_succeeds("test $(wc -l <${sandboxHome}/stub-app.log) -ge 2", timeout=30)
      launches = workstation.succeed("cat ${sandboxHome}/stub-app.log").splitlines()
      assert len(launches) == 2, launches
      assert out.splitlines()[-1] == launches[1].split()[1], f"{out} {launches}"
      # In the app's unit, its cgroup delegated, as from the desktop: the sandbox in sandbox/app/
      cg = workstation.succeed("systemctl --user -M alice@ show -P ControlGroup claude-desktop-app").strip()
      assert cg.endswith("/claude\\x2ddesktop.slice/claude-desktop-app.service"), cg
      assert workstation.succeed(f"cat '/sys/fs/cgroup{cg}/sandbox/app/cgroup.procs'").split(), f"nothing in {cg}/sandbox/app"

  with subtest("Without nsdelegate, the sandbox's cgroup is read-only and there's no systemd --user, which the launch says"):
      def cgroup2_flags():
          return workstation.succeed("grep -m1 ' - cgroup2 ' /proc/self/mountinfo").split()[-1]
      # systemd mounts cgroup2 with it
      flags = cgroup2_flags()
      assert "nsdelegate" in flags.split(","), flags
      workstation.succeed("systemctl --user -M alice@ stop claude-desktop-app")
      # As cilium's mount at /run/cilium/cgroupv2 does: another cgroup2 mount in the host's cgroup namespace without
      # the option clears it for all
      workstation.succeed("mkdir /run/test-cgroupv2 && mount -t cgroup2 none /run/test-cgroupv2")
      assert "nsdelegate" not in cgroup2_flags().split(","), cgroup2_flags()
      workstation.succeed("systemd-run --user -M alice@ --wait --pipe --quiet -- /etc/profiles/per-user/alice/bin/claude-desktop")
      workstation.wait_until_succeeds("test $(wc -l <${sandboxHome}/stub-app.log) -ge 3", timeout=300)
      # The launcher says so in its unit's journal, and starts the app
      workstation.wait_until_succeeds(
          "journalctl --namespace=claude-desktop_sandbox _SYSTEMD_USER_UNIT=claude-desktop-app.service | grep -q 'cgroup2 is mounted without nsdelegate'",
          timeout=30)
      workstation.succeed("systemctl --user -M alice@ is-active claude-desktop-app")
      # Inside, its cgroup read-only
      top = [l.split() for l in in_sandbox("cat /proc/self/mountinfo").splitlines() if l.split()[4] == "/sys/fs/cgroup"][-1]
      assert "ro" in top[5].split(","), top
      status, out = workstation.execute(sandbox_cmd("sh -c 'mkdir /sys/fs/cgroup/x'") + " 2>&1")
      assert status != 0, out
      # The bind alone: a cgroup2 mount of its own still writes its subtree, and reaches nothing above it
      fresh_cgroup2_mount(in_sandbox, f"/sys/fs/cgroup{cg}")
      # No systemd --user, as the launch said, so no scopes either
      assert "No systemd --user" in workstation.succeed(
          "journalctl --namespace=claude-desktop_sandbox --no-pager -o cat -t claude-desktop")
      status, out = workstation.execute(sandbox_cmd("systemd-run --user --scope true") + " 2>&1")
      assert status != 0, out
      # The remount the warning names restores it
      workstation.succeed("umount /run/test-cgroupv2")
      warning = workstation.succeed("journalctl --namespace=claude-desktop_sandbox _SYSTEMD_USER_UNIT=claude-desktop-app.service | grep -o \"'mount -o [^']*'\"")
      workstation.succeed(warning.strip().splitlines()[-1].strip("'"))
      assert cgroup2_flags() == flags, f"{cgroup2_flags()}, was {flags}"
''
