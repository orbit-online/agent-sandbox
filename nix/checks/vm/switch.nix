# A switch while the app runs leaves its unit and sandbox alone, whatever it does to the launcher's slice: sd-switch
# would stop the slice, and the app's unit in it, for a changed unit file or one that is new or gone
{ ... }:
''
  start_portal()
  workstation.succeed("mkdir /srv/project")
  launch()
  sandbox_pid = bwrap_info()["child-pid"]
  slice = "claude\\x2ddesktop.slice"
  weight = f"/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/{slice}/cpu.weight"
  base = workstation.succeed("readlink -f /run/current-system").strip()

  def invocation():
      return workstation.succeed("systemctl --user -M alice@ show -P InvocationID claude-desktop-app").strip()

  started = invocation()
  assert workstation.succeed(f"systemctl --user -M alice@ show -P RefuseManualStop '{slice}'").strip() == "yes"

  for name, toplevel, want in [
      ("a changed CPU weight", f"{base}/specialisation/slice-changed", "70"),
      ("the weight changed back", base, "50"),
      ("the slice's unit file gone", f"{base}/specialisation/slice-gone", None),
  ]:
      with subtest(f"a switch to {name} leaves the app running"):
          workstation.succeed(f"{toplevel}/bin/switch-to-configuration test")
          assert invocation() == started, f"the app's unit restarted: {invocation()}"
          workstation.succeed(f"test -e /proc/{sandbox_pid}")
          if want:
              assert workstation.succeed(f"cat '{weight}'").strip() == want
''
