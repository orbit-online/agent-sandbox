# The launcher work next to the default one, and its permissions broker
{
  pkgs,
  broker,
  brokerLive,
  workStateDir,
  mcpArgs,
  routerIP,
  ...
}:
''
  import re, time

  start_portal()
  workstation.succeed("mkdir /srv/project")
  app_pid, app_netns, app_mntns, _, _, _ = launch()
  work_home = "${workStateDir}/home"

  with subtest("A named launcher runs a sandbox of its own next to the default one"):
      work_pid, work_netns, work_mntns, _, _, work_bus = launch("claude-desktop-work", work_home)
      assert work_netns != app_netns and work_mntns != app_mntns, "work runs in the default sandbox"
      # Its own tray item next to the default one's
      assert work_bus == "1" and work_pid != app_pid, f"work is pid {work_pid}, the default {app_pid}: {work_bus}"

      # Its re-entry finds its own sandbox by its app ID
      assert in_work("readlink /proc/self/ns/net").strip() == work_netns
      # Both on the LAN, the MAC salted with the launcher's name
      workstation.wait_until_succeeds(work_cmd("grep -qx 'nameserver ${routerIP}' /etc/resolv.conf"), timeout=60)
      assert "inet 192.168.1." in in_work("ip -4 -o addr show dev eth0")
      macs = {f("ip -br link show eth0").split()[2] for f in [in_sandbox, in_work]}
      assert len(macs) == 2, macs
      # Its own state dir, with ~/.claude and the app's config in its home
      workstation.succeed(f"test -d {work_home}/.claude && test -s {work_home}/.config/Claude/claude_desktop_config.json")
      workstation.succeed("test -L ${workStateDir}/nix/var/nix/gcroots/claude-desktop")
      workstation.succeed("test -L /run/user/1000/claude-desktop/store-roots-work")

  with subtest("The sandbox runs in its unit's delegated cgroup, the app in sandbox/app"):
      user = "/user.slice/user-1000.slice/user@1000.service"
      work_slice = f"{user}/claude\\x2ddesktop\\x2dwork.slice"
      unit_root = f"/sys/fs/cgroup{work_slice}/claude-desktop-work-app.service"
      def procs(cg):
          return workstation.succeed(f"cat '{unit_root}/{cg}cgroup.procs'").split()
      def cgroup(pid):
          return workstation.succeed(f"cat /proc/{pid}/cgroup").strip().removeprefix("0::")
      def main_pid(unit):
          return workstation.succeed(f"systemctl --user -M alice@ show -P MainPID {unit}").strip()
      for prop, want in [("Delegate", "yes"), ("DelegateSubgroup", "supervisor")]:
          got = workstation.succeed(f"systemctl --user -M alice@ show -P {prop} claude-desktop-work-app").strip()
          assert got == want, f"{prop}={got}"
      # Neither the delegation root nor the sandbox's root holds a process
      inner = [procs(""), procs("sandbox/")]
      assert inner == [[], []], f"processes in the root and sandbox/: {inner}"
      # The unit's main process, nixpak's launcher, in supervisor/; bwrap's child and the app in sandbox/app/
      assert main_pid("claude-desktop-work-app") in procs("supervisor/")
      sandbox_procs = procs("sandbox/app/")
      assert str(bwrap_info("com.nixpak.ClaudeDesktop.work")["child-pid"]) in sandbox_procs, sandbox_procs
      app = next(p for p in sandbox_procs
                 if workstation.execute(f"tr '\\0' ' ' </proc/{p}/cmdline")[1].endswith("/sleep infinity "))
      # With the variable of the unit that ran the launcher
      workstation.succeed(f"tr '\\0' '\\n' </proc/{app}/environ | grep -qx WAYLAND_DISPLAY=wayland-0")
      # The default launcher's in a unit and slice of its own
      assert cgroup(bwrap_info()["child-pid"]) == f"{user}/claude\\x2ddesktop.slice/claude-desktop-app.service/sandbox/app"
      # The broker, a unit of its own in the slice
      workstation.wait_until_succeeds("systemctl --user -M alice@ is-active claude-desktop-work-permissions", timeout=60)
      unit = "claude-desktop-work-permissions"
      assert cgroup(main_pid(unit)) == f"{work_slice}/{unit}.service", f"{unit} in {cgroup(main_pid(unit))}"
      # The re-entries join the app's cgroup: claude:// and --shell
      assert in_work("cat /proc/self/cgroup").strip() == "0::/app"
      assert sandbox_shell("cat /proc/self/cgroup").strip().splitlines()[-1] == "0::/app"
      # Inside, /sys/fs/cgroup is the sandbox's subtree alone, writable: none of the session's units
      listing = in_work("ls /sys/fs/cgroup").split()
      assert "app" in listing and not [n for n in listing if n.endswith((".slice", ".service", ".scope"))], listing
      dirs = in_work("find /sys/fs/cgroup -mindepth 1 -type d").split()
      assert dirs == ["/sys/fs/cgroup/app"], dirs
      top = [l.split() for l in in_work("cat /proc/self/mountinfo").splitlines() if l.split()[4] == "/sys/fs/cgroup"][-1]
      assert top[3] == "/" and "rw" in top[5].split(","), top

  with subtest("cgrun runs a job in a cgroup of its own, killed past its memory limit while the app runs on"):
      out = in_work("cgrun --memory=64M -- sh -c 'cat /proc/self/cgroup; cat /sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)/memory.max'")
      cg, limit = out.split()
      assert re.fullmatch(r"0::/cgrun-\d+", cg) and limit == str(64 << 20), out
      out = in_work("sh -c 'cgrun --memory=64M -- sh -c \"head -c 512M /dev/zero | tail\"; echo exit=$?'")
      assert out.strip().splitlines()[-1] == "exit=137", out
      # Its cgroup gone after it
      assert not [n for n in in_work("ls /sys/fs/cgroup").split() if n.startswith("cgrun-")]
      workstation.succeed("systemctl --user -M alice@ is-active claude-desktop-work-app")
      workstation.succeed(f"test -e /proc/{app}")
      events = dict(l.split() for l in workstation.succeed(f"cat '{unit_root}/sandbox/memory.events'").splitlines())
      assert int(events["oom_kill"]) >= 1, events

  with subtest("The sandbox can't widen its cgroup or leave it"):
      def refused(cmd):
          status, out = workstation.execute(work_cmd(f"sh -c {shlex.quote(cmd)}") + " 2>&1")
          assert status != 0, f"{cmd}: {out}"
      # Its root's limits are the host's (nsdelegate)
      refused("echo 1G >/sys/fs/cgroup/memory.max")
      refused("echo max >/sys/fs/cgroup/cgroup.max.descendants")
      # No process in its root, which holds controllers for its children
      refused("echo 0 >/sys/fs/cgroup/cgroup.procs")
      # The host's hierarchy under the bind stays hidden, and a cgroup2 mount of its own, in a cgroup namespace of its
      # own, shows its own cgroup's subtree
      refused("unshare --user --map-current-user --mount umount /sys/fs/cgroup")
      out = in_work("unshare --user --map-root-user --mount --cgroup sh -c"
                    " 'd=$(mktemp -d) && mount -t cgroup2 none $d && ls $d'").split()
      assert "cgroup.procs" in out and not [n for n in out if n.endswith((".slice", ".service", ".scope"))], out
      # At most 64 cgroups below its root, app/ included
      out = in_work("sh -c 'n=0; while [ $n -lt 80 ] && mkdir /sys/fs/cgroup/d$n 2>/dev/null; do n=$((n + 1)); done;"
                    " echo $n; rmdir /sys/fs/cgroup/d*'")
      assert out.strip() == "63", f"made {out.strip()} cgroups"

  with subtest("The work launcher's broker"):
      # The permissions broker: its daemon runs, its grant directory is read-only inside, shared in the sandbox's
      # outer mount namespace before the FHS env's bwrap copied it, so a slave where the app runs
      workstation.wait_until_succeeds("systemctl --user -M alice@ is-active claude-desktop-work-permissions", timeout=60)
      # Restarted on failure, but not forever when it never finds a sandbox
      limit = workstation.succeed(
          "systemctl --user -M alice@ show -p StartLimitBurst -p StartLimitIntervalUSec claude-desktop-work-permissions"
      ).split()
      assert sorted(limit) == ["StartLimitBurst=3", "StartLimitIntervalUSec=10min"], f"start limit {limit}"
      work_pid = bwrap_info("com.nixpak.ClaudeDesktop.work")["child-pid"]
      m1 = [l for l in workstation.succeed(f"cat /proc/{work_pid}/mountinfo").splitlines() if " /run/permissions " in l]
      assert len(m1) == 1 and " shared:" in m1[0], f"/run/permissions in M1: {m1}"
      m2 = [l for l in in_work("cat /proc/self/mountinfo").splitlines() if " /run/permissions " in l]
      assert len(m2) == 1 and " master:" in m2[0] and " ro," in m2[0], f"/run/permissions where the app runs: {m2}"
      status, _ = workstation.execute(work_cmd("touch /run/permissions/x"))
      assert status != 0, "the sandbox can write to its grant directory"
      # request.sock answers from inside, and refuses share from where the app runs
      status, out = workstation.execute(work_cmd("${pkgs.lib.getExe broker} share") + " 2>&1")
      assert status != 0 and "outer mount namespace" in out, out
      # The user's side through control.sock, as the window has it
      control_sock = "/run/user/1000/claude-desktop/permissions-work-control.sock"
      def control(req, tries=1):
          script = ("import socket, sys; s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]);"
                    " s.sendall(sys.argv[2].encode()); print(s.makefile().readline())")
          for _ in range(tries):
              status, out = workstation.execute(alice_cmd(
                  f"${pkgs.python3.interpreter} -c {shlex.quote(script)} {control_sock} {shlex.quote(json.dumps(req))}"
              ))
              if status == 0:
                  return json.loads(out)
              time.sleep(1)
          raise Exception(f"control.sock doesn't answer {req}")

      def answer(capability, params):
          for _ in range(60):
              for p in control({"op": "state"}).get("pending", []):
                  if p["capability"] == capability and p["params"] == params:
                      return control({"op": "answer", "pending": p["id"], "allow": True})
              time.sleep(1)
          raise Exception(f"No request of {capability} {params} pending")

      init = [
          {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
              "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "vm", "version": "0"}}},
          {"jsonrpc": "2.0", "method": "notifications/initialized"},
      ]
      def mcp_script(*calls, wait=3):
          lines = " ".join(shlex.quote(json.dumps(m)) for m in init)
          script = f"(printf '%s\\n' {lines}; sleep 3"
          for c in calls:
              script += f"; printf '%s\\n' {shlex.quote(json.dumps(c))}; sleep {wait}"
          return script + ") | ${pkgs.lib.getExe broker} ${pkgs.lib.escapeShellArgs mcpArgs}"

      def request_call(capability, params, n=2):
          return {"jsonrpc": "2.0", "id": n, "method": "tools/call", "params": {"name": "request", "arguments": {
              "capability": capability, "params": params, "reason": "the VM test", "lease": "PT1H"}}}

      # Retried until the daemon listens; the MCP server's whole output, stderr too, if it never answers
      def mcp_until(script, want, tries=20):
          for _ in range(tries):
              _, out = workstation.execute(work_cmd(f"sh -c {shlex.quote(script + ' 2>&1')}"))
              if want in out:
                  return
              time.sleep(3)
          raise Exception(f"No {want!r} from the MCP server: {out}")

      # A request through the MCP server in the background, its output in the sandbox's home, which the user answers
      def granted(name, capability, params, want):
          script = mcp_script(request_call(capability, params), wait=60) + f" >/home/alice/{name}.out 2>&1"
          workstation.succeed(f"systemd-run --user -M alice@ --unit {name} --"
                              f" /etc/profiles/per-user/alice/bin/claude-desktop-work --exec sh -c {shlex.quote(script)}")
          answer(capability, params)
          workstation.wait_until_succeeds(f"grep -q {shlex.quote(want)} ${workStateDir}/home/{name}.out", timeout=60)

      # The standing grants from the config, there since the daemon started: the host command, a tool of the MCP
      # server's from its start, called without asking and told its maxValidity, and the host socket
      make_folders()
      start_echo()
      standing = {g["capability"]: g["id"] for g in control({"op": "state"}, tries=30)["grants"] if g["lease"] == "standing"}
      assert sorted(standing) == ["echo", "test"], f"standing grants {standing}"
      mcp_until(mcp_script({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
          "name": "test_thing", "arguments": {"reason": "the VM test"}}}), "issued-PT28800S")
      # The call ran as a unit in the launcher's slice
      call = workstation.succeed("cat /run/user/1000/test-call.cgroup").strip()
      assert re.fullmatch(rf"0::{re.escape(work_slice)}/perm-work_call-[0-9a-f]+\.service", call), f"the call in {call}"
      # The host socket at its stable address: the broker copies bytes to and from alice's echo server. The test
      # binary's live-connect is the client, as the sandbox has no nc
      workstation.succeed(f"install -D -m755 -o alice ${brokerLive}/bin/permissions-broker-live {work_home}/connect")
      connect = "/home/alice/connect live-connect /run/permissions/sockets/echo"
      out = in_work(f"sh -c {shlex.quote('echo ping | timeout 10 ' + connect)}")
      assert out.strip() == "ping", f"through the host socket: {out!r}"

      # A connection held open: it ends when the grant does. The shell feeding it doesn't wait for its input
      def hold(name):
          script = (f"mkfifo /tmp/{name}.in; (echo first; exec sleep 600) >/tmp/{name}.in & {connect} </tmp/{name}.in"
                    f" >/home/alice/{name}.out; echo $? >/home/alice/{name}.exit")
          workstation.succeed(f"systemd-run --user -M alice@ --unit {name} --"
                              f" /etc/profiles/per-user/alice/bin/claude-desktop-work --exec sh -c {shlex.quote(script)}")
          workstation.wait_until_succeeds(f"grep -qx first {work_home}/{name}.out", timeout=60)

      # Revoked, the standing grant's connection is closed, a new one is closed at once, and the grant is asked for
      # like any other
      hold("held")
      control({"op": "revoke", "grant": standing["echo"]})
      workstation.wait_until_succeeds(f"test -s {work_home}/held.exit", timeout=30)
      out = in_work(f"sh -c {shlex.quote('echo ping | timeout 10 ' + connect + '; echo exit=$?')}")
      assert out.strip() == "exit=0", f"without a grant: {out!r}"
      granted("echo", "echo", {}, "/run/permissions/sockets/echo")
      out = in_work(f"sh -c {shlex.quote('echo ping | timeout 10 ' + connect)}")
      assert out.strip() == "ping", f"granted again: {out!r}"
      # A folder, mounted read-only, nodev and nosuid where the app runs; /srv/mounted has a mount beneath it, which
      # would come along unchecked: never mounted
      granted("notes", "folders/folder", {"path": "/srv/notes"}, "/run/permissions/")
      workstation.wait_until_succeeds(work_cmd("sh -c 'cat /run/permissions/*/file'") + " | grep -qx notes", timeout=60)
      granted("mounted", "folders/folder", {"path": "/srv/mounted"}, '"isError":true')
      status, _ = workstation.execute(work_cmd("sh -c 'touch /run/permissions/*/new'"))
      assert status != 0, "the read-only folder grant is writable"
      grants = [l for l in in_work("cat /proc/self/mountinfo").splitlines() if " /run/permissions/" in l]
      assert len(grants) == 1, f"one folder mounted, not the one with a mount beneath it: {grants}"
      opts = grants[0].split()[5].split(",")
      assert {"ro", "nodev", "nosuid"} <= set(opts), grants[0]

      # A crash ends the daemon's grants: ExecStopPost detaches the folder, and its connections close with it.
      # Started again, it has its standing grants alone, the revoked one too, under new ids
      folder = grants[0].split()[4]
      hold("crashed")
      stop_post = workstation.succeed("systemctl --user -M alice@ show -P ExecStopPost claude-desktop-work-permissions")
      assert " cleanup " in stop_post, f"ExecStopPost {stop_post!r}"
      workstation.succeed("systemctl --user -M alice@ kill --signal=SIGKILL claude-desktop-work-permissions")
      workstation.wait_until_succeeds(f"test -s {work_home}/crashed.exit", timeout=30)
      workstation.wait_until_succeeds(work_cmd(f"sh -c '! grep -q \" {folder} \" /proc/self/mountinfo'"), timeout=30)
      workstation.wait_until_succeeds("systemctl --user -M alice@ is-active -q claude-desktop-work-permissions", timeout=30)
      state = control({"op": "state"}, tries=30)
      again = {g["capability"]: g["id"] for g in state["grants"] if g["lease"] == "standing"}
      assert sorted(again) == ["echo", "test"] and len(state["grants"]) == 2, f"grants after a restart: {state}"
      assert not set(again.values()) & set(standing.values()), f"the same ids after a restart: {again}"
      # The window's overview of the configuration
      assert state["overview"]["network"] and any(b["path"] == "/home/alice" for b in state["overview"]["binds"]), state["overview"]
      out = in_work(f"sh -c {shlex.quote('echo ping | timeout 10 ' + connect)}")
      assert out.strip() == "ping", f"the standing grant back after a restart: {out!r}"

      # No system bus inside: D-Bus grants and the system-bus proxy aren't built (docs/permissions.md, D-Bus)
      status, _ = workstation.execute(work_cmd("test -e /run/dbus/system_bus_socket"))
      assert status != 0, "the work sandbox has a system bus socket"

      # The Permissions window starts on the host against the running daemon, its Qt kept from the host's plugins.
      # Offscreen, as the VM has no compositor alice could show it on: still up after five seconds
      as_alice("/run/current-system/sw/bin/sh -c 'QT_QPA_PLATFORM=offscreen timeout 5 /etc/profiles/per-user/alice/bin/claude-desktop-work"
               " --permissions; [ $? = 124 ]'")

  with subtest("The work sandbox ends with its unit"):
      workstation.succeed("systemctl --user -M alice@ kill --kill-whom=main claude-desktop-work-app")
      workstation.wait_until_fails(f"test -e /proc/{work_pid}", timeout=30)
      # The daemon ends with its sandbox
      workstation.wait_until_fails("systemctl --user -M alice@ is-active claude-desktop-work-permissions", timeout=30)
      # The default sandbox runs on
      assert in_sandbox("readlink /proc/self/ns/net").strip() == app_netns
''
