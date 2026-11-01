# The launcher work next to the default one, and its permissions broker
{
  pkgs,
  broker,
  workStateDir,
  routerIP,
  ...
}:
''
  import time

  start_portal()
  workstation.succeed("mkdir /srv/project")
  app_pid, app_netns, app_mntns, _, _, _ = launch()

  with subtest("A named launcher runs a sandbox of its own next to the default one"):
      work_home = "${workStateDir}/home"
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
          return script + ") | ${pkgs.lib.getExe broker} mcp"

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

      # The standing grants from the config, there since the daemon started: the command issued without asking, for
      # the ceiling's maxValidity
      make_folders()
      standing = {g["capability"]: g["id"] for g in control({"op": "state"}, tries=30)["grants"] if g["lease"] == "standing"}
      assert sorted(standing) == ["test/echo", "test/thing"], f"standing grants {standing}"
      mcp_until(mcp_script(request_call("test/thing", {})), "issued-PT28800S")
      # The service: its plugin runs socket-activated by systemd, on a socket in the grant directory, and the MCP
      # server offers its tool and forwards a call to it
      workstation.succeed(f"systemctl --user -M alice@ is-active -q perm-work_{standing['test/echo']}.socket")
      call = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
          "name": "test_echo", "arguments": {"text": "from the sandbox"}}}
      mcp_until(mcp_script(call), "echo: from the sandbox")
      # Revoked, a standing grant is asked for like any other
      control({"op": "revoke", "grant": standing["test/echo"]})
      workstation.wait_until_fails(f"systemctl --user -M alice@ is-active -q perm-work_{standing['test/echo']}.socket",
                                   timeout=30)
      granted("echo", "test/echo", {}, ".sock")
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

      # A crash ends the daemon's grants: ExecStopPost detaches the folder, and the service units are bound to it.
      # Started again, it has its standing grants alone, the revoked one too, under new ids
      socket_unit = workstation.succeed(
          "systemctl --user -M alice@ list-units --plain --no-legend 'perm-work_*.socket' | cut -d' ' -f1"
      ).strip()
      folder = grants[0].split()[4]
      bound = workstation.succeed(f"systemctl --user -M alice@ show -P BindsTo {socket_unit}")
      assert "claude-desktop-work-permissions.service" in bound, f"{socket_unit} bound to {bound!r}"
      stop_post = workstation.succeed("systemctl --user -M alice@ show -P ExecStopPost claude-desktop-work-permissions")
      assert " cleanup " in stop_post, f"ExecStopPost {stop_post!r}"
      workstation.succeed("systemctl --user -M alice@ kill --signal=SIGKILL claude-desktop-work-permissions")
      workstation.wait_until_fails(f"systemctl --user -M alice@ is-active -q {socket_unit}", timeout=30)
      workstation.wait_until_succeeds(work_cmd(f"sh -c '! grep -q \" {folder} \" /proc/self/mountinfo'"), timeout=30)
      workstation.wait_until_succeeds("systemctl --user -M alice@ is-active -q claude-desktop-work-permissions", timeout=30)
      state = control({"op": "state"}, tries=30)
      again = {g["capability"]: g["id"] for g in state["grants"] if g["lease"] == "standing"}
      assert sorted(again) == ["test/echo", "test/thing"] and len(state["grants"]) == 2, f"grants after a restart: {state}"
      assert not set(again.values()) & set(standing.values()), f"the same ids after a restart: {again}"
      workstation.succeed(f"systemctl --user -M alice@ is-active -q perm-work_{again['test/echo']}.socket")

      # The Permissions window starts on the host against the running daemon, its Qt kept from the host's plugins.
      # Offscreen, as the VM has no compositor alice could show it on: still up after five seconds
      as_alice("/run/current-system/sw/bin/sh -c 'QT_QPA_PLATFORM=offscreen timeout 5 /etc/profiles/per-user/alice/bin/claude-desktop-work"
               " --permissions; [ $? = 124 ]'")

      workstation.succeed("systemctl --user -M alice@ kill --kill-whom=main claude-desktop-work")
      workstation.wait_until_fails(f"test -e /proc/{work_pid}", timeout=30)
      # The daemon ends with its sandbox
      workstation.wait_until_fails("systemctl --user -M alice@ is-active claude-desktop-work-permissions", timeout=30)
      # The default sandbox runs on
      assert in_sandbox("readlink /proc/self/ns/net").strip() == app_netns
''
