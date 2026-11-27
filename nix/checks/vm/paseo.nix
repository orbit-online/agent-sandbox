# Paseo's sandboxes (alice's agent-sandbox.paseo, on the stub of ../paseo-stub.nix) beside Claude Desktop's: the launch,
# the state step, what the agents find inside, the re-entries and the launcher work
{
  nodes,
  pkgs,
  ...
}:
let
  paseo = nodes.workstation.home-manager.users.alice.agent-sandbox.paseo;
  work = paseo.launchers.work;
  conf = paseo.build.launcherConfig;
  workConf = work.build.launcherConfig;
  exe = "${paseo.package}/libexec/paseo-desktop/paseo-electron";
in
''
  import time
  import tomllib

  paseo_state = "${conf.stateDir}"
  paseo_home = "${conf.home}"
  work_home = "${workConf.home}"
  exe = "${exe}"
  root = "${paseo.build.appRoot}"

  # Starts a Paseo launcher as launch() starts Claude Desktop's and returns the stub's start entry: its pid, namespaces,
  # capabilities, argv, PATH, desktop name and version
  def paseo_launch(launcher="paseo", home=paseo_home):
      status, out = workstation.execute(
          "systemd-run --user -M alice@ --wait --pipe --quiet -E WAYLAND_DISPLAY=wayland-0"
          f" -- /etc/profiles/per-user/alice/bin/{launcher} 2>&1"
      )
      if status != 0:
          logs = workstation.execute(f"journalctl --namespace={launcher} --no-pager -n 60; "
                                     f"journalctl --namespace={launcher}_sandbox --no-pager -n 60")[1]
          raise Exception(f"{launcher} didn't start: {out}\n{logs}")
      workstation.wait_until_succeeds(f"grep -q '\"event\":\"start\"' {home}/paseo-stub.log", timeout=300)
      return [e for e in paseo_log(home) if e["event"] == "start"][-1]

  def paseo_log(home=paseo_home):
      return [json.loads(l) for l in workstation.succeed(f"cat {home}/paseo-stub.log").splitlines()]

  # Stops a launcher's unit and its log, for a launch afresh
  def paseo_stop(launcher="paseo", home=paseo_home):
      workstation.succeed(f"systemctl --user -M alice@ stop {launcher}-app.service")
      workstation.wait_until_fails(f"systemctl --user -M alice@ is-active {launcher}-app.service", timeout=60)
      workstation.succeed(f"rm -f {home}/paseo-stub.log")

  # cmd in a running Paseo sandbox, through the launcher's re-entry and the stub's --exec
  def paseo_cmd(cmd, launcher="paseo"):
      return alice_cmd(f"/etc/profiles/per-user/alice/bin/{launcher} --exec {cmd}")

  def in_paseo(cmd, launcher="paseo"):
      return workstation.succeed(paseo_cmd(cmd, launcher))

  def journal(ns, args=""):
      return workstation.succeed(f"journalctl --namespace={ns} --no-pager -o cat {args}")

  # The agents' files in a home, by name
  def agent_files(home):
      return {f: workstation.succeed(f"cat {home}/{f}") for f in [".paseo/config.json", ".claude.json"]}

  # Codex's system config in a running sandbox, parsed
  def codex_config(launcher="paseo"):
      return tomllib.loads(in_paseo("cat /etc/codex/config.toml", launcher))

  # A file of alice's in a Paseo home, edited by a shell command run in its directory
  def edit_home(cmd, home=paseo_home):
      script = f"set -e; cd {home}; jq=${pkgs.lib.getExe pkgs.jq}; {cmd}"
      as_alice(f"/run/current-system/sw/bin/bash -c {shlex.quote(script)}")

  start_portal()
  workstation.succeed("mkdir -p /srv/project/sub")
  app_pid, app_netns, app_mntns, _, _, _ = launch()

  with subtest("Paseo's sandbox: launched to its ready line, with its own name, netns, journals, state, unit and slice"):
      p = paseo_launch()
      # The module's app root, on the package's Electron, with no argument but --no-sandbox; the launcher's app ID as the
      # windows' (index.js keeps main.js from setting Paseo.desktop), the package's version
      assert p["argv"] == [exe, root, "--no-sandbox"], p["argv"]
      assert p["desktopName"] == "sh.paseo.Paseo.desktop", p["desktopName"]
      assert p["version"] == "${paseo.package.version}", p["version"]
      # At the pid app-pid.sh set, which isn't Claude Desktop's, without capabilities
      assert p["pid"] == ${toString conf.appPid} and ${toString conf.appPid} != int(app_pid), f"{p['pid']}, Claude Desktop's {app_pid}"
      assert p["capEff"] == "0000000000000000", p["capEff"]
      assert p["net"] != app_netns and p["mnt"] != app_mntns, "Paseo runs in Claude Desktop's sandbox"
      # The ready line ended the start (the launcher returned), from index.js's hook, once, in the sandbox's journal
      ready = journal("paseo_sandbox").count("agent-sandbox: ready")
      assert ready == 1, f"{ready} ready lines"
      assert "agent-sandbox: ready" not in journal("paseo"), "the ready line in the host side's journal"
      assert "agent-sandbox: ready" in journal("claude-desktop_sandbox"), "Claude Desktop's journal lost its ready line"
      started = [l for l in journal("paseo", "-t paseo").splitlines() if l.startswith("level=INFO msg=Started ")]
      assert started and " ready=" in started[-1], journal("paseo")
      # Its unit in its slice, its state dir with its own store
      workstation.succeed("systemctl --user -M alice@ is-active ${conf.unit}")
      slice = workstation.succeed("systemctl --user -M alice@ show -P Slice ${conf.unit}").strip()
      assert slice == r"${conf.slice}", slice
      workstation.succeed(f"test -L {paseo_state}/nix/var/nix/gcroots/paseo")
      workstation.succeed("test -L /run/user/1000/agent-sandbox/paseo-store-roots")
      # Its own address; neither sandbox reaches the other's listener
      paseo4 = in_paseo("ip -4 -o addr show dev eth0").split()[3].split("/")[0]
      claude4 = in_sandbox("ip -4 -o addr show dev eth0").split()[3].split("/")[0]
      assert paseo4 != claude4, paseo4
      in_paseo("sh -c 'setsid python3 -m http.server 8000 >/dev/null 2>&1 </dev/null &'")
      in_sandbox("sh -c 'setsid python3 -m http.server 8001 >/dev/null 2>&1 </dev/null &'")
      workstation.wait_until_succeeds(paseo_cmd(tcp_connect(paseo4, 8000)), timeout=30)
      workstation.wait_until_succeeds(sandbox_cmd(tcp_connect(claude4, 8001)), timeout=30)
      workstation.fail(sandbox_cmd(tcp_connect(paseo4, 8000)))
      workstation.fail(paseo_cmd(tcp_connect(claude4, 8001)))
      workstation.fail(f"curl -sf -m3 http://{paseo4}:8000/")

  defaults = json.loads(workstation.succeed("cat ${../../home/paseo/config-defaults.json}"))
  with subtest("The state step: Paseo's defaults with dictation off, the permissions server and the doc for the agents"):
      files = agent_files(paseo_home)
      config = json.loads(files[".paseo/config.json"])
      want = json.loads(json.dumps(defaults))
      want.setdefault("features", {}).setdefault("dictation", {})["enabled"] = False
      assert config == want, config
      servers = json.loads(files[".claude.json"])["mcpServers"]
      assert servers == json.loads(${builtins.toJSON (builtins.toJSON paseo.mcpServers)}), servers
      assert list(servers) == ["permissions"], servers
      for f in files:
          mode = workstation.succeed(f"stat -c '%a %U' {paseo_home}/{f}").strip()
          assert mode == "600 alice", f"{f}: {mode}"
      # Codex's in its system config, a layer below the user's ~/.codex/config.toml: the servers with the keys Codex
      # takes, the doc inlined as developer_instructions. Nothing of the module's in the home
      codex = codex_config()
      want = {n: {k: v[k] for k in ["command", "args", "env"] if v.get(k) is not None} for n, v in servers.items()}
      assert codex["mcp_servers"] == want, codex
      agents = codex["developer_instructions"]
      assert agents.startswith("# Your environment: the Paseo sandbox\n"), agents[:200]
      assert "\n## Paseo\n" in agents, agents
      workstation.succeed(f"test ! -e {paseo_home}/.codex")

  with subtest("The state step again: unchanged on a second launch, the user's own entries kept on a third"):
      paseo_stop()
      paseo_launch()
      assert agent_files(paseo_home) == files, "a second launch changed the agents' files"
      paseo_stop()
      # The user's own, between launches: dictation turned on, a server of theirs and a key
      edit_home(
          "$jq '.features.dictation.enabled = true' .paseo/config.json >c && mv c .paseo/config.json;"
          " $jq '.mcpServers.mine = {command: \"/srv/bin/mine\"} | .theme = \"dark\"' .claude.json >c && mv c .claude.json"
      )
      paseo_launch()
      after = agent_files(paseo_home)
      config = json.loads(after[".paseo/config.json"])
      assert config["features"]["dictation"]["enabled"] is True, config
      assert config["daemon"] == defaults["daemon"], config
      claude = json.loads(after[".claude.json"])
      assert claude["theme"] == "dark" and list(sorted(claude["mcpServers"])) == ["mine", "permissions"], claude
      assert claude["mcpServers"]["permissions"] == servers["permissions"], claude

  record = f"{paseo_home}/.local/state/agent-sandbox/mcp-servers.json"
  with subtest("A ~/.claude.json the step can't merge stays as it was, with a warning, and the launch goes on"):
      paseo_stop()
      edit_home("cp .claude.json claude.json.good; head -c 20 claude.json.good >.claude.json")
      truncated = workstation.succeed(f"cat {paseo_home}/.claude.json")
      recorded = workstation.succeed(f"cat {record}")
      paseo_launch()
      assert workstation.succeed(f"cat {paseo_home}/.claude.json") == truncated, "the truncated ~/.claude.json changed"
      assert workstation.succeed(f"cat {record}") == recorded, "the record changed"
      warned = [l for l in journal("paseo", "-t paseo").splitlines()
                if "level=WARN" in l and f"Left {paseo_home}/.claude.json as it was" in l]
      assert warned, journal("paseo", "-t paseo")
      # Paseo's config.json, merged all the same
      assert json.loads(workstation.succeed(f"cat {paseo_home}/.paseo/config.json")) == config

  with subtest("A server of the user's by the module's name wins it, and the module's is back once it's gone"):
      paseo_stop()
      edit_home(
          "$jq '.mcpServers.permissions = {command: \"/srv/bin/theirs\"}' claude.json.good >.claude.json;"
          " rm claude.json.good"
      )
      paseo_launch()
      claude = json.loads(workstation.succeed(f"cat {paseo_home}/.claude.json"))
      assert claude["mcpServers"]["permissions"] == {"command": "/srv/bin/theirs"}, claude
      assert json.loads(workstation.succeed(f"cat {record}")) == {}, workstation.succeed(f"cat {record}")
      paseo_stop()
      edit_home("$jq 'del(.mcpServers.permissions)' .claude.json >c && mv c .claude.json")
      p = paseo_launch()
      claude = json.loads(workstation.succeed(f"cat {paseo_home}/.claude.json"))
      assert claude["mcpServers"] == {"mine": {"command": "/srv/bin/mine"}, "permissions": servers["permissions"]}, claude
      assert json.loads(workstation.succeed(f"cat {record}")) == {"permissions": servers["permissions"]}

  with subtest("Inside: the doc where Claude Code reads it, no agent CLI on PATH, a login shell's PATH"):
      assert in_paseo("cat /etc/claude-code/CLAUDE.md") == "@/etc/claude/environment.md\n"
      doc = in_paseo("cat /etc/claude/environment.md")
      imported = [l[1:] for l in doc.splitlines() if l.startswith("@")]
      assert len(imported) == 1, doc
      assert in_paseo(f"cat {imported[0]}").startswith("# Your environment: the Paseo sandbox\n")
      assert "\n## PATH\n" in doc, doc
      # The same doc Codex gets inlined
      assert agents.startswith(in_paseo(f"cat {imported[0]}")), agents[:300]
      # Claude Code and Codex are the consumer's to add
      for cli in ["claude", "codex"]:
          workstation.fail(paseo_cmd(f"sh -c {shlex.quote(f'command -v {cli}')}"))
          workstation.fail(paseo_cmd(f"bash -i -l -c {shlex.quote(f'command -v {cli}')}"))
      # What the app got, and what Paseo's login-shell merge ($SHELL -i -l -c) gives each agent: the module's PATH, then
      # the FHS env's /usr/bin and /usr/sbin, its /run/wrappers/bin gone
      module = "${paseo.env.PATH.value}"
      assert p["path"] == module + ":/usr/bin:/usr/sbin", p["path"]
      shell = in_paseo("printenv SHELL").strip()
      assert shell == "/run/current-system/sw/bin/bash", shell
      login = in_paseo(f"{shell} -i -l -c {shlex.quote('echo $PATH')}").strip().splitlines()[-1]
      assert login == module + ":/usr/bin:/usr/sbin", login

  with subtest("The agents' permissions server answers inside, as ~/.claude.json names it"):
      s = json.loads(in_paseo("cat /home/alice/.claude.json"))["mcpServers"]["permissions"]
      init = [
          {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
              "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "vm", "version": "0"}}},
          {"jsonrpc": "2.0", "method": "notifications/initialized"},
          {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
      ]
      lines = " ".join(shlex.quote(json.dumps(m)) for m in init)
      script = (f"(printf '%s\\n' {lines}; sleep 3) | {shlex.quote(s['command'])} "
                + " ".join(shlex.quote(a) for a in s.get("args", [])) + " 2>&1")
      for _ in range(20):
          out = workstation.execute(paseo_cmd(f"sh -c {shlex.quote(script)}"))[1]
          if '"name":"request"' in out:
              break
          time.sleep(3)
      else:
          raise Exception(f"No request tool from the permissions server: {out}")

  with subtest("Re-entry: a path, `paseo .` and a paseo:// link reach the first instance without the app root, --shell its namespaces"):
      before = paseo_log()
      ready = journal("paseo_sandbox").count("agent-sandbox: ready")
      # `paseo .` in a directory bound into the sandbox reaches the app as its absolute path (the wrapper's prelude)
      paseo_bin = "/etc/profiles/per-user/alice/bin/paseo"
      for cmd, arg in [
          (f"{paseo_bin} /srv/project", "/srv/project"),
          (f"cd /srv/project/sub && exec {paseo_bin} .", "/srv/project/sub"),
          (f"{paseo_bin} paseo://h/s/agent/a", "paseo://h/s/agent/a"),
      ]:
          as_alice("/run/current-system/sw/bin/sh -c " + shlex.quote(cmd))
          workstation.wait_until_succeeds(f"grep -qF {shlex.quote(json.dumps(arg))} {paseo_home}/paseo-stub.log", timeout=30)
          time.sleep(1)
          new = [e for e in paseo_log() if e not in before]
          before = paseo_log()
          # The second instance got the app root ahead of the caller's argument, the first doesn't see it
          second = [e for e in new if e["event"] == "second"]
          handed = [e for e in new if e["event"] == "second-instance"]
          assert [e["argv"] for e in second] == [[exe, root, "--no-sandbox", arg]], new
          assert [e["argv"] for e in handed] == [[exe, "--no-sandbox", arg]], new
          assert not [e for e in new if e["event"] == "start"], new
      assert journal("paseo_sandbox").count("agent-sandbox: ready") == ready, "a re-entry printed a ready line"
      reentry = in_paseo("readlink /proc/self/ns/net /proc/self/ns/pid /proc/self/ns/mnt").split()
      assert reentry == [p["net"], p["pidns"], p["mnt"]], f"re-entry in {reentry}, app in {p}"
      out = as_alice("/run/current-system/sw/bin/sh -c " + shlex.quote(
          "echo 'readlink /proc/self/ns/pid /proc/self/ns/mnt /proc/self/ns/net' | /etc/profiles/per-user/alice/bin/paseo --shell"
      )).split()
      assert out == [p["pidns"], p["mnt"], p["net"]], f"--shell in {out}, app in {p}"

  with subtest("The launcher work: its own app ID and sandbox, no paseo:// handler, no permissions server"):
      w = paseo_launch("paseo-work", work_home)
      assert w["desktopName"] == "sh.paseo.Paseo.work.desktop", w["desktopName"]
      assert w["argv"] == [exe, "${work.build.appRoot}", "--no-sandbox"], w["argv"]
      assert w["pid"] == ${toString workConf.appPid} and w["pid"] != p["pid"], w["pid"]
      assert w["net"] not in [p["net"], app_netns] and w["mnt"] not in [p["mnt"], app_mntns], w
      # /.flatpak-info of its proxy names its app ID, which names its .desktop file
      bwrap_info("${workConf.appId}")
      apps = "/etc/profiles/per-user/alice/share/applications"
      workstation.succeed(f"grep -qx StartupWMClass=${workConf.appId} {apps}/${workConf.appId}.desktop")
      handlers = workstation.succeed(f"grep -l '^MimeType=.*x-scheme-handler/paseo;' {apps}/*.desktop").split()
      assert handlers == [f"{apps}/sh.paseo.Paseo.desktop"], handlers
      workstation.succeed("systemctl --user -M alice@ is-active ${workConf.unit}")
      slice = workstation.succeed("systemctl --user -M alice@ show -P Slice ${workConf.unit}").strip()
      assert slice == r"${workConf.slice}", slice
      assert "agent-sandbox: ready" in journal("paseo-work_sandbox")
      # Without the broker: no server for the agents, Codex's config with the doc alone
      wf = agent_files(work_home)
      assert json.loads(wf[".claude.json"])["mcpServers"] == {}, wf[".claude.json"]
      wc = codex_config("paseo-work")
      assert wc.get("mcp_servers", {}) == {}, wc
      assert wc["developer_instructions"].startswith("# Your environment: the Paseo sandbox\n"), wc
      workstation.succeed(f"test ! -e {work_home}/.codex")
      # Its re-entry finds its own sandbox
      assert in_paseo("readlink /proc/self/ns/net", "paseo-work").strip() == w["net"]
''
