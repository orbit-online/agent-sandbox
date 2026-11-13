# The launcher work next to the default one, and its permissions broker
{
  pkgs,
  broker,
  brokerLive,
  workStateDir,
  mcpArgs,
  routerIP,
  routerIP6,
  workstationIP,
  mdnsQuery,
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
      # Its own netkit pair and addresses, from the launcher's name; neither sandbox reaches the other, nor the host
      # an ungranted port of either
      workstation.succeed(work_cmd("grep -qx 'nameserver ${routerIP}' /etc/resolv.conf"))
      addrs = {f("ip -o addr show dev eth0 scope global").split()[3].split("/")[0] for f in [in_sandbox, in_work]}
      assert len(addrs) == 2, addrs
      work4 = in_work("ip -4 -o addr show dev eth0").split()[3].split("/")[0]
      in_work("sh -c 'setsid python3 -m http.server 8000 >/dev/null 2>&1 </dev/null &'")
      probe = tcp_connect(work4, 8000)
      workstation.wait_until_succeeds(work_cmd(probe), timeout=30)
      workstation.fail(sandbox_cmd(probe))
      workstation.fail(f"curl -sf -m3 http://{work4}:8000/")
      # Its own state dir, with ~/.claude and the app's config in its home
      workstation.succeed(f"test -d {work_home}/.claude && test -s {work_home}/.config/Claude/claude_desktop_config.json")
      workstation.succeed("test -L ${workStateDir}/nix/var/nix/gcroots/claude-desktop")
      workstation.succeed("test -L /run/user/1000/claude-desktop/store-roots-work")

  with subtest("mDNS: queries of the default sandbox out, responses in; work, without mDNS, neither"):
      app_ns = f"nsenter -t {bwrap_info()['child-pid']} -n ${mdnsQuery}"
      work_net = f"nsenter -t {bwrap_info('com.anthropic.Claude.work')['child-pid']} -n"
      work_ns = f"{work_net} ${mdnsQuery}"
      router.wait_for_unit("avahi-daemon.service")
      router.succeed("systemd-run --unit=mdns-cap -p StandardError=truncate:/tmp/mdns-cap.err"
                     " tcpdump -U -ni eth1 -w /tmp/mdns.pcap udp port 5353")
      # From when tcpdump has its filter attached
      router.wait_until_succeeds("grep -q 'listening on' /tmp/mdns-cap.err", timeout=30)
      # work listens throughout, over IPv4 and IPv6, and asks for itself
      workstation.succeed(f"systemd-run --unit=work-mdns -p StandardOutput=file:/tmp/work-mdns {work_ns} 4 query work.local 8",
                          f"systemd-run --unit=work-mdns6 -p StandardOutput=file:/tmp/work-mdns6 {work_ns} 6 query work6.local 8")
      # Both bound before anything is sent to them
      workstation.wait_until_succeeds(f"{work_net} ss -H -4 -lun 'sport = :5353' | grep -q . && {work_net} ss -H -6 -lun 'sport = :5353' | grep -q .", timeout=10)
      # The answers, by multicast to the querier on port 5353 in the sandbox
      for fam, want in [("4", "${routerIP}"), ("6", "${routerIP6}")]:
          out = workstation.succeed(f"{app_ns} {fam} query printer.local 3").split()
          assert want in out, f"IPv{fam}: {out}"
      # A one-shot query from another port leaves from port 5353 too
      workstation.succeed(f"{app_ns} 4 query oneshot.local 0 eth0 0")
      # A response and a probe of the sandbox stay in
      workstation.succeed(f"{app_ns} 4 respond claim.local 0", f"{app_ns} 4 probe claim.local 0",
                          f"{app_ns} 6 respond claim.local 0")
      # A GSO datagram of a query and a response segment stays in whole, and so does a query with bytes past its IP
      # length; the same query without them leaves
      workstation.succeed(f"{app_ns} 4 gso gso-segmented-query.local 0", f"{app_ns} 4 rawtrail trailing.local 0",
                          f"{app_ns} 4 raw rawquery.local 0")
      # A query from the LAN doesn't come in
      workstation.succeed(f"systemd-run --unit=app-mdns -p StandardOutput=file:/tmp/app-mdns {app_ns} 4 listen x 4",
                          "sleep 1")
      router.succeed("${mdnsQuery} 4 query lan.local 0 eth1")
      workstation.wait_until_fails("systemctl is-active app-mdns", timeout=10)
      workstation.wait_until_fails("systemctl is-active work-mdns", timeout=15)
      workstation.wait_until_fails("systemctl is-active work-mdns6", timeout=15)
      for out in ["app-mdns", "work-mdns", "work-mdns6"]:
          assert workstation.succeed(f"cat /tmp/{out}").strip() == "", workstation.succeed(f"cat /tmp/{out}")
      router.succeed("systemctl stop mdns-cap")
      lan = router.succeed("tcpdump -nr /tmp/mdns.pcap 2>/dev/null")
      print(lan)
      ws_lines = [l for l in lan.splitlines() if "printer.local" in l and " > " in l and "?" in l]
      # From the workstation address and port 5353, the unicast-response bit cleared
      assert any("${workstationIP}.5353 > 224.0.0.251.5353" in l for l in ws_lines), ws_lines
      assert any(re.search(r"fe80::\S+\.5353 > ff02::fb\.5353", l) for l in ws_lines), ws_lines
      assert not any("(QU)" in l for l in ws_lines), ws_lines
      assert any("${workstationIP}.5353 > 224.0.0.251.5353" in l and "oneshot.local" in l for l in lan.splitlines()), lan
      assert "lan.local" in lan and "rawquery.local" in lan, lan
      # Nothing of the response and probe, of the GSO datagram or the query with trailing bytes, of work, or from a
      # sandbox address
      for leak in ["claim.local", "gso-segmented", "smuggled.local", "trailing.local", "work.local", "work6.local", " 169.254.10",
                   " fd"]:
          assert leak not in lan, leak
      # Only the default primary takes responses
      mdns = workstation.succeed("bpftool -j map dump pinned /run/sandbox-uplink/mdns")
      ifindex = workstation.succeed("cat /sys/class/net/sbx-rs-e3b0c442/ifindex").strip()
      assert [int.from_bytes(bytes(int(x, 16) for x in e["key"]), "little") for e in json.loads(mdns)] == [int(ifindex)], mdns

  with subtest("mDNS: queries out at MDNS_RATE (10) a second after a burst of MDNS_BURST (20)"):
      router.succeed("systemd-run --unit=mdns-burst -p StandardError=truncate:/tmp/mdns-burst.err"
                     " tcpdump -U -ni eth1 -w /tmp/burst.pcap udp port 5353")
      router.wait_until_succeeds("grep -q 'listening on' /tmp/mdns-burst.err", timeout=30)
      burst = ("import socket, struct; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
               "for i in range(100): s.sendto(struct.pack('!6H', 0, 0, 1, 0, 0, 0) + bytes([len(n := f'burst{i}'.encode())]) + n"
               " + b'\\x05local\\x00' + struct.pack('!2H', 1, 1), ('224.0.0.251', 5353))")
      workstation.succeed(f"nsenter -t {bwrap_info()['child-pid']} -n ${pkgs.python3}/bin/python3 -c {shlex.quote(burst)}")
      time.sleep(1)
      router.succeed("systemctl stop mdns-burst")
      sent = len(re.findall(r"burst\d+\.local", router.succeed("tcpdump -nr /tmp/burst.pcap 2>/dev/null")))
      print(f"{sent} of 100 queries left")
      assert 15 <= sent <= 30, sent

  with subtest("Each launcher's notifications name an app with a .desktop file of that name"):
      # The portal names a notification's app by the caller's /.flatpak-info, and gnome-shell drops it unless
      # <app>.desktop exists; that file's StartupWMClass puts the app's windows under it
      apps = "/etc/profiles/per-user/alice/share/applications"
      for run, launcher, app_id in [(in_sandbox, "default", "com.anthropic.Claude"),
                                    (in_work, "work", "com.anthropic.Claude.work")]:
          run(f"notify-send hello-from-{launcher}")
          workstation.wait_until_succeeds(f"grep -q hello-from-{launcher} /run/user/1000/fake-portal-notifications", timeout=30)
          sent = json.loads(workstation.succeed(f"grep hello-from-{launcher} /run/user/1000/fake-portal-notifications"))
          assert sent["app"] == app_id, f"the portal saw {launcher}'s notification come from {sent}"
          workstation.succeed(f"grep -qx StartupWMClass={app_id} {apps}/{app_id}.desktop")

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
      assert str(bwrap_info("com.anthropic.Claude.work")["child-pid"]) in sandbox_procs, sandbox_procs
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
      # The app's, and the one its systemd --user starts in (its own below it)
      dirs = sorted(in_work("find /sys/fs/cgroup -mindepth 1 -maxdepth 1 -type d").split())
      assert dirs == ["/sys/fs/cgroup/app", "/sys/fs/cgroup/user"], dirs
      top = [l.split() for l in in_work("cat /proc/self/mountinfo").splitlines() if l.split()[4] == "/sys/fs/cgroup"][-1]
      assert top[3] == "/" and "rw" in top[5].split(","), top
      # The host's cgroup2 with nsdelegate, which systemd sets, so the launcher bound it writable
      flags = workstation.succeed("grep -m1 ' - cgroup2 ' /proc/self/mountinfo").split()[-1]
      assert "nsdelegate" in flags.split(","), flags
      # The caps on the sandbox's cgroups on the unit's: 64 below sandbox/, 4 deep, which the sandbox has no path to
      caps = [workstation.succeed(f"cat '{unit_root}/cgroup.max.{f}'").strip() for f in ["descendants", "depth"]]
      assert caps == ["66", "5"], caps

  with subtest("systemd-run --scope runs a job in a cgroup of its own, killed past its memory limit while the app runs on"):
      job = "systemd-run --user --scope --quiet -p MemoryMax=64M -p MemorySwapMax=0 -p CPUWeight=50 -p OOMPolicy=kill"
      out = in_work(f"{job} -- sh -c 'cat /proc/self/cgroup; cd /sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup) && cat memory.max cpu.weight'")
      cg, limit, weight = out.split()
      assert re.fullmatch(r"0::/user/app\.slice/run-[^/]+\.scope", cg) and limit == str(64 << 20) and weight == "50", out
      # The launcher's slice below app.slice's
      assert workstation.succeed(f"cat '/sys/fs/cgroup{work_slice}/cpu.weight'").strip() == "50"
      # One process, so the OOM kill is what ends it: with a pipeline the scope stopping after the kill could end the
      # shell with SIGTERM first (exit 143)
      out = in_work(f"sh -c '{job} -- dd if=/dev/zero of=/dev/null bs=512M count=1; echo exit=$?'")
      assert out.strip().splitlines()[-1] == "exit=137", out
      # What it leaves running ends with a stop of its scope (environment.md)
      in_work("sh -c 'systemd-run --user --scope --quiet --unit=job -- sh -c \"sleep 600 & exit 0\" && systemctl --user stop job.scope'")
      status, out = workstation.execute(work_cmd("pgrep -x sleep"))
      assert status != 0, out
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
      # own, shows its own cgroup's subtree and nothing above it
      refused("unshare --user --map-current-user --mount umount /sys/fs/cgroup")
      fresh_cgroup2_mount(in_work, unit_root)
      # At most 64 cgroups below its root, app/ and its systemd --user's included
      out = in_work("sh -c 'n=0; while [ $n -lt 80 ] && mkdir /sys/fs/cgroup/d$n 2>/dev/null; do n=$((n + 1)); done;"
                    " find /sys/fs/cgroup -mindepth 1 -type d | wc -l; rmdir /sys/fs/cgroup/d*'")
      assert out.strip() == "64", f"{out.strip()} cgroups"
      # At most 4 levels below its root
      out = in_work("sh -c 'mkdir -p /sys/fs/cgroup/a/b/c/d && echo 4; mkdir /sys/fs/cgroup/a/b/c/d/e 2>/dev/null && echo 5;"
                    " rmdir /sys/fs/cgroup/a/b/c/d/e 2>/dev/null;"
                    " rmdir /sys/fs/cgroup/a/b/c/d /sys/fs/cgroup/a/b/c /sys/fs/cgroup/a/b /sys/fs/cgroup/a'")
      assert out.split() == ["4"], f"made {out.split()} levels"
      # nsdelegate guards only the root of the writer's own cgroup namespace: from a nested one, rooted at app/, the
      # sandbox lifts sandbox/'s caps, and the unit's still hold
      nested = ("echo max >/sys/fs/cgroup/cgroup.max.descendants && echo max >/sys/fs/cgroup/cgroup.max.depth && echo lifted;"
                " n=0; while [ $n -lt 80 ] && mkdir /sys/fs/cgroup/d$n 2>/dev/null; do n=$((n + 1)); done;"
                " find /sys/fs/cgroup -mindepth 1 -type d | wc -l;"
                " rmdir /sys/fs/cgroup/d*; mkdir -p /sys/fs/cgroup/a/b/c/d && echo 4; mkdir /sys/fs/cgroup/a/b/c/d/e 2>/dev/null && echo 5;"
                " rmdir /sys/fs/cgroup/a/b/c/d/e 2>/dev/null;"
                " rmdir /sys/fs/cgroup/a/b/c/d /sys/fs/cgroup/a/b/c /sys/fs/cgroup/a/b /sys/fs/cgroup/a")
      out = in_work("unshare --user --map-root-user --cgroup sh -c " + shlex.quote(nested))
      assert out.split() == ["lifted", "64", "4"], out

  with subtest("The work launcher's broker"):
      # The permissions broker: its daemon runs, its grant directory is read-only inside, shared in the sandbox's
      # outer mount namespace before the FHS env's bwrap copied it, so a slave where the app runs
      workstation.wait_until_succeeds("systemctl --user -M alice@ is-active claude-desktop-work-permissions", timeout=60)
      # Restarted on failure, but not forever when it never finds a sandbox
      limit = workstation.succeed(
          "systemctl --user -M alice@ show -p StartLimitBurst -p StartLimitIntervalUSec claude-desktop-work-permissions"
      ).split()
      assert sorted(limit) == ["StartLimitBurst=3", "StartLimitIntervalUSec=10min"], f"start limit {limit}"
      work_pid = bwrap_info("com.anthropic.Claude.work")["child-pid"]
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
      # server's from its start, called without asking and told its maxValidity, the host socket and a port
      make_folders()
      start_echo()
      standing = {g["capability"]: g["id"] for g in control({"op": "state"}, tries=30)["grants"] if g["lease"] == "standing"}
      assert sorted(standing) == ["echo", "port", "test"], f"standing grants {standing}"
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

      # Ports: the standing one reached from the host from the start; another refused until Claude asks and the user
      # allows it, then reached at the addresses the grant names, and refused again once revoked, with the standing
      # one's, its flows gone
      work6 = in_work("ip -6 -o addr show dev eth0 scope global").split()[3].split("/")[0]
      for p in (8001, 8081):
          in_work(f"sh -c 'setsid python3 -m http.server {p} --bind :: >/dev/null 2>&1 </dev/null &'")
          workstation.wait_until_succeeds(work_cmd(tcp_connect("::1", p)), timeout=30)
      # As alice: the ports of her sandbox take her processes alone
      curl = lambda a, p: f"runuser -u alice -- curl -gsf -m5 -o /dev/null http://{a}:{p}/"
      workstation.succeed(curl(work4, 8081), curl(f"[{work6}]", 8081))
      workstation.fail(curl(work4, 8001), curl(f"[{work6}]", 8001))
      granted("port", "port", {"port": 8001, "protocol": "tcp"}, f"[{work6}]:8001")
      out = workstation.succeed(f"cat {work_home}/port.out")
      assert f"{work4}:8001" in out, f"the grant's addresses: {out}"
      ports = {g["params"]["port"]: g for g in control({"op": "state"})["grants"] if g["capability"] == "port"}
      assert ports[8001]["addresses"] == [f"{work4}:8001", f"[{work6}]:8001"], ports
      workstation.succeed(curl(work4, 8001), curl(f"[{work6}]", 8001))
      flows = lambda: json.loads(workstation.succeed("bpftool -j map dump pinned /run/sandbox-uplink/1000-work/flows"))
      assert flows(), "no flow recorded"
      for p in (8001, 8081):
          control({"op": "revoke", "grant": ports[p]["id"]})
          workstation.fail(curl(work4, p), curl(f"[{work6}]", p))
      assert not flows(), f"flows left: {flows()}"
      # A UDP port the same way: a datagram of a connected socket of alice echoed once granted, over IPv4 and IPv6, and
      # not once revoked
      echo = ("import socket; s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.bind(('::', 5301));"
              " [s.sendto(d, a) for d, a in iter(lambda: s.recvfrom(64), None)]")
      in_work(f"sh -c {shlex.quote(f'setsid python3 -c {shlex.quote(echo)} >/dev/null 2>&1 </dev/null &')}")
      ping = shlex.quote("import socket, sys; c = socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET,"
                         " socket.SOCK_DGRAM); c.settimeout(3); c.connect((sys.argv[1], 5301)); c.send(b'ping');"
                         " assert c.recv(9) == b'ping'")
      udp = lambda a: f"runuser -u alice -- ${pkgs.python3.interpreter} -c {ping} {a}"
      workstation.wait_until_succeeds(work_cmd(f"python3 -c {ping} ::1"), timeout=30)
      workstation.fail(udp(work4), udp(work6))
      granted("udp", "port", {"port": 5301, "protocol": "udp"}, f"{work4}:5301")
      workstation.succeed(udp(work4), udp(work6))
      udp_grant = next(g for g in control({"op": "state"})["grants"] if g["params"] == {"port": 5301, "protocol": "udp"})
      control({"op": "revoke", "grant": udp_grant["id"]})
      workstation.fail(udp(work4), udp(work6))
      # Granted again, for the crash below to end
      granted("port2", "port", {"port": 8001, "protocol": "tcp"}, f"[{work6}]:8001")
      workstation.succeed(curl(work4, 8001))

      # A crash ends the daemon's grants: ExecStopPost detaches the folder, revokes the ports, and its connections
      # close with it. Started again, it has its standing grants alone, the revoked ones too, under new ids. The
      # new daemon revokes the ports as it starts as well: the line of ExecStopPost in the journal of the unit (those
      # of the daemon go to the journal namespace of the launcher) says it did first
      revoked = ("journalctl _SYSTEMD_USER_UNIT=claude-desktop-work-permissions.service -o cat"
                 " | grep -c 'Revoked the ports' || true")
      revoked_before = int(workstation.succeed(revoked))
      folder = grants[0].split()[4]
      hold("crashed")
      stop_post = workstation.succeed("systemctl --user -M alice@ show -P ExecStopPost claude-desktop-work-permissions")
      assert " cleanup " in stop_post, f"ExecStopPost {stop_post!r}"
      workstation.succeed("systemctl --user -M alice@ kill --signal=SIGKILL claude-desktop-work-permissions")
      workstation.wait_until_succeeds(f"test -s {work_home}/crashed.exit", timeout=30)
      workstation.wait_until_succeeds(work_cmd(f"sh -c '! grep -q \" {folder} \" /proc/self/mountinfo'"), timeout=30)
      workstation.wait_until_succeeds("systemctl --user -M alice@ is-active -q claude-desktop-work-permissions", timeout=30)
      workstation.wait_until_succeeds(f"[ $({revoked}) -eq {revoked_before + 1} ]", timeout=10)
      state = control({"op": "state"}, tries=30)
      again = {g["capability"]: g["id"] for g in state["grants"] if g["lease"] == "standing"}
      assert sorted(again) == ["echo", "port", "test"] and len(state["grants"]) == 3, f"grants after a restart: {state}"
      assert not set(again.values()) & set(standing.values()), f"the same ids after a restart: {again}"
      # The window's overview of the configuration
      assert state["overview"]["network"] and any(b["path"] == "/home/alice" for b in state["overview"]["binds"]), state["overview"]
      out = in_work(f"sh -c {shlex.quote('echo ping | timeout 10 ' + connect)}")
      assert out.strip() == "ping", f"the standing grant back after a restart: {out!r}"
      workstation.succeed(curl(work4, 8081))
      workstation.fail(curl(work4, 8001))

      # No system bus inside: D-Bus grants and the system-bus proxy aren't built (docs/permissions.md, D-Bus)
      status, _ = workstation.execute(work_cmd("test -e /run/dbus/system_bus_socket"))
      assert status != 0, "the work sandbox has a system bus socket"

      # The Permissions window starts on the host against the running daemon, its Qt kept from the host's plugins.
      # Offscreen, as the VM has no compositor alice could show it on: still up after five seconds. Its app ID, the
      # Wayland app_id and WM_CLASS it takes, is the launcher's, so it shows under the launcher's .desktop file
      workstation.succeed("systemd-run --user -M alice@ --unit permissions-window -E QT_QPA_PLATFORM=offscreen --"
                          " /run/current-system/sw/bin/timeout 5 /etc/profiles/per-user/alice/bin/claude-desktop-work --permissions")
      window_args = workstation.wait_until_succeeds(
          "for p in /proc/[0-9]*; do case $(readlink $p/exe) in */bin/.permissions-window-wrapped)"
          " tr '\\0' '\\n' <$p/cmdline; exit 0;; esac; done; exit 1", timeout=30).splitlines()
      assert "--app-id=com.anthropic.Claude.work" in window_args, window_args
      workstation.wait_until_fails("systemctl --user -M alice@ is-active permissions-window", timeout=30)
      status = workstation.succeed("systemctl --user -M alice@ show -P ExecMainStatus permissions-window").strip()
      assert status == "124", f"the Permissions window ended before its timeout: {status}"

  with subtest("The work sandbox ends with its unit"):
      workstation.succeed("systemctl --user -M alice@ kill --kill-whom=main claude-desktop-work-app")
      workstation.wait_until_fails(f"test -e /proc/{work_pid}", timeout=30)
      # The daemon ends with its sandbox
      workstation.wait_until_fails("systemctl --user -M alice@ is-active claude-desktop-work-permissions", timeout=30)
      # The default sandbox runs on
      assert in_sandbox("readlink /proc/self/ns/net").strip() == app_netns
''
