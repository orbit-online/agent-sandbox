# The sandbox on a booted NixOS: alice's claude-desktop (the stub app) on a workstation whose LAN has a router with
# DHCP and DNS. The router also stands in for the internet: its DNS points api.anthropic.com and github.com at itself.
{
  pkgs,
  aliceModule,
  broker,
}:
let
  # A service plugin's serve: MCP on the socket systemd hands it, one tool, echo
  echoServe = pkgs.writers.writePython3 "echo-serve" { flakeIgnore = [ "E501" ]; } ''
    import json
    import socket

    listener = socket.socket(fileno=3)


    def handle(conn):
        with conn, conn.makefile("rw") as f:
            for line in f:
                msg = json.loads(line)
                if "id" not in msg:
                    continue
                method, params = msg.get("method"), msg.get("params") or {}
                if method == "initialize":
                    result = {"protocolVersion": params.get("protocolVersion"), "capabilities": {"tools": {}},
                              "serverInfo": {"name": "echo", "version": "0"}}
                elif method == "tools/list":
                    result = {"tools": [{"name": "echo", "description": "Echoes.",
                                         "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}]}
                elif method == "tools/call":
                    text = (params.get("arguments") or {}).get("text", "")
                    result = {"content": [{"type": "text", "text": "echo: " + text}]}
                else:
                    f.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": method}}) + "\n")
                    f.flush()
                    continue
                f.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
                f.flush()


    while True:
        handle(listener.accept()[0])
  '';
  # Plugins for the permissions broker: a command whose run prints the validity it was given, and a service with tools
  testPlugin = pkgs.writeTextDir "share/agent-sandbox/permissions/test.json" (
    builtins.toJSON {
      name = "test";
      capabilities = [
        {
          name = "thing";
          type = "command";
          description = "a test command";
          run = [
            (pkgs.writeShellScript "run" "echo issued-$(${pkgs.lib.getExe pkgs.jq} -r .validity)")
          ];
        }
        {
          name = "echo";
          type = "service";
          description = "a test service";
          serve = [ "${echoServe}" ];
          tools = true;
        }
      ];
    }
  );
  # The broker's test binary, for TestLiveMachine (cmd/permissions-broker/live_test.go): the state machine tests
  # against the live daemon and sandbox
  brokerLive = broker.overrideAttrs {
    pname = "permissions-broker-live";
    doCheck = false;
    buildPhase = ''
      runHook preBuild
      go test -c -o permissions-broker-live ./cmd/permissions-broker
      runHook postBuild
    '';
    installPhase = ''
      runHook preInstall
      install -Dm755 permissions-broker-live $out/bin/permissions-broker-live
      runHook postInstall
    '';
    # The broker's wraps bin/permissions-broker, which this lacks. Unwrapped: the test runs copies named claude and node
    postInstall = "";
  };
  stateDir = "/home/alice/.local/share/claude-desktop";
  sandboxHome = "${stateDir}/home";
  scratchpad = "${stateDir}/tmp-scratchpad";
  workStateDir = "/home/alice/.local/share/claude-desktop-work";
  stub = pkgs.callPackage ./stub-app.nix { };
  fakePortal = pkgs.writers.writePython3Bin "fake-portal" {
    libraries = [ pkgs.python3Packages.dbus-next ];
    # dbus-next's signatures are string annotations
    flakeIgnore = [
      "F722"
      "F821"
      "E501"
    ];
  } (builtins.readFile ./fake-portal.py);
in
pkgs.testers.runNixOSTest {
  name = "claude-desktop";

  nodes.router =
    { nodes, ... }:
    {
      networking.firewall.enable = false;
      services.dnsmasq = {
        enable = true;
        resolveLocalQueries = false;
        settings = {
          interface = "eth1";
          no-resolv = true;
          dhcp-range = "192.168.1.100,192.168.1.200,1h";
          address = map (d: "/${d}/${nodes.router.networking.primaryIPAddress}") [
            "api.anthropic.com"
            "github.com"
          ];
        };
      };
      systemd.services.https = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 443 --directory /var/empty";
      };
    };

  nodes.workstation =
    { nodes, ... }:
    {
      imports = [
        (aliceModule {
          enable = true;
          package = stub;
          tray = true;
          # Missing until the launch subtest creates it
          binds."/srv/project" = { };
          # Under /etc, which the FHS env doesn't take from nixpak's binds, and in the sandbox's home. Each references what
          # the sandbox lacks otherwise
          files =
            pkgs.lib.genAttrs [ "/etc/agent-sandbox-test/hello" "/home/alice/.config/agent-sandbox-test/hello" ]
              (_: {
                source = pkgs.writeShellScript "hello" "exec ${pkgs.lib.getExe pkgs.hello}";
              });
          launchers.work = {
            package = stub;
            tray = true;
            permissions = {
              enable = true;
              # Made by the subtest, before the launch
              folders = [
                { path = "/srv/notes"; }
                { path = "/srv/mounted"; }
              ];
              plugins.test = {
                package = testPlugin;
                ceiling.maxValidity = "PT8H";
              };
            };
          };
        })
      ];
      virtualisation = {
        memorySize = 2048;
        # The store syncs copy the sandbox closure (graphics drivers included) into alice's home, once per launcher
        diskSize = 12288;
      };
      # netns-macvlan puts the macvlan on the default route's device
      networking.defaultGateway = nodes.router.networking.primaryIPAddress;
      # So the macvlan's isolation is what blocks the sandbox, not the firewall
      networking.firewall.enable = false;
      # A host-only name, which the sandbox's own hosts file leaves out
      networking.hosts."127.0.0.1" = [ "host-only.test" ];
      users.users.alice.linger = true;
      users.users.bob.isNormalUser = true;
      home-manager.useUserPackages = true;
      environment.systemPackages = [ pkgs.libcap ];
      # A host service for the sandbox to miss, on the LAN address, loopback and dummy0 (setup in the test script)
      systemd.services.listener = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 80 --directory /var/empty";
      };
    };

  testScript =
    { nodes, ... }:
    let
      routerIP = nodes.router.networking.primaryIPAddress;
      workstationIP = nodes.workstation.networking.primaryIPAddress;
    in
    ''
      import json, os, shlex, time

      scratchpad = "${scratchpad}"

      def alice_cmd(cmd):
          return f"systemd-run --user -M alice@ --wait --pipe --quiet -- {cmd}"

      def as_alice(cmd):
          return workstation.succeed(alice_cmd(cmd))

      # cmd in alice's running sandbox, through the wrapper's claude:// re-entry and the stub's --exec
      def sandbox_cmd(cmd):
          return alice_cmd(f"/etc/profiles/per-user/alice/bin/claude-desktop --exec {cmd}")

      def in_sandbox(cmd):
          return workstation.succeed(sandbox_cmd(cmd))

      # Not setpriv: it keeps root's capabilities through the exec permission check
      def as_user(user, cmd):
          return workstation.execute(f"runuser -u {user} -- {cmd} 2>&1")

      def as_bob(cmd):
          return as_user("bob", cmd)

      # Runs a sleep as `user` in a transient service (in the netns of `netns_pid` if given) and returns its pid.
      # Not setpriv: it keeps root's capabilities until the exec, which leaves the process undumpable, so the
      # kernel's ptrace check on /proc/<pid>/ns/net would refuse bob before netns-macvlan's own checks do
      def spawn(unit, user, cmd="", netns_pid=None):
          netns = f"-p NetworkNamespacePath=/proc/{netns_pid}/ns/net" if netns_pid else ""
          workstation.succeed(
              f"systemd-run --unit {unit} -p User={user} {netns} -- {cmd} /run/current-system/sw/bin/sleep infinity"
          )
          pid = f"$(systemctl show -P MainPID {unit})"
          # Not comm: coreutils is one binary, so that reads coreutils
          workstation.wait_until_succeeds(f"grep -qz '^/run/current-system/sw/bin/sleep$' /proc/{pid}/cmdline", timeout=30)
          return workstation.succeed(f"echo {pid}").strip()

      # The info of a running sandbox's bwrap, found by its app ID: the work launcher's lies next to the default one's
      def bwrap_info(app_id="com.nixpak.ClaudeDesktop"):
          d = workstation.succeed(f"grep -lx name={app_id} /run/user/1000/.flatpak/nixpak-app-*/info").split()[-1]
          return json.loads(workstation.succeed(f"cat {d.removesuffix('/info')}/bwrapinfo.json"))

      start_all()
      router.wait_for_unit("dnsmasq.service")
      router.wait_for_unit("https.service")
      workstation.wait_for_unit("home-manager-alice.service")
      workstation.wait_for_unit("user@1000.service")
      workstation.wait_for_unit("listener.service")

      host_only = ["${workstationIP}:80", "127.0.0.1:80", "10.99.0.1:80"]
      with subtest("host-only targets answer on the host"):
          workstation.succeed("ip link add dummy0 type dummy && ip addr add 10.99.0.1/24 dev dummy0 && ip link set dummy0 up")
          for t in host_only:
              workstation.succeed(f"curl -sf http://{t}/")

      with subtest("setcap wrapper"):
          workstation.succeed("getcap /run/wrappers/bin/netns-macvlan | grep -q cap_net_admin=ep")
          # System users can't run it, only group users
          status, out = as_user("nobody", "/run/wrappers/bin/netns-macvlan 1")
          assert status != 0 and "Permission denied" in out, f"nobody ran the wrapper: {status} {out}"

      # alice's own files, which links the sandbox planted in its state point at
      # c parses as a keyfile, so gsettings would carry its group into the sandbox's
      victims = {"a": "secret-a", "b": "secret-b", "c": "[secret-c]", "json": '{"secret": 1}'}
      planted = {
          "${sandboxHome}/.config/user-dirs.dirs": "a",
          "${sandboxHome}/.config/resolv.conf": "new",
          "${sandboxHome}/.config/glib-2.0/settings/keyfile": "c",
          # The default launcher binds ~/.config/Claude from the host
          "/home/alice/.config/Claude/claude_desktop_config.json": "json",
          "/home/alice/.config/Claude/claude_desktop_config.json.tmp": "b",
      }

      def victims_untouched():
          for name, content in victims.items():
              got = workstation.succeed(f"cat /home/alice/victim-{name}").strip()
              assert got == content, f"victim-{name} holds {got!r}"
          workstation.fail("test -e /home/alice/victim-new")
          assert workstation.succeed("ls -A /home/alice/victim-store") == "", "the store sync wrote to the host"

      with subtest("the launcher doesn't follow links the sandbox planted in its state"):
          # As the sandbox could leave them between launches. Its store dir as a link would have nixpak bind what it
          # points to on the host
          for name, content in victims.items():
              as_alice(f"/run/current-system/sw/bin/sh -c {shlex.quote(f'echo {shlex.quote(content)} >/home/alice/victim-{name}')}")
          as_alice("/run/current-system/sw/bin/mkdir -p /home/alice/victim-store ${stateDir}/nix ${sandboxHome}/.config/glib-2.0/settings /home/alice/.config/Claude")
          for link, name in planted.items():
              as_alice(f"/run/current-system/sw/bin/ln -s /home/alice/victim-{name} {link}")
          as_alice("/run/current-system/sw/bin/ln -s /home/alice/victim-store ${stateDir}/nix/store")
          status, out = workstation.execute(
              "systemd-run --user -M alice@ --wait --pipe --quiet -p RuntimeMaxSec=600"
              " -- /etc/profiles/per-user/alice/bin/claude-desktop 2>&1"
          )
          assert status != 0 and "nix/store is a link" in out, f"{status} {out}"
          victims_untouched()
          as_alice("/run/current-system/sw/bin/rm ${stateDir}/nix/store")

      with subtest("launch"):
          workstation.succeed("systemd-run --user -M alice@ --unit fake-portal -- ${pkgs.lib.getExe fakePortal}")
          workstation.wait_until_succeeds(alice_cmd(
              "${pkgs.lib.getExe' pkgs.glib "gdbus"} call --session --dest org.freedesktop.portal.Desktop"
              " --object-path /org/freedesktop/portal/desktop --method org.freedesktop.portal.Settings.ReadOne"
              " org.freedesktop.appearance color-scheme"
          ))
          # A bind that isn't optional, with its source missing. The launch syncs the store first. RuntimeMaxSec:
          # without the check it starts the app, and --wait would wait on it
          status, out = workstation.execute(
              "systemd-run --user -M alice@ --wait --pipe --quiet -p RuntimeMaxSec=600"
              " -- /etc/profiles/per-user/alice/bin/claude-desktop 2>&1"
          )
          assert status != 0 and "Bind source /srv/project is missing" in out, f"{status} {out}"
          workstation.succeed("mkdir /srv/project")
          # KillMode=process: like a desktop's app scope, ending the app leaves the rest alone
          workstation.succeed(
              "systemd-run --user -M alice@ --unit claude-desktop -p KillMode=process -E WAYLAND_DISPLAY=wayland-0"
              " -- /etc/profiles/per-user/alice/bin/claude-desktop"
          )
          workstation.wait_until_succeeds("test -s ${sandboxHome}/stub-app.log", timeout=300)
          workstation.succeed("test -L /home/alice/.local/share/claude-desktop/nix/var/nix/gcroots/claude-desktop")
          workstation.succeed("test -d /home/alice/.claude")
          app_pid, app_netns, app_mntns, app_pidns, app_caps, app_bus = (
              workstation.succeed("cat ${sandboxHome}/stub-app.log").split()
          )
          # The proxy let it own the tray item's name with its pid in it, which app-pid.sh set
          assert app_bus == "1", f"the app (pid {app_pid}) didn't get StatusNotifierItem-{app_pid}-1: {app_bus}"
          # app-pid.sh dropped the FHS env's CAP_CHECKPOINT_RESTORE
          assert app_caps == "0000000000000000", f"the app has capabilities {app_caps}"
          assert app_netns != as_alice("/run/current-system/sw/bin/readlink /proc/self/ns/net").strip(), "the app runs in the host's netns"

      with subtest("D-Bus reaches the portal's notifications and the tray's calls, nothing else of Plasma's"):
          gdbus = "${pkgs.lib.getExe' pkgs.glib "gdbus"}"

          def bus_call(dest, path, method, *args):
              q = " ".join(shlex.quote(a) for a in args)
              return workstation.execute(sandbox_cmd(
                  f"{gdbus} call --session --dest {dest} --object-path {path} --method {method} {q}"
              ) + " 2>&1")

          # Notifications go through the portal (libnotify with NOTIFY_FORCE_PORTAL, as the app's Electron), never to
          # the notification server, where the sandbox could replace or close the permissions broker's
          in_sandbox("notify-send hello-portal")
          workstation.wait_until_succeeds("grep -q hello-portal /run/user/1000/fake-portal-notifications", timeout=30)
          status, out = bus_call("org.freedesktop.Notifications", "/org/freedesktop/Notifications",
                                 "org.freedesktop.Notifications.Notify", "test", "uint32 0", "", "summary", "body",
                                 "@as []", "@a{sv} {}", "int32 -1")
          assert status != 0 and "uint32 7" not in out, f"Notify on the notification server: {status} {out}"
          shell = as_alice(f"{gdbus} call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus"
                           " --method org.freedesktop.DBus.GetNameOwner org.freedesktop.Notifications").split("'")[1]
          status, out = bus_call("org.kde.klipper", "/klipper", "org.kde.klipper.klipper.getClipboardContents")
          assert status != 0 and "secret" not in out, f"the clipboard by its name: {status} {out}"
          # The notification server's own connection, by its unique name: the rules of the names it holds apply
          status, out = bus_call(shell, "/klipper", "org.kde.klipper.klipper.getClipboardContents")
          assert status != 0 and "secret" not in out, f"the clipboard through {shell}: {status} {out}"
          status, out = bus_call("org.freedesktop.Notifications", "/klipper", "org.kde.klipper.klipper.getClipboardContents")
          assert status != 0 and "secret" not in out, f"the clipboard through the notification name: {status} {out}"
          status, out = bus_call("org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher",
                                 "org.freedesktop.DBus.Properties.Get", "org.kde.StatusNotifierWatcher",
                                 "IsStatusNotifierHostRegistered")
          assert status == 0 and "true" in out, f"IsStatusNotifierHostRegistered: {status} {out}"
          status, out = bus_call("org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher",
                                 "org.kde.StatusNotifierWatcher.RegisterStatusNotifierItem",
                                 f"org.freedesktop.StatusNotifierItem-{app_pid}-1")
          assert status == 0, f"RegisterStatusNotifierItem: {status} {out}"
          items = as_alice(f"{gdbus} call --session --dest org.kde.StatusNotifierWatcher --object-path"
                           " /StatusNotifierWatcher --method org.freedesktop.DBus.Properties.Get"
                           " org.kde.StatusNotifierWatcher RegisteredStatusNotifierItems")
          assert f"StatusNotifierItem-{app_pid}-1" in items, items
          status, out = bus_call("org.kde.StatusNotifierWatcher", "/kded", "org.kde.kded6.unloadModule", "x")
          assert status != 0 and "true" not in out, f"kded's other object: {status} {out}"

      with subtest("the launch replaced the planted links and left alice's files alone"):
          victims_untouched()
          for link in planted:
              if not link.endswith(".tmp"):
                  workstation.succeed(f"test -f {link} && test ! -L {link}")
          config = workstation.succeed("cat /home/alice/.config/Claude/claude_desktop_config.json")
          assert "secret" not in config and "mcpServers" in config, config
          theme = workstation.succeed("cat ${sandboxHome}/.config/glib-2.0/settings/keyfile")
          assert "secret" not in theme and "gtk-theme" in theme, theme
          workstation.succeed("grep -qx 'XDG_DOWNLOAD_DIR=\"$HOME/Downloads\"' ${sandboxHome}/.config/user-dirs.dirs")
          # The sandbox can't rename its store dir, where host-side processes that join its mount namespace run
          # binaries from: it's a mount of its own
          status, out = workstation.execute(sandbox_cmd("mv /nix/store /nix/store.moved") + " 2>&1")
          assert status != 0 and "busy" in out, f"{status} {out}"

      with subtest("Claude Code's temp dir is bound from the host"):
          in_sandbox("touch /tmp/claude-1000/probe")
          workstation.succeed(f"test -e {scratchpad}/probe")
          assert workstation.succeed(f"stat -c %a {scratchpad}").strip() == "700"

      with subtest("subordinate ids"):
          info = bwrap_info()
          # alice's auto range (65536 ids), her uid and gid (1000, 100) as themselves
          for kind, own in [("uid", 1000), ("gid", 100)]:
              start = int(workstation.succeed(f"grep ^alice: /etc/sub{kind}").split(":")[1])
              got = workstation.succeed(f"grep . /proc/{info['child-pid']}/{kind}_map").split()
              want = [str(n) for n in [0, start, own, own, own, 1, own + 1, start + own + 1, 65535 - own]]
              assert got == want, f"{kind}_map {got}, want {want}"
          # The FHS env's userns: all of the outer one's ids as themselves
          got = in_sandbox("grep . /proc/self/uid_map").split()
          assert got == ["0", "0", "1000", "1000", "1000", "1", "1001", "1001", "64535"], got
          assert in_sandbox("id -u").strip() == "1000"
          got = in_sandbox("cat /etc/subuid /etc/subgid")
          assert got == "alice:0:1000\nalice:1001:64535\nalice:0:100\nalice:101:65435\n", repr(got)
          # Through the shims and the broker: from /etc/subuid, and as podman maps a container's root to the user
          got = in_sandbox("unshare --user --map-auto grep . /proc/self/uid_map").split()
          assert got == ["0", "0", "1000"], got
          out = in_sandbox("unshare --user --map-root-user --map-users=1:1001:10 grep . /proc/self/uid_map")
          assert out.split() == ["0", "1000", "1", "1", "1001", "10"], out
          # Tools that run shadow's by path get the shims too
          shim = in_sandbox("readlink -f /usr/bin/newuidmap").strip()
          assert shim.endswith("/bin/subid-broker"), shim
          in_sandbox("touch /tmp/claude-1000/owner")
          assert workstation.succeed(f"stat -c %U:%G {scratchpad}/owner").strip() == "alice:users"
          # The app shares the netns's userns but has no capabilities in it
          status, out = workstation.execute(sandbox_cmd("ip link add probe0 type dummy") + " 2>&1")
          assert status != 0 and "Operation not permitted" in out, f"{status} {out}"
          # The broker only serves clients in a sandbox
          sock = workstation.succeed("ls /run/user/1000/claude-desktop/subid-broker-*.sock").strip()
          # The sleep's output elsewhere and killed after: execute waits for whatever holds the pipe
          status, out = as_user("alice", "sh -c " + shlex.quote(
              f"unshare --user sleep 30 >/dev/null 2>&1 & sleep 1; SUBID_BROKER_SOCKET={sock}"
              f" {shim.removesuffix('subid-broker')}newuidmap $! 0 1000 1; s=$?; kill $!; exit $s"
          ))
          assert status != 0 and "Client isn't in a sandbox" in out, f"{status} {out}"

      with subtest("scratchpad prune"):
          as_alice("/run/current-system/sw/bin/sh -c " + shlex.quote(
              f"cd {scratchpad} && mkdir -p -- -p/old/scratchpad -p/new/scratchpad -gone/old/scratchpad harness"
              " && touch -- -p/old/scratchpad/f -p/new/scratchpad/f -gone/old/scratchpad/f old.json new.json"
              " && touch -d '31 days ago' -- -p/old/scratchpad/f -p/old/scratchpad -p/old"
              " -gone/old/scratchpad/f -gone/old/scratchpad -gone/old old.json harness"
          ))
          in_sandbox("claude-desktop-scratchpad-prune")
          left = sorted(workstation.succeed(f"cd {scratchpad} && find . -mindepth 1").split())
          assert left == ["./-p", "./-p/new", "./-p/new/scratchpad", "./-p/new/scratchpad/f", "./harness", "./new.json", "./owner", "./probe"], left

      gc_dir = "${stateDir}/nix/var/claude-desktop"
      with subtest("store GC"):
          workstation.succeed(f"test -e {gc_dir}/gc-pending")
          assert "nix-store --gc" in in_sandbox("claude-desktop-store-gc")
          workstation.succeed(f"test ! -e {gc_dir}/gc-pending && test -e {gc_dir}/gc-last")
          # Not due: no marker and the last run is recent
          assert in_sandbox("claude-desktop-store-gc") == ""
          workstation.succeed(f"touch -d '8 days ago' {gc_dir}/gc-last")
          assert "nix-store --gc" in in_sandbox("claude-desktop-store-gc")
          # On the host it would collect the host's store
          gc = in_sandbox("readlink -f /run/current-system/sw/bin/claude-desktop-store-gc").strip()
          status, out = as_user("alice", gc)
          assert status != 0 and "Only runs inside the claude-desktop sandbox" in out, f"{status} {out}"

      keyfile = "${sandboxHome}/.config/glib-2.0/settings/keyfile"
      with subtest("GTK theme follows the portal's color scheme"):
          workstation.succeed(f"grep -qx \"gtk-theme='Adwaita-dark'\" {keyfile}")
          # The watcher writes while the sandbox runs, which swaps the keyfile for a link to one of alice's files
          in_sandbox("ln -sfn /home/alice/victim-c /home/alice/.config/glib-2.0/settings/keyfile")
          as_alice(
              "${pkgs.lib.getExe' pkgs.glib "gdbus"} call --session --dest org.freedesktop.portal.Desktop"
              " --object-path /org/freedesktop/portal/desktop --method org.freedesktop.portal.Settings.SetColorScheme 0"
          )
          workstation.wait_until_succeeds(f"grep -qx \"gtk-theme='Adwaita'\" {keyfile}", timeout=30)
          workstation.succeed(f"test ! -L {keyfile}")
          assert "secret" not in workstation.succeed(f"cat {keyfile}")
          victims_untouched()

      with subtest("claude:// re-entry joins the running sandbox"):
          reentry = in_sandbox("readlink /proc/self/ns/net /proc/self/ns/pid").split()
          assert reentry == [app_netns, app_pidns], f"re-entry in {reentry}, app in {[app_netns, app_pidns]}"
          assert len(workstation.succeed("cat ${sandboxHome}/stub-app.log").splitlines()) == 1

      with subtest("Chromium sees COSMIC ahead of GNOME, and KDE as is"):
          for host, want in [("ubuntu:GNOME", "ubuntu:COSMIC:GNOME"), ("KDE", "KDE")]:
              got = workstation.succeed(
                  f"systemd-run --user -M alice@ --wait --pipe --quiet -E XDG_CURRENT_DESKTOP={host}"
                  " -- /etc/profiles/per-user/alice/bin/claude-desktop --exec printenv XDG_CURRENT_DESKTOP"
              ).strip()
              assert got == want, f"{host}: {got!r}, want {want!r}"

      # A login shell, as the .desktop file's terminal action runs it, reading commands from stdin
      def sandbox_shell(cmd, env=""):
          return as_alice("/run/current-system/sw/bin/sh -c " + shlex.quote(
              f"echo {shlex.quote(cmd)} | {env} /etc/profiles/per-user/alice/bin/claude-desktop --shell"
          ))

      with subtest("--shell joins the app's namespaces"):
          out = sandbox_shell("readlink /proc/self/ns/net /proc/self/ns/mnt")
          assert out.split() == [app_netns, app_mntns], f"shell in {out.split()}, app in {[app_netns, app_mntns]}"
          # no_new_privs, as everything bwrap starts: file capabilities on what it execs count for nothing
          out = sandbox_shell("grep NoNewPrivs /proc/self/status")
          assert out.split() == ["NoNewPrivs:", "1"], out
          assert in_sandbox("grep NoNewPrivs /proc/self/status").split() == ["NoNewPrivs:", "1"]

      with subtest("--shell keeps the terminal's TERM, unless its TERMINFO isn't in the sandbox"):
          for env, want in [
              ("TERM=xterm-ghostty TERMINFO=/nonexistent COLORTERM=truecolor", "xterm-256color - truecolor"),
              ("TERM=xterm-ghostty TERMINFO=/etc", "xterm-ghostty /etc"),
              ("TERM=konsole-256color", "konsole-256color -"),
          ]:
              # No ''${...}: systemd-run would expand it
              out = sandbox_shell('[ -v TERMINFO ] && t=$TERMINFO || t=-; echo "$TERM $t $COLORTERM"', env).strip()
              assert out == want, f"{env}: {out!r}, want {want!r}"

      with subtest("re-entries find the app past a process at its pid in a pid ns of the sandbox's own"):
          # As anything in the sandbox can: a user and pid ns of its own, a process at the app's pid there, the
          # unshare gone, so it hangs off the FHS env's init, nearer to the sandbox's pid 1 than the app. The
          # pid is set from inside that ns, by a child: the unshare's own shell is still in the FHS env's
          nest = ("unshare -Urpm sh -c 'sleep infinity & mount -t proc proc /proc;"
                  " sh -c \"echo 99 >/proc/sys/kernel/ns_last_pid\"; sleep infinity &'; exec sleep infinity")
          # SIGKILL: the nested pid ns's init, a sleep, ignores SIGTERM, which would hold the stop for its 90 s timeout
          workstation.succeed(
              "systemd-run --user -M alice@ --unit nest -p KillSignal=SIGKILL"
              " -- /etc/profiles/per-user/alice/bin/claude-desktop --exec sh -c "
              + shlex.quote(nest)
          )
          workstation.wait_until_succeeds(
              "grep -lP '^NSpid:\\t\\d+\\t\\d+\\t\\d+\\t100$' /proc/[0-9]*/status", timeout=30
          )
          assert in_sandbox("readlink /proc/self/ns/pid").strip() == app_pidns, "claude:// joined the nested pid ns"
          out = sandbox_shell("readlink /proc/self/ns/pid /proc/self/ns/mnt").split()
          assert out == [app_pidns, app_mntns], f"--shell in {out}, app in {[app_pidns, app_mntns]}"
          workstation.succeed("systemctl --user -M alice@ stop nest")

      with subtest("DHCP lease on the macvlan"):
          workstation.wait_until_succeeds(
              sandbox_cmd("grep -qx 'nameserver ${routerIP}' /etc/resolv.conf"), timeout=60
          )
          links = in_sandbox("ip -o link show")
          assert [l.split(":")[1].strip().split("@")[0] for l in links.splitlines()] == ["lo", "eth0"], links
          assert "macvlan" in in_sandbox("ip -d link show eth0")
          assert "inet 192.168.1." in in_sandbox("ip -4 -o addr show dev eth0")
          assert "default via ${routerIP} dev eth0" in in_sandbox("ip route")
          # udhcpc runs in a mount namespace of its own, holding only its closure, not the sandbox's: there the sandbox
          # could swap the store directory for one of its own and have udhcpc run it
          udhcpc = workstation.succeed("pgrep -u alice -x udhcpc").split()[0]
          sb_mnt = workstation.succeed(f"readlink /proc/{bwrap_info()['child-pid']}/ns/mnt").strip()
          assert workstation.succeed(f"readlink /proc/{udhcpc}/ns/mnt").strip() != sb_mnt, "udhcpc runs in M1"
          store = workstation.succeed(f"ls /proc/{udhcpc}/root/nix/store").split()
          assert any(p.endswith("-claude-desktop-udhcpc") for p in store), store
          assert not any("stub" in p or "claude-desktop-store-roots" in p for p in store), store
          workstation.succeed(f"test -f /proc/{udhcpc}/root/home/alice/.config/resolv.conf")
          workstation.fail(f"test -e /proc/{udhcpc}/root/home/alice/victim-a")

      with subtest("A named launcher runs a sandbox of its own next to the default one"):
          work_home = "${workStateDir}/home"
          workstation.succeed(
              "systemd-run --user -M alice@ --unit claude-desktop-work -p KillMode=process -E WAYLAND_DISPLAY=wayland-0"
              " -- /etc/profiles/per-user/alice/bin/claude-desktop-work"
          )
          workstation.wait_until_succeeds(f"test -s {work_home}/stub-app.log", timeout=300)
          work_pid, work_netns, work_mntns, _, _, work_bus = workstation.succeed(f"cat {work_home}/stub-app.log").split()
          assert work_netns != app_netns and work_mntns != app_mntns, "work runs in the default sandbox"
          # Its own tray item next to the default one's
          assert work_bus == "1" and work_pid != app_pid, f"work is pid {work_pid}, the default {app_pid}: {work_bus}"

          def work_cmd(cmd):
              return alice_cmd(f"/etc/profiles/per-user/alice/bin/claude-desktop-work --exec {cmd}")

          def in_work(cmd):
              return workstation.succeed(work_cmd(cmd))

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
          # A grant through the MCP server: with an always grant stored, after a restart of the daemon (which finds
          # the sandbox again), it's issued without asking, for the ceiling's maxValidity
          workstation.succeed("mkdir -p /srv/notes && echo notes > /srv/notes/file && chown -R alice /srv/notes")
          # A folder with a mount beneath it, which would come along unchecked: never mounted
          workstation.succeed("mkdir -p /srv/mounted/sub && mount -t tmpfs none /srv/mounted/sub && chown -R alice /srv/mounted")
          workstation.succeed(
              "echo '{\"always\": [{\"capability\": \"test/thing\", \"params\": {}, \"granted\": \"2026-01-01T00:00:00Z\"},"
              " {\"capability\": \"folders/folder\", \"params\": {\"path\": \"/srv/notes\"}, \"granted\": \"2026-01-01T00:00:00Z\"},"
              " {\"capability\": \"folders/folder\", \"params\": {\"path\": \"/srv/mounted\"}, \"granted\": \"2026-01-01T00:00:00Z\"},"
              " {\"capability\": \"test/echo\", \"params\": {}, \"granted\": \"2026-01-01T00:00:00Z\"}]}'"
              " | runuser -u alice -- tee ${workStateDir}/permissions.json"
          )
          workstation.succeed("systemctl --user -M alice@ restart claude-desktop-work-permissions")
          rpc = "\n".join(json.dumps(m) for m in [
              {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                  "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "vm", "version": "0"}}},
              {"jsonrpc": "2.0", "method": "notifications/initialized"},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "request", "arguments": {
                  "capability": "test/thing", "reason": "the VM test", "lease": "PT1H"}}},
          ])
          # Stdin stays open a while for the answer. Retried until the restarted daemon listens
          mcp = f"(printf '%s\\n' {shlex.quote(rpc)}; sleep 3) | ${pkgs.lib.getExe broker} mcp"
          # Retried until the restarted daemon listens; the MCP server's whole output, stderr too, if it never answers
          def mcp_until(script, want, tries=20):
              for _ in range(tries):
                  _, out = workstation.execute(work_cmd(f"sh -c {shlex.quote(script + ' 2>&1')}"))
                  if want in out:
                      return
                  time.sleep(3)
              raise Exception(f"No {want!r} from the MCP server: {out}")

          mcp_until(mcp, "issued-PT28800S")
          # The always service grant: its plugin runs socket-activated by systemd, on a socket in the grant directory,
          # and the MCP server offers its tool and forwards a call to it
          call = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
              "name": "test_echo", "arguments": {"text": "from the sandbox"}}})
          mcp = (f"(printf '%s\\n' {shlex.quote(rpc.splitlines()[0])} {shlex.quote(rpc.splitlines()[1])}; sleep 3;"
                 f" printf '%s\\n' {shlex.quote(call)}; sleep 3) | ${pkgs.lib.getExe broker} mcp")
          mcp_until(mcp, "echo: from the sandbox")

          # A crash ends the daemon's grants: ExecStopPost detaches the folder, and the service units are bound to it.
          # Started again, it replays the always grants under new ids
          socket_unit = workstation.succeed(
              "systemctl --user -M alice@ list-units --plain --no-legend 'perm-work_*.socket' | cut -d' ' -f1"
          ).strip()
          folder = next(l.split()[4] for l in in_work("cat /proc/self/mountinfo").splitlines() if " /run/permissions/" in l)
          # The restarted daemon cleans up too, so the wiring is checked as such
          bound = workstation.succeed(f"systemctl --user -M alice@ show -P BindsTo {socket_unit}")
          assert "claude-desktop-work-permissions.service" in bound, f"{socket_unit} bound to {bound!r}"
          stop_post = workstation.succeed("systemctl --user -M alice@ show -P ExecStopPost claude-desktop-work-permissions")
          assert " cleanup " in stop_post, f"ExecStopPost {stop_post!r}"
          workstation.succeed("systemctl --user -M alice@ kill --signal=SIGKILL claude-desktop-work-permissions")
          workstation.wait_until_fails(f"systemctl --user -M alice@ is-active -q {socket_unit}", timeout=30)
          workstation.wait_until_succeeds(work_cmd(f"sh -c '! grep -q \" {folder} \" /proc/self/mountinfo'"), timeout=30)
          workstation.wait_until_succeeds("systemctl --user -M alice@ is-active -q claude-desktop-work-permissions", timeout=30)
          workstation.wait_until_succeeds(work_cmd("sh -c 'cat /run/permissions/*/file'") + " | grep -qx notes", timeout=60)
          # The always folder too: the restarted daemon takes over the shared grant directory, mounts the folder there
          # from the host, and it reaches the app's mount namespace, read-only
          workstation.wait_until_succeeds(work_cmd("sh -c 'cat /run/permissions/*/file'") + " | grep -qx notes", timeout=60)
          status, _ = workstation.execute(work_cmd("sh -c 'touch /run/permissions/*/new'"))
          assert status != 0, "the read-only folder grant is writable"
          grants = [l for l in in_work("cat /proc/self/mountinfo").splitlines() if " /run/permissions/" in l]
          assert len(grants) == 1, f"one folder mounted, not the one with a mount beneath it: {grants}"
          opts = grants[0].split()[5].split(",")
          assert {"ro", "nodev", "nosuid"} <= set(opts), grants[0]

          # The state machine tests live (TestLiveMachine): rapid's sequences of requests from processes in the sandbox
          # (sessions anchored at a copy of the test binary named claude, a forged one below a copy named node, a caller
          # without one), answers, revoke and forget through control.sock, releases, sessions ending, restarts with
          # replay and lock events, the live state checked against the reference model after every step. A fixed seed;
          # LIVE_RAPID replaces the rapid flags in the interactive driver, -rapid.seed=0 for a random one, and LIVE_TIMEOUT its
          # 15 minutes
          workstation.succeed("mkdir -p /srv/notes/sub /srv/outside && chown alice /srv/notes/sub /srv/outside")
          workstation.succeed(
              f"install -D -m755 -o alice ${brokerLive}/bin/permissions-broker-live {work_home}/live/claude"
              f" && cp -p {work_home}/live/claude {work_home}/live/node"
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
              f" LIVE_BIN=/home/alice/live/claude LIVE_ROOT=/srv/notes LIVE_OUTSIDE=/srv/outside LIVE_LOCK_SESSION={lock_session}"
              f" ${brokerLive}/bin/permissions-broker-live -test.run '^TestLiveMachine$' -test.v -rapid.nofailfile {rapid_flags}"
          ) + " 2>&1", timeout=int(os.environ.get("LIVE_TIMEOUT", "900")))
          print(out)
          assert status == 0 and "--- PASS: TestLiveMachine" in out, f"TestLiveMachine failed after {time.monotonic() - started:.0f} s"
          print(f"TestLiveMachine took {time.monotonic() - started:.0f} s")
          workstation.succeed("systemctl stop fake-session")

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

      with subtest("Own hosts file"):
          workstation.succeed("grep -qw host-only.test /etc/hosts")
          hosts = in_sandbox("cat /etc/hosts")
          assert "host-only.test" not in hosts, hosts
          assert {"127.0.0.1 localhost", "127.0.0.2 workstation"} <= set(hosts.splitlines()), hosts

      with subtest("A file from the store, with what it references"):
          for d in ["/etc", "/home/alice/.config"]:
              assert in_sandbox(f"{d}/agent-sandbox-test/hello").strip() == "Hello, world!", d

      with subtest("A host GC leaves the sandbox's store paths and /etc alone"):
          root = "/run/user/1000/claude-desktop/store-roots"
          workstation.succeed(f"nix-store -q --roots $(readlink -e {root}) | grep -q '^{root} '")
          # hosts and resolv.conf are links in the FHS env's rootfs, so nixpak's binds of the host's go unused
          for f in ["hosts", "resolv.conf"]:
              assert not in_sandbox(f"readlink -f /etc/{f}").startswith("/.host-etc/"), f
          # The rest by the root of their mount: the host's own files only where activation writes them
          mounts = {f[4]: f[3] for f in map(str.split, in_sandbox("cat /proc/self/mountinfo").splitlines())}
          from_host = {
              m for m, r in mounts.items()
              if m.startswith("/.host-etc/") and r.startswith("/etc/") and m not in ["/.host-etc/hosts", "/.host-etc/resolv.conf"]
          }
          assert from_host == {f"/.host-etc/{e}" for e in ["passwd", "group", "machine-id"]}, from_host
          in_sandbox("test -s /etc/ssl/certs/ca-certificates.crt")

      with subtest("nettest.sh"):
          print(in_sandbox(f"nettest {' '.join(host_only)}"))

      sandbox_pid = bwrap_info()["child-pid"]

      with subtest("netns-macvlan refuses other users' namespaces"):
          bob_ns = spawn("bob-ns", "bob", "/run/current-system/sw/bin/unshare -Urn")
          alice_in_bob_ns = spawn("alice-in-bob-ns", "alice", netns_pid=bob_ns)
          bob_in_alice_ns = spawn("bob-in-alice-ns", "bob", netns_pid=sandbox_pid)
          for pid, error in [
              (sandbox_pid, "belongs to uid 1000, not 1001"),
              # Only the process check stops these two: the netns is bob's
              (alice_in_bob_ns, "belongs to uid 1000, not 1001"),
              # Only the owner check: the process is bob's
              (bob_in_alice_ns, "is owned by uid 1000, not 1001"),
              ("$$", "shares the caller's network namespace"),
          ]:
              status, out = as_bob(f"sh -c {shlex.quote(f'exec /run/wrappers/bin/netns-macvlan {pid}')}")
              assert status != 0 and error in out, f"netns-macvlan {pid}: {status} {out}"
          # A network namespace owned by a user namespace of alice's, below one root made and mapped her uid into: the
          # immediate owner is hers, but she holds no capability there. The kernel's ptrace check on /proc/<pid>/ns/net
          # already refuses alice the process that made it, so the target is one of hers in the host's user namespace
          # that root put in that netns
          setup = ("u=/run/current-system/sw/bin; $u/unshare --user $u/sleep infinity & p=$!; $u/sleep 1;"
                   " echo '1000 1000 1' >/proc/$p/uid_map; echo '100 100 1' >/proc/$p/gid_map;"
                   " exec $u/nsenter -t $p -U --setuid 1000 --setgid 100 $u/unshare --user --net --map-root-user \"$@\"")
          under_root = spawn("alice-under-root", "root", f"/run/current-system/sw/bin/sh -c {shlex.quote(setup)} sh")
          # spawn's wait also matches nsenter, which has sleep among its arguments: wait for the exec into sleep
          workstation.wait_until_succeeds(
              f"[ \"$(head -zn1 /proc/{under_root}/cmdline | tr -d '\\0')\" = /run/current-system/sw/bin/sleep ]",
              timeout=30,
          )
          alice_in_nested = spawn("alice-in-nested", "alice", netns_pid=under_root)
          status, out = as_user("alice", f"/run/wrappers/bin/netns-macvlan {alice_in_nested}")
          assert status != 0 and "is owned by uid 0, not 1000" in out, f"netns-macvlan {alice_in_nested}: {status} {out}"
          workstation.succeed("systemctl stop alice-in-nested alice-under-root")
          status, out = as_bob(f"/run/wrappers/bin/netns-macvlan {bob_ns}")
          assert status == 0, out
          workstation.succeed(f"nsenter -t {bob_ns} -n ip link show eth0")
          # It holds the sandbox's netns, whose macvlan's MAC would then block the next sandbox's
          workstation.succeed("systemctl stop bob-in-alice-ns")

      with subtest("the theme watcher ends with the app"):
          workstation.succeed("pgrep -u alice -f claude-desktop-gtk-theme-watch")
          workstation.succeed("systemctl --user -M alice@ kill --kill-whom=main claude-desktop")
          workstation.wait_until_fails("pgrep -u alice -f 'claude-desktop-gtk-theme-watch|gdbus monitor'", timeout=30)
          workstation.wait_until_fails("pgrep -u alice subid-broker", timeout=30)
          workstation.fail("ls /run/user/1000/claude-desktop/subid-broker-*.sock")

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
    '';
}
