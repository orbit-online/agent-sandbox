# The sandbox on a booted NixOS: alice's claude-desktop (the stub app) on a workstation whose LAN has a router with
# DHCP and DNS. The router also stands in for the internet: its DNS points api.anthropic.com and github.com at itself.
# Split into tests Nix runs in parallel, each booting the same two machines (built once) and running a part of the
# script (./<part>.nix) after a shared prelude of helpers. Returns { <part> = test; }
{
  pkgs,
  aliceModule,
  broker,
}:
let
  inherit (pkgs) lib;
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
  # A plugin for the permissions broker: a service with tools
  testPlugin = pkgs.writeTextDir "share/agent-sandbox/permissions/test.json" (
    builtins.toJSON {
      name = "test";
      capabilities = [
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
  stub = pkgs.callPackage ../stub-app.nix { };
  fakePortal = pkgs.writers.writePython3Bin "fake-portal" {
    libraries = [ pkgs.python3Packages.dbus-next ];
    # dbus-next's signatures are string annotations
    flakeIgnore = [
      "F722"
      "F821"
      "E501"
    ];
  } (builtins.readFile ../fake-portal.py);
  gdbus = lib.getExe' pkgs.glib "gdbus";

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
            lib.genAttrs [ "/etc/agent-sandbox-test/hello" "/home/alice/.config/agent-sandbox-test/hello" ]
              (_: {
                source = pkgs.writeShellScript "hello" "exec ${lib.getExe pkgs.hello}";
              });
          launchers.work = {
            package = stub;
            tray = true;
            permissions = {
              enable = true;
              # Made by the test script, before the daemon's restart
              folders = [
                { path = "/srv/notes"; }
                { path = "/srv/mounted"; }
              ];
              plugins.test.package = testPlugin;
              # A host command printing the validity it was given
              commands.test = {
                description = "a test command";
                commands.thing = {
                  description = "print the validity";
                  run = [ "${pkgs.writeShellScript "run" "echo issued-$(${lib.getExe pkgs.jq} -r .validity)"}" ];
                  maxValidity = "PT8H";
                };
              };
              grants = [
                { capability = "test"; }
                {
                  plugin = "test";
                  capability = "echo";
                }
              ];
            };
          };
        })
      ];
      virtualisation = {
        memorySize = 2048;
        # The store syncs copy the sandbox closure into alice's home, once per launcher
        diskSize = 12288;
      };
      # No graphics stack in the sandbox closure the store syncs copy, a third of it with mesa's: the stub app draws
      # nothing, and the module's graphics assertion still holds
      hardware.graphics = {
        package = pkgs.emptyDirectory;
        extraPackages = lib.mkForce [ ];
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

  # Helpers every part's script starts with, and the boot
  prelude = ''
    import json, shlex

    scratchpad = "${scratchpad}"
    gdbus = "${gdbus}"

    def alice_cmd(cmd):
        return f"systemd-run --user -M alice@ --wait --pipe --quiet -- {cmd}"

    def as_alice(cmd):
        return workstation.succeed(alice_cmd(cmd))

    # cmd in alice's running sandbox, through the wrapper's claude:// re-entry and the stub's --exec
    def sandbox_cmd(cmd):
        return alice_cmd(f"/etc/profiles/per-user/alice/bin/claude-desktop --exec {cmd}")

    def in_sandbox(cmd):
        return workstation.succeed(sandbox_cmd(cmd))

    # The same in the work launcher's
    def work_cmd(cmd):
        return alice_cmd(f"/etc/profiles/per-user/alice/bin/claude-desktop-work --exec {cmd}")

    def in_work(cmd):
        return workstation.succeed(work_cmd(cmd))

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

    # A login shell, as the .desktop file's terminal action runs it, reading commands from stdin
    def sandbox_shell(cmd, env=""):
        return as_alice("/run/current-system/sw/bin/sh -c " + shlex.quote(
            f"echo {shlex.quote(cmd)} | {env} /etc/profiles/per-user/alice/bin/claude-desktop --shell"
        ))

    # The fake portal on alice's session bus, once it answers
    def start_portal():
        workstation.succeed("systemd-run --user -M alice@ --unit fake-portal -- ${lib.getExe fakePortal}")
        workstation.wait_until_succeeds(alice_cmd(
            "${gdbus} call --session --dest org.freedesktop.portal.Desktop"
            " --object-path /org/freedesktop/portal/desktop --method org.freedesktop.portal.Settings.ReadOne"
            " org.freedesktop.appearance color-scheme"
        ))

    # Starts a launcher as a unit of alice's, named after it, and returns what the stub app logged in `home`: its pid,
    # net, mount and pid ns, capabilities and whether it got its tray item's name. KillMode=process: like a desktop's
    # app scope, ending the app leaves the rest alone
    def launch(launcher="claude-desktop", home="${sandboxHome}"):
        workstation.succeed(
            f"systemd-run --user -M alice@ --unit {launcher} -p KillMode=process -E WAYLAND_DISPLAY=wayland-0"
            f" -- /etc/profiles/per-user/alice/bin/{launcher}"
        )
        workstation.wait_until_succeeds(f"test -s {home}/stub-app.log", timeout=300)
        return workstation.succeed(f"cat {home}/stub-app.log").split()

    # The folders the work launcher's broker may grant: one with a file, one with a mount beneath it
    def make_folders():
        workstation.succeed("mkdir -p /srv/notes && echo notes > /srv/notes/file && chown -R alice /srv/notes")
        workstation.succeed("mkdir -p /srv/mounted/sub && mount -t tmpfs none /srv/mounted/sub && chown -R alice /srv/mounted")

    start_all()
    router.wait_for_unit("dnsmasq.service")
    router.wait_for_unit("https.service")
    workstation.wait_for_unit("home-manager-alice.service")
    workstation.wait_for_unit("user@1000.service")
    workstation.wait_for_unit("listener.service")
  '';

  test =
    part:
    pkgs.testers.runNixOSTest {
      name = "claude-desktop-${part}";
      inherit nodes;
      testScript =
        { nodes, ... }:
        prelude
        + import ./${part}.nix {
          inherit
            pkgs
            broker
            brokerLive
            gdbus
            stateDir
            sandboxHome
            workStateDir
            ;
          mcpArgs = nodes.workstation.home-manager.users.alice.agent-sandbox.claude-desktop.launchers.work.mcpServers.permissions.args;
          routerIP = nodes.router.networking.primaryIPAddress;
          workstationIP = nodes.workstation.networking.primaryIPAddress;
        };
    };
in
lib.genAttrs [
  "launch"
  "store"
  "work"
  "live"
] test
