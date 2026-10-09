# The sandbox on a booted NixOS: alice's claude-desktop (the stub app) on a workstation whose LAN has a router with
# DHCP and DNS. The router also stands in for the internet: its DNS points api.anthropic.com and github.com at itself.
{ pkgs, aliceModule }:
let
  sandboxHome = "/home/alice/.local/share/claude-desktop/home";
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
          package = pkgs.callPackage ./stub-app.nix { };
        })
      ];
      virtualisation = {
        memorySize = 2048;
        # The store sync copies the sandbox closure (graphics drivers included) into alice's home
        diskSize = 8192;
      };
      # netns-macvlan puts the macvlan on the default route's device
      networking.defaultGateway = nodes.router.networking.primaryIPAddress;
      # So the macvlan's isolation is what blocks the sandbox, not the firewall
      networking.firewall.enable = false;
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
      import json, shlex

      def alice_cmd(cmd):
          return f"systemd-run --user -M alice@ --wait --pipe --quiet -- {cmd}"

      def as_alice(cmd):
          return workstation.succeed(alice_cmd(cmd))

      # cmd in alice's running sandbox, through the wrapper's claude:// re-entry and the stub's --exec
      def sandbox_cmd(cmd):
          return alice_cmd(f"/etc/profiles/per-user/alice/bin/claude-desktop --exec {cmd}")

      def in_sandbox(cmd):
          return workstation.succeed(sandbox_cmd(cmd))

      def as_bob(cmd):
          return workstation.execute(f"setpriv --reuid bob --regid users --init-groups -- {cmd} 2>&1")

      # Runs cmd, which ends in an exec of sleep, as a transient root service and returns sleep's pid
      def spawn(unit, cmd):
          workstation.succeed(f"systemd-run --unit {unit} -- {cmd} /run/current-system/sw/bin/sleep infinity")
          pid = f"$(systemctl show -P MainPID {unit})"
          # Not comm: coreutils is one binary, so that reads coreutils
          workstation.wait_until_succeeds(f"grep -qz '^/run/current-system/sw/bin/sleep$' /proc/{pid}/cmdline", timeout=30)
          return workstation.succeed(f"echo {pid}").strip()

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

      with subtest("launch"):
          workstation.succeed(
              "systemd-run --user -M alice@ --unit claude-desktop -E WAYLAND_DISPLAY=wayland-0"
              " -- /etc/profiles/per-user/alice/bin/claude-desktop"
          )
          workstation.wait_until_succeeds("test -s ${sandboxHome}/stub-app.log", timeout=300)
          workstation.succeed("test -L /home/alice/.local/share/claude-desktop/nix/var/nix/gcroots/claude-desktop")
          app_netns = workstation.succeed("cut -d' ' -f2 ${sandboxHome}/stub-app.log").strip()
          assert app_netns != as_alice("/run/current-system/sw/bin/readlink /proc/self/ns/net").strip(), "the app runs in the host's netns"

      with subtest("claude:// re-entry joins the running sandbox"):
          reentry_netns = in_sandbox("readlink /proc/self/ns/net").strip()
          assert reentry_netns == app_netns, f"re-entry in {reentry_netns}, app in {app_netns}"
          assert len(workstation.succeed("cat ${sandboxHome}/stub-app.log").splitlines()) == 1

      with subtest("DHCP lease on the macvlan"):
          workstation.wait_until_succeeds(
              sandbox_cmd("grep -qx 'nameserver ${routerIP}' /etc/resolv.conf"), timeout=60
          )
          links = in_sandbox("ip -o link show")
          assert [l.split(":")[1].strip().split("@")[0] for l in links.splitlines()] == ["lo", "eth0"], links
          assert "macvlan" in in_sandbox("ip -d link show eth0")
          assert "inet 192.168.1.1" in in_sandbox("ip -4 -o addr show dev eth0")
          assert "default via ${routerIP} dev eth0" in in_sandbox("ip route")

      with subtest("nettest.sh"):
          print(in_sandbox(f"nettest {' '.join(host_only)}"))

      sandbox_pid = json.loads(
          workstation.succeed("cat /run/user/1000/.flatpak/nixpak-app-*/bwrapinfo.json")
      )["child-pid"]

      with subtest("netns-macvlan refuses other users' namespaces"):
          bob_ns = spawn("bob-ns", "setpriv --reuid bob --regid users --init-groups -- unshare -Urn")
          alice_in_bob_ns = spawn(
              "alice-in-bob-ns",
              f"nsenter -t {bob_ns} -n -- setpriv --reuid alice --regid users --init-groups --",
          )
          bob_in_alice_ns = spawn(
              "bob-in-alice-ns",
              f"nsenter -t {sandbox_pid} -n -- setpriv --reuid bob --regid users --init-groups --",
          )
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
          status, out = as_bob(f"/run/wrappers/bin/netns-macvlan {bob_ns}")
          assert status == 0, out
          workstation.succeed(f"nsenter -t {bob_ns} -n ip link show eth0")
    '';
}
