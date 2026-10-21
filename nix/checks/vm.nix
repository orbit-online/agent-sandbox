# The sandbox on a booted NixOS: alice's claude-desktop (the stub app) on a workstation whose LAN has a router with
# DHCP and DNS. The router also stands in for the internet: its DNS points api.anthropic.com and github.com at itself.
{ pkgs, aliceModule }:
let
  stateDir = "/home/alice/.local/share/claude-desktop";
  sandboxHome = "${stateDir}/home";
  scratchpad = "${stateDir}/tmp-scratchpad";
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
          package = pkgs.callPackage ./stub-app.nix { };
          # Missing until the launch subtest creates it
          binds."/srv/project" = { };
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
      import json, shlex

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
          app_pid, app_netns, app_mntns = workstation.succeed("cat ${sandboxHome}/stub-app.log").split()
          # The module's tray D-Bus rule names the app's main process: StatusNotifierItem-18-1
          assert app_pid == "18", f"the app is pid {app_pid} in the sandbox, update the tray rule"
          assert app_netns != as_alice("/run/current-system/sw/bin/readlink /proc/self/ns/net").strip(), "the app runs in the host's netns"

      with subtest("Claude Code's temp dir is bound from the host"):
          in_sandbox("touch /tmp/claude-1000/probe")
          workstation.succeed(f"test -e {scratchpad}/probe")
          assert workstation.succeed(f"stat -c %a {scratchpad}").strip() == "700"

      with subtest("scratchpad prune"):
          as_alice("/run/current-system/sw/bin/sh -c " + shlex.quote(
              f"cd {scratchpad} && mkdir -p -- -p/old/scratchpad -p/new/scratchpad -gone/old/scratchpad harness"
              " && touch -- -p/old/scratchpad/f -p/new/scratchpad/f -gone/old/scratchpad/f old.json new.json"
              " && touch -d '31 days ago' -- -p/old/scratchpad/f -p/old/scratchpad -p/old"
              " -gone/old/scratchpad/f -gone/old/scratchpad -gone/old old.json harness"
          ))
          in_sandbox("claude-desktop-scratchpad-prune")
          left = sorted(workstation.succeed(f"cd {scratchpad} && find . -mindepth 1").split())
          assert left == ["./-p", "./-p/new", "./-p/new/scratchpad", "./-p/new/scratchpad/f", "./harness", "./new.json", "./probe"], left

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
          as_alice(
              "${pkgs.lib.getExe' pkgs.glib "gdbus"} call --session --dest org.freedesktop.portal.Desktop"
              " --object-path /org/freedesktop/portal/desktop --method org.freedesktop.portal.Settings.SetColorScheme 0"
          )
          workstation.wait_until_succeeds(f"grep -qx \"gtk-theme='Adwaita'\" {keyfile}", timeout=30)

      with subtest("claude:// re-entry joins the running sandbox"):
          reentry_netns = in_sandbox("readlink /proc/self/ns/net").strip()
          assert reentry_netns == app_netns, f"re-entry in {reentry_netns}, app in {app_netns}"
          assert len(workstation.succeed("cat ${sandboxHome}/stub-app.log").splitlines()) == 1

      # A login shell, as the .desktop file's terminal action runs it, reading commands from stdin
      def sandbox_shell(cmd, env=""):
          return as_alice("/run/current-system/sw/bin/sh -c " + shlex.quote(
              f"echo {shlex.quote(cmd)} | {env} /etc/profiles/per-user/alice/bin/claude-desktop --shell"
          ))

      with subtest("--shell joins the app's namespaces"):
          out = sandbox_shell("readlink /proc/self/ns/net /proc/self/ns/mnt")
          assert out.split() == [app_netns, app_mntns], f"shell in {out.split()}, app in {[app_netns, app_mntns]}"

      with subtest("--shell keeps the terminal's TERM, unless its TERMINFO isn't in the sandbox"):
          for env, want in [
              ("TERM=xterm-ghostty TERMINFO=/nonexistent COLORTERM=truecolor", "xterm-256color - truecolor"),
              ("TERM=xterm-ghostty TERMINFO=/etc", "xterm-ghostty /etc"),
              ("TERM=konsole-256color", "konsole-256color -"),
          ]:
              # No ''${...}: systemd-run would expand it
              out = sandbox_shell('[ -v TERMINFO ] && t=$TERMINFO || t=-; echo "$TERM $t $COLORTERM"', env).strip()
              assert out == want, f"{env}: {out!r}, want {want!r}"

      with subtest("DHCP lease on the macvlan"):
          workstation.wait_until_succeeds(
              sandbox_cmd("grep -qx 'nameserver ${routerIP}' /etc/resolv.conf"), timeout=60
          )
          links = in_sandbox("ip -o link show")
          assert [l.split(":")[1].strip().split("@")[0] for l in links.splitlines()] == ["lo", "eth0"], links
          assert "macvlan" in in_sandbox("ip -d link show eth0")
          assert "inet 192.168.1.1" in in_sandbox("ip -4 -o addr show dev eth0")
          assert "default via ${routerIP} dev eth0" in in_sandbox("ip route")

      with subtest("Own hosts file"):
          workstation.succeed("grep -qw host-only.test /etc/hosts")
          hosts = in_sandbox("cat /etc/hosts")
          assert "host-only.test" not in hosts, hosts
          assert {"127.0.0.1 localhost", "127.0.0.2 workstation"} <= set(hosts.splitlines()), hosts

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

      sandbox_pid = json.loads(
          workstation.succeed("cat /run/user/1000/.flatpak/nixpak-app-*/bwrapinfo.json")
      )["child-pid"]

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
          status, out = as_bob(f"/run/wrappers/bin/netns-macvlan {bob_ns}")
          assert status == 0, out
          workstation.succeed(f"nsenter -t {bob_ns} -n ip link show eth0")
          # It holds the sandbox's netns, whose macvlan's MAC would then block the next sandbox's
          workstation.succeed("systemctl stop bob-in-alice-ns")

      with subtest("the theme watcher ends with the app"):
          workstation.succeed("pgrep -u alice -f claude-desktop-gtk-theme-watch")
          workstation.succeed("systemctl --user -M alice@ kill --kill-whom=main claude-desktop")
          workstation.wait_until_fails("pgrep -u alice -f 'claude-desktop-gtk-theme-watch|gdbus monitor'", timeout=30)

      with subtest("--shell starts the app when it isn't running"):
          workstation.wait_until_fails(f"test -e /proc/{sandbox_pid}", timeout=30)
          out = sandbox_shell("readlink /proc/self/ns/net")
          # --shell enters as soon as bwrap forks the app, which may not have logged yet
          workstation.wait_until_succeeds("test $(wc -l <${sandboxHome}/stub-app.log) -ge 2", timeout=30)
          launches = workstation.succeed("cat ${sandboxHome}/stub-app.log").splitlines()
          assert len(launches) == 2, launches
          assert out.splitlines()[-1] == launches[1].split()[1], f"{out} {launches}"
    '';
}
