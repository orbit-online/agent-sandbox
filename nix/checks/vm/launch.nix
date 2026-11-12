# The default launcher: its launch, D-Bus, links planted in its state, subordinate ids, the scratchpad, store GC, the
# theme, re-entries and --shell, the network, /etc and the store, netns-macvlan's refusals
{
  gdbus,
  dbusProxy,
  stateDir,
  sandboxHome,
  routerIP,
  workstationIP,
  ...
}:
''
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
      start_portal()
      # A bind that isn't optional, with its source missing, refused before the app's unit starts, so the caller
      # sees it. The launch syncs the store first. RuntimeMaxSec: a launcher hanging there
      status, out = workstation.execute(
          "systemd-run --user -M alice@ --wait --pipe --quiet -p RuntimeMaxSec=600"
          " -- /etc/profiles/per-user/alice/bin/claude-desktop 2>&1"
      )
      assert status != 0 and "Bind source /srv/project is missing" in out, f"{status} {out}"
      workstation.succeed("mkdir /srv/project")
      app_pid, app_netns, app_mntns, app_pidns, app_caps, app_bus = launch()
      workstation.succeed("test -L /home/alice/.local/share/claude-desktop/nix/var/nix/gcroots/claude-desktop")
      workstation.succeed("test -d /home/alice/.claude")
      # The proxy let it own the tray item's name with its pid in it, which app-pid.sh set
      assert app_bus == "1", f"the app (pid {app_pid}) didn't get StatusNotifierItem-{app_pid}-1: {app_bus}"
      # app-pid.sh dropped the FHS env's CAP_CHECKPOINT_RESTORE
      assert app_caps == "0000000000000000", f"the app has capabilities {app_caps}"
      assert app_netns != as_alice("/run/current-system/sw/bin/readlink /proc/self/ns/net").strip(), "the app runs in the host's netns"

  with subtest("D-Bus through our proxy reaches the portal's notifications and OpenURI and the tray's calls, nothing else"):
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
      # Links go to the host's browser through the portal's OpenURI, which names the app by the caller's process: the
      # proxy's, in nixpak's wrapper with the app's /.flatpak-info
      in_sandbox("xdg-open https://example.test/from-the-sandbox")
      workstation.wait_until_succeeds("grep -q from-the-sandbox /run/user/1000/fake-portal-uris", timeout=30)
      opened = json.loads(workstation.succeed("grep from-the-sandbox /run/user/1000/fake-portal-uris"))
      assert opened["app"] == "com.anthropic.Claude", f"the portal saw the caller as {opened}"
      # Also by name without PATH, from the FHS env's /usr/bin, where a launch with the default path finds it
      in_sandbox("env -u PATH xdg-open https://example.test/no-path")
      workstation.wait_until_succeeds("grep -q no-path /run/user/1000/fake-portal-uris", timeout=30)
      # A method of an allowed name that no rule lists
      status, out = bus_call("org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop",
                             "org.freedesktop.portal.OpenURI.SchemeSupported", "https", "@a{sv} {}")
      assert status != 0 and "AccessDenied" in out, f"OpenURI.SchemeSupported: {status} {out}"
      workstation.fail("grep -q scheme /run/user/1000/fake-portal-uris")
      # A name without rules is hidden: no owner, not listed
      status, out = bus_call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.GetNameOwner",
                             "org.kde.klipper")
      assert status != 0 and "NameHasNoOwner" in out, f"GetNameOwner org.kde.klipper: {status} {out}"
      status, out = bus_call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.ListNames")
      assert status == 0 and "org.freedesktop.portal.Desktop" in out and "org.kde.klipper" not in out, f"ListNames: {out}"
      # The proxy nixpak started is ours: its wrapper runs bin/xdg-dbus-proxy, which execs dbus-proxy through systemd-cat
      proxies = workstation.succeed("pgrep -u alice -x dbus-proxy").split()
      assert len(proxies) == 1, f"proxies: {proxies}"
      exe = workstation.succeed(f"readlink /proc/{proxies[0]}/exe").strip()
      assert exe == "${dbusProxy}/bin/dbus-proxy", f"the D-Bus proxy runs {exe}"

  with subtest("the launcher's journal namespaces: the host side's by name and priority, which the sandbox reads but can't write to, and the sandbox's"):
      def host_journal(ns, args):
          return workstation.succeed(f"journalctl --namespace={ns} --no-pager -o cat {args}")
      # The refusals above, as warnings, on the host side
      workstation.wait_until_succeeds(
          "journalctl --namespace=claude-desktop --no-pager -o cat -t dbus-proxy -p warning | grep -q member=getClipboardContents",
          timeout=30)
      assert "time=" not in host_journal("claude-desktop", "-t dbus-proxy -p warning"), "slog's time in the journal"
      # What supervise pumps (nixpak, bwrap, the app, its ready line among it) and udhcpc, in the sandbox's; supervise's
      # own messages, under the same name, on the host side
      assert "agent-sandbox: ready" in host_journal("claude-desktop_sandbox", "-t claude-desktop")
      assert "agent-sandbox: ready" not in host_journal("claude-desktop", "")
      assert host_journal("claude-desktop_sandbox", "-t udhcpc").strip(), "nothing from udhcpc"
      assert not host_journal("claude-desktop", "-t udhcpc").strip(), "udhcpc on the host side"
      in_sandbox("logger -t probe-in hello-from-inside")
      in_sandbox("systemd-cat -t probe-cat echo hello-from-cat")
      workstation.wait_until_succeeds(sandbox_cmd("journalctl --no-pager -o cat -t probe-in -t probe-cat") + " | grep -c hello-from | grep -qx 2", timeout=30)
      # Nothing of the sandbox's reaches the host side's namespace
      status, out = workstation.execute(sandbox_cmd("systemd-cat --namespace=claude-desktop echo forged") + " 2>&1")
      assert status != 0, out
      assert "forged" not in host_journal("claude-desktop", "")
      assert not host_journal("claude-desktop", "-t probe-in").strip()
      # The proxy's refusals, from inside: the host side's namespace, read through the user's journal file's ACL
      assert "member=getClipboardContents" in in_sandbox("journalctl --namespace=claude-desktop --no-pager -o cat -t dbus-proxy -p warning")
      # Only the launcher's namespaces: the main journal's files aren't there
      out = sorted(in_sandbox("ls /var/log/journal").split())
      assert len(out) == 2 and out[1] == out[0] + ".claude-desktop", out
      cgroup = workstation.succeed(
          "journalctl --namespace=claude-desktop_sandbox --no-pager -o cat --output-fields=_SYSTEMD_CGROUP -t probe-in -n 1").strip()
      assert cgroup.endswith("/claude-desktop-app.service/sandbox/app"), cgroup

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
      # A unit of its own in the launcher's slice, bound to the app's
      broker = workstation.succeed("pgrep -u alice subid-broker").split()[0]
      assert workstation.succeed(f"cat /proc/{broker}/cgroup").strip().endswith(
          "/claude\\x2ddesktop.slice/claude-desktop-subid.service"), broker
      assert "claude-desktop-app.service" in workstation.succeed(
          "systemctl --user -M alice@ show -P BindsTo claude-desktop-subid"), "subid-broker isn't bound to the app"

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
  with subtest("the sandbox's systemd --user: beside the app, its timers, and the store GC its path unit starts"):
      assert in_sandbox("systemctl --user is-system-running").strip() == "running"
      # In user/, not the app's cgroup, and the app kept its pid
      assert in_sandbox("cat /sys/fs/cgroup/user/init.scope/cgroup.procs").strip()
      assert "100" in in_sandbox("cat /sys/fs/cgroup/app/cgroup.procs").split()
      timers = in_sandbox("systemctl --user list-timers --all --no-legend")
      assert "claude-desktop-store-gc.timer" in timers and "claude-desktop-scratchpad-prune.timer" in timers, timers
      # The launch moved the GC root; the path unit collects at once and the run removes the marker
      workstation.wait_until_succeeds(f"test ! -e {gc_dir}/gc-pending", timeout=120)
      assert "nix-store --gc" in in_sandbox("journalctl --no-pager -o cat -t claude-desktop-store-gc")
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
          "${gdbus} call --session --dest org.freedesktop.portal.Desktop"
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
      # A unit of its own beside the app's, outside the sandbox's cgroups, bound to the app's
      assert workstation.succeed(f"cat /proc/{udhcpc}/cgroup").strip().endswith(
          "/claude\\x2ddesktop.slice/claude-desktop-dhcp.service"), udhcpc
      assert "claude-desktop-app.service" in workstation.succeed(
          "systemctl --user -M alice@ show -P BindsTo claude-desktop-dhcp"), "udhcpc isn't bound to the app"

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

  with subtest("the launcher's supervise, which follows the theme, is the app's unit and ends it"):
      main = workstation.succeed("systemctl --user -M alice@ show -P MainPID claude-desktop-app").strip()
      assert "launcher\x00supervise\x00" in workstation.succeed(f"cat /proc/{main}/cmdline"), main
      workstation.succeed("systemctl --user -M alice@ kill --kill-whom=main claude-desktop-app")
      workstation.wait_until_fails("systemctl --user -M alice@ -q is-active claude-desktop-app", timeout=30)
      workstation.wait_until_fails("pgrep -u alice -f 'launcher supervise'", timeout=30)
      workstation.wait_until_fails("pgrep -u alice subid-broker", timeout=30)
      workstation.fail("ls /run/user/1000/claude-desktop/subid-broker-*.sock")
      for unit in ["subid", "dhcp"]:
          workstation.wait_until_fails(f"systemctl --user -M alice@ -q is-active claude-desktop-{unit}", timeout=30)
''
