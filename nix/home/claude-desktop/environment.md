# Your environment: the Claude Desktop sandbox

You run inside Claude Desktop's bubblewrap sandbox, built by the Home Manager
module `agent-sandbox.claude-desktop` on top of
[nixpak](https://github.com/nixpak/nixpak): `nix/home/claude-desktop/` in the
`orbit-online/agent-sandbox` repo, with this file as `environment.md`.
`/etc/claude/environment.md` imports it and adds the binds and PATH as
configured. If something here could work better for you, suggest a change to
the module.

Never widen the sandbox (binds, D-Bus rules, sockets, env, tokens) without
the user's explicit approval, even when it's the obvious fix. That includes
access you lack for testing or research (a repo, a host, a service): say
what and why, propose the change and wait.

<!-- memo-doc: topic=sandbox # The sandbox you run in: its home, what survives a restart, its namespaces -->
<!-- memo-doc: topic=nix # Nix: building, running and installing packages, the Nix store -->
<!-- memo-doc: topic=containers # Containers and user namespaces: podman, unshare, subordinate ids -->
<!-- memo-doc: activity=self-diagnostic # Checking that the agent's setup works as its config says -->

## Services and logs

A `systemd --user` runs in the sandbox, started right after the app in the
cgroup `user/` beside the app's `app/`, and gone with it. `systemctl --user`
reaches it over its private socket. It has no D-Bus, so `systemd-run`'s
`--wait`, `--pipe`, `--pty` and `--shell` don't work; its units get the
session bus. Its timers run `claude-desktop-store-gc` weekly and when the
launcher moved the store's GC root (see Nix), and
`claude-desktop-scratchpad-prune` daily (see Home), catching up after a time
the sandbox wasn't running. Units of your own go in `~/.config/systemd/user`.
Without the manager (see Tools, `nsdelegate`) none of this runs.

The launcher logs to two journald namespaces, `claude-desktop` for the
default launcher and `claude-desktop-<name>` for a named one
(`ls /var/log/journal` shows which):

- The sandbox's, the one `journalctl`, `logger` and `systemd-cat` use by
  default: the app's output (Chromium's stderr) and the manager's units.
- The host side's, which you read but can't write to:
  `journalctl --namespace=<it>`. The launcher (its warnings about the
  start among it), the permissions broker,
  subid-broker and the D-Bus proxy. When something on the session bus
  doesn't work, look for the proxy's refusals there
  (`-t dbus-proxy -p warning`, `msg=Refused` with the call's destination,
  path, interface and member).

On the host they're `journalctl --namespace=claude-desktop[-<name>]` and
`--namespace=claude-desktop[-<name>]_sandbox`.

## Home
<!-- memo: topic=sandbox -->

The user can run several of these sandboxes side by side, each from its own
launcher with a state dir of its own on the host:
`~/.local/share/claude-desktop` for the default one,
`~/.local/share/claude-desktop-<name>` for a named one. The binds in
`/etc/claude/environment.md` show which one this is.

`$HOME` is the host user's home path, but it's yours: on the host it's `home/`
in the state dir, and it survives restarts and rebuilds. In a named launcher's
sandbox, `~/.claude` and `~/.config/Claude` are in it too, unless bound.
`/tmp` is a private tmpfs, gone on restart, except Claude Code's temp dir
`/tmp/claude-<uid>`. That one, with the session scratchpads in it, is bound
from `tmp-scratchpad/` in the state dir and survives.

Each launch rewrites `~/.config/user-dirs.dirs`, `~/.config/resolv.conf` and
the app's `claude_desktop_config.json` (merged), replacing links there, and
the GTK theme in `~/.config/glib-2.0/settings/keyfile` follows the desktop's.
The launcher does that, and its work on your store, in a bwrap that sees
nothing of the host but those directories, so links in them never reach the
host's files.

## What you can see

The binds listed in `/etc/claude/environment.md`, plus the Nix store described
below. The rest of the host (other repos, `~/.ssh`, the user's dotfiles)
doesn't exist in here; if you need something that isn't bound, propose the
bind in the user's config and wait for their go. `/proc/self/mountinfo` shows
the live set. With the `permissions` MCP server, ask through it instead for
what its `list` offers: the user answers on the host, and grants show up under
`/run/permissions`. Grants with lease `standing` come from the configuration
and are there from the start. Its tools named `<capability>_<command>` run
commands on the host: a call asks the user for a grant of the capability
unless one covers it. Host sockets sit at fixed addresses under
`/run/permissions/sockets/`: a connection without a grant is closed at once,
so ask first. A grant is the whole sandbox's and lasts its lease (an hour
unless you ask otherwise); release it when you're done.

- Own PID, user, UTS and IPC namespaces (pid 1 is `bwrap`), new session.
  Portals see the app as Flatpak `com.anthropic.Claude`, or
  `com.anthropic.Claude.<name>` for a named launcher (nixpak's
  `/.flatpak-info`, which the FHS env's inner bwrap doesn't bind).
- Session D-Bus goes through a filtering proxy on the host (the module's
  `dbus-proxy`, started by nixpak in place of xdg-dbus-proxy), which lets through
  calls only: OpenURI, Settings and Notification on the portal, and with the
  tray the StatusNotifierWatcher's registration. Of their broadcasts, only the
  portal's `SettingChanged` gets in. Notifications go through the
  portal (`NOTIFY_FORCE_PORTAL=1` for libnotify, `notify-send`); the
  notification server itself (`org.freedesktop.Notifications`) and anything
  else the desktop's processes export are out of reach. Links open in the
  host browser via OpenURI. There is no system bus. Processes running as a
  subuid can't connect to the session bus.
- Own network namespace, joined to the host by a netkit pair (`eth0`
  here). Its programs let packets out only through the physical uplinks of
  the host (Ethernet and Wi-Fi), NATed there, and only replies back in: the
  addresses of the host (its `127.0.0.1` and LAN address included),
  host-only networks (VPN mesh, container bridges, auth proxies) and other
  sandboxes are out of reach. Behind a full-tunnel VPN you still leave through the
  physical uplink with the default route, never into the VPN. Addresses:
  an IPv4 /32 from `169.254.100.0/22` and an IPv6 /128 from a ULA /48 of
  the machine, both stable per launcher, with default routes through
  `eth0`. The host reaches a port of yours only while the user grants it,
  and the LAN never does: listen on it (on `::` or `0.0.0.0`), then
  `request` the capability `port` with `params`
  `{"protocol": "tcp", "port": 8080}` (or `udp`) and a reason.
  The `addresses` of the grant say where the host user reaches it
  (`<IPv4>:8080` and `[<IPv6>]:8080`); tell them. Connections the host
  opened end with the grant.
  DNS: `/etc/resolv.conf` lists the `nameservers` option of the launcher,
  or without it the servers that systemd-resolved (or NetworkManager) on
  the host has for the uplink with the default route, and its global ones
  you reach through that uplink, kept current while you run, so LAN names
  resolve as on the host. Servers and domains of a VPN are left out, as
  are servers you can't reach (`127.0.0.53` on the host). An empty file
  means no DNS: the host has neither source nor the option, or none of its
  servers is reachable from here; the launcher logs
  a warning in the journal namespace of the host side then (see Services
  and logs).
  mDNS (`.local` names), unless the launcher has `network.mdns` off: your
  queries to `224.0.0.251` or `ff02::fb` port 5353 leave from the host
  address and port 5353, and the responses on the LAN come back to the
  group here, so only a querier on port 5353 gets them (avahi, or a
  socket on 5353 that joined the group; a one-shot query from another
  port, as `dig -p 5353` sends, gets no answer). Your responses, probes
  and announcements stay in: you can't publish a name on the LAN.
  A launcher with `network.enable` off (for local models) leaves you a
  network namespace with `lo` alone (`ip link` shows no `eth0`): no
  routes, an empty `/etc/resolv.conf` and no `port` capability. A model
  server on the host is then reachable only through a host socket of the
  permissions broker that the user configured, a Unix socket at
  `/run/permissions/sockets/<name>`.
- No SSH agent and no `~/.ssh`.

## User namespaces
<!-- memo: topic={containers,sandbox} -->

Your userns has 65536 ids, the user's subuid and subgid range on the host,
with your own uid and gid kept as themselves, so rootless tools (podman,
`unshare --map-auto`) work. What you create in the binds under any other id
belongs to a subuid on the host, where the user may not be able to change or
remove it.

## Tools

- PATH, for the Code tab's shells and the claude-code MCP server: the
  directories and packages under PATH in `/etc/claude/environment.md`, then
  the FHS env's `/usr/bin`. `SHELL` is bash from the sandbox's
  `/run/current-system/sw`; no shell rc files come from the host `/etc`.
- `claude` runs the Claude Code the app keeps under
  `~/.config/Claude/claude-code/`, its newest version.
- A tool is missing: work around it for now (`nix run`, `nix shell`), and in
  the same go add it to the module's `path` in the user's config and tell the
  user to rebuild.
- Run heavy jobs in a scope of their own, then stop the scope for what they
  left running:
  `systemd-run --user --scope --unit=NAME -p MemoryMax=SIZE -p MemorySwapMax=0 -p CPUWeight=50 -p OOMPolicy=kill -- CMD...`
  and `systemctl --user stop NAME.scope`. Past the limit the kernel kills
  the job, not the app or the user's desktop, and half the app's CPU weight
  keeps the app responsive (1 to 10000 against the app's 100). The whole
  sandbox runs at half the weight of the desktop's own apps. `nix flake
  check` and other big builds also with `--max-jobs 4 --cores 4` (Nix's
  defaults start a builder per core, each using every core), for example
  with `-p MemoryMax=24G` and `nix flake check -L --max-jobs 4 --cores 4`;
  long property or fuzz runs and Alloy too. Size the limit a little above
  the job's measured peak (`systemctl --user show -P MemoryPeak NAME.scope`
  before the stop); the repo's CLAUDE.md may name it. When the host mounts
  cgroup2 without `nsdelegate`, the launcher binds the sandbox's cgroup
  read-only and there's no `systemd --user`: run the job without it, at
  those `--max-jobs` and `--cores`, and tell the user (the launcher's
  warning in the host side's journal namespace, see Services and logs, says
  how to fix the host: `journalctl --namespace=<it> -p warning`).

## Nix
<!-- memo: topic={nix,sandbox} -->

A single-user store of its own: `nix/` in the state dir, bound rw at `/nix`,
and its `store/` bound again at `/nix/store`. The next launch refuses a
`store/` that is a link. If `store/` isn't the one it recorded, or there's
no record (an install from before it kept one), it deletes `nix/` and copies the closure into a fresh one: what was installed in `/nix` before is
gone then. No daemon, substitutes from cache.nixos.org only. The launcher copies the app's
closure in and roots it
(`/nix/var/nix/gcroots/claude-desktop`); those paths are bound read-only on
top. When it moves the root it leaves `/nix/var/claude-desktop/gc-pending`,
which starts `claude-desktop-store-gc` (see Services and logs).

## Self-check
<!-- memo: activity=self-diagnostic environment=bwrap -->

The sandbox:

- Each bind under Binds in `/etc/claude/environment.md` is a mount in
  `/proc/self/mountinfo`, read-write or read-only as listed. One marked as
  present only if the host has it may be missing.
- The binaries of each package under PATH there resolve on PATH.
- pid 1 is `bwrap`, and `/proc/self/uid_map` and `gid_map` hold 65536 ids
  with your own kept as themselves.
- `/nix/var/nix/gcroots/claude-desktop` resolves.
- `systemctl --user is-system-running` says `running`, and
  `systemctl --user list-timers` shows `claude-desktop-store-gc.timer` and
  `claude-desktop-scratchpad-prune.timer`.
- `journalctl -n 1` and `journalctl --namespace=<the host side's> -n 1`
  each show an entry, and `systemd-cat --namespace=<the host side's> true`
  fails.
- `/tmp` is a tmpfs, with Claude Code's temp dir bound on top.
- The host (its `127.0.0.1` and LAN address) is out of reach, the LAN and
  the internet aren't (`scripts/nettest.sh HOST:PORT...` in a checkout of
  orbit-online/agent-sandbox, given services of the host, tests the host
  and the internet). With `network.enable` off, `ip link` shows `lo` alone.

## Permissions self-check
<!-- memo: activity=self-diagnostic environment=bwrap -->

The `permissions` MCP server:

- `/run/permissions/request.sock` is a socket.
- `list` shows each capability the launcher's config declares, with the
  instances it allows, and `status` the standing grants, each with lease
  `standing`.
- Each host socket capability has its address under
  `/run/permissions/sockets/`; a connection without a grant is closed at
  once.
- With the user's go: `request` a read-only grant of a folder `list`
  offers, read a file through it under `/run/permissions`, then `release`
  it and see it gone from `status` and the mount gone.
