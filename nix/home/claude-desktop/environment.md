# Your environment: the Claude Desktop sandbox

You run inside Claude Desktop's bubblewrap sandbox, built by the Home Manager
module `agent-sandbox.claude-desktop` on top of
[nixpak](https://github.com/nixpak/nixpak): `nix/home/claude-desktop/` in the
`orbit-online/agent-sandbox` repo, with this file as `environment.md`.
`/etc/claude/environment.md` imports it and adds the binds and PATH as
configured. If something here could work better for you, suggest a change to
the module; widening the sandbox (binds, D-Bus rules, sockets, env, tokens)
always needs the user's go first.

## First startup

Two maintenance scripts come with the sandbox, on PATH. Nothing runs them on
its own:

- `claude-desktop-store-gc`: collects the sandbox's Nix store (see Nix below)
  when the launcher has moved its GC root or the last run is a week old.
  Otherwise it exits right away.
- `claude-desktop-scratchpad-prune`: removes session scratchpads with nothing
  changed in 30 days (see Home).

If no `SessionStart` hook in the user's Claude Code settings calls them, offer
once to add one. It should start both detached (`setsid -f`, output to a log
file), since a GC can take minutes and the session waits for its hooks.

## Home

`$HOME` is the host user's home path, but it's yours: on the host it's
`~/.local/share/claude-desktop/home`, and it survives restarts and rebuilds.
`/tmp` is a private tmpfs, gone on restart, except Claude Code's temp dir
`/tmp/claude-<uid>`. That one, with the session scratchpads in it, is bound
from `~/.local/share/claude-desktop/tmp-scratchpad` on the host and survives.

## What you can see

The binds listed in `/etc/claude/environment.md`, plus the Nix store described
below. The rest of the host (other repos, `~/.ssh`, the user's dotfiles)
doesn't exist in here; if you need something that isn't bound, say what and
why, and the user adds it. `/proc/self/mountinfo` shows the live set.

- Own PID, user, UTS and IPC namespaces (pid 1 is `bwrap`), new session.
  Portals see the app as Flatpak `com.nixpak.ClaudeDesktop` (nixpak's
  `/.flatpak-info`, which the FHS env's inner bwrap doesn't bind).
- Session D-Bus goes through nixpak's `xdg-dbus-proxy`: OpenURI and Settings
  portals and Notifications only. Links open in the host browser via OpenURI.
- Own network namespace with a macvlan on the LAN (DHCP), so host-only
  services (VPN mesh, auth proxies, the host's `127.0.0.1`) are out of reach.
- No SSH agent and no `~/.ssh`.

## Tools

- PATH, for the Code tab's shells and the claude-code MCP server: the
  directories and packages under PATH in `/etc/claude/environment.md`, then
  the FHS env's `/usr/bin`. `SHELL` is bash from the sandbox's
  `/run/current-system/sw`; no shell rc files come from the host `/etc`.
- A tool is missing: work around it for now (`nix run`, `nix shell`), and in
  the same go add it to the module's `path` in the user's config and tell the
  user to rebuild.

## Nix

A single-user store of its own: `~/.local/share/claude-desktop/nix` on the
host, bound rw at `/nix`. No daemon, substitutes from cache.nixos.org only. The
launcher copies the app's closure in and roots it
(`/nix/var/nix/gcroots/claude-desktop`); those paths are bound read-only on
top. When it moves the root it leaves `/nix/var/claude-desktop/gc-pending`,
which `claude-desktop-store-gc` picks up.
