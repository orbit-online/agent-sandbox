# Your environment: the Claude Desktop sandbox

You run inside Claude Desktop's bubblewrap sandbox. This file is
`/etc/claude/environment.md`, built into the sandbox by the Home Manager module
`agent-sandbox.claude-desktop` (`nix/home/claude-desktop/` in the
`orbit-online/agent-sandbox` repo: `default.nix` and this file,
`environment.md`), on top of [nixpak](https://github.com/nixpak/nixpak). If
something here could work better for you, suggest a change to the module;
widening the sandbox (binds, D-Bus rules, sockets, env, tokens) always needs
the user's go first.

## Home

`$HOME` is the host user's home path, but it's yours: on the host it's
`~/.local/share/claude-desktop/home`, and it survives restarts and rebuilds.
Nothing tracks it, so it works as a scratch workbench for tools and notes that
don't belong in a repo. `/tmp` is a private tmpfs, gone on restart.

## What you can see

Only the binds listed at the end, plus the Nix store described below. The rest
of the host (other repos, `~/.ssh`, the user's dotfiles) doesn't exist in
here; if you need something that isn't bound, say what and why, and the user
adds it. `/proc/self/mountinfo` shows the live set.

- Own PID, user, UTS and IPC namespaces (pid 1 is `bwrap`), new session.
  `/.flatpak-info` exists: portals see the app as Flatpak
  `com.nixpak.ClaudeDesktop`.
- Session D-Bus goes through nixpak's `xdg-dbus-proxy`: OpenURI and Settings
  portals and Notifications only. Links open in the host browser via OpenURI.
- Own network namespace with a macvlan on the LAN (DHCP), so host-only
  services (VPN mesh, auth proxies, the host's `127.0.0.1`) are out of reach.
- No SSH agent and no `~/.ssh`; git goes over HTTPS with the PATs set up by
  `~/.claude`.

## Tools

- PATH, for the Code tab's shells and the MCP shell alike: `~/.claude/bin`,
  then the packages listed at the end, then the FHS env's `/usr/bin`.
  `SHELL` is bash from the sandbox's `/run/current-system/sw`; no shell rc
  files come from the host `/etc`.
- A tool is missing: work around it for now (`nix run`, `nix shell`), and in
  the same go add it to the module's `path` and tell the user to rebuild.
- Two local MCP servers serve Cowork and claude.ai through the device bridge:
  - `filesystem`: the binds marked MCP. A `jq` filter strips the client's MCP
    roots, which would otherwise replace that list with Cowork's scratch
    folder.
  - `claude-code` (`claude mcp serve`): shell, Read/Write/Edit. Its commands
    time out after about 60 s.
- Claude Code's Bash tool shadows `grep` and `find` with shell functions
  running its embedded ugrep and bfs. The `SessionStart` hook unsets them
  through `$CLAUDE_ENV_FILE`; `claude mcp serve` runs no hook, so the module
  points its `CLAUDE_ENV_FILE` at a store file doing the same.

## Nix

A single-user store of its own: `~/.local/share/claude-desktop/nix` on the
host, bound rw at `/nix`. No daemon, substitutes from cache.nixos.org only. The
launcher copies the app's closure in and roots it
(`/nix/var/nix/gcroots/claude-desktop`); those paths are bound read-only on
top. When it moves the root it leaves `/nix/var/claude-desktop/gc-pending`
for `~/.claude`'s startup hook to collect.
