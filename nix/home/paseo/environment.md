# Your environment: the Paseo sandbox

You run inside Paseo's bubblewrap sandbox, built by the Home Manager
module `agent-sandbox.paseo` on top of
[nixpak](https://github.com/nixpak/nixpak): `nix/home/sandbox/` in the
`orbit-online/agent-sandbox` repo for the sandbox, with its `environment.md`,
and `nix/home/paseo/` for what is Paseo's, with this file's first and last
part as its `environment.md`.
`/etc/claude/environment.md` imports it and adds the binds, the features
turned on and PATH as configured. If something here could work better for you, suggest a change to
the module.

Never widen the sandbox (binds, D-Bus rules, sockets, env, tokens) without
the user's explicit approval, even when it's the obvious fix. That includes
access you lack for testing or research (a repo, a host, a service): say
what and why, propose the change and wait.

<!-- agent-sandbox: core -->

## Paseo

You are one of the agents Paseo's daemon runs: Claude Code through its
Agent SDK, Codex as `codex app-server`, or another provider. The desktop
app, the daemon and every agent share the sandbox. Each agent gets PATH
from a login shell the app ran at its start (`$SHELL -i -l -c`), so a
`~/.bashrc` or `~/.profile` in this home changes the next launch's agents.

Where things live, in this sandbox's own home unless the binds above say
otherwise:

- `~/.paseo`: Paseo's state: `config.json` (the daemon's settings; it
  reads them only there, not from the environment), its logs, the agents'
  worktrees (`~/.paseo/worktrees/`), schedules and the terminal worker.
- `~/.config/Paseo`: the desktop app's own (Electron's userData).
- `~/.claude`, `~/.claude.json`: Claude Code's. `~/.codex`: Codex's.

The daemon listens on `127.0.0.1:6767` in the sandbox's network
namespace, without a password by default: anything in the sandbox reaches
it, the host and the LAN don't. Paseo gives each agent an MCP server
named `paseo` there (agents, terminals, schedules). A grant of `port`
6767 alone doesn't change that, as it reaches the sandbox's `eth0`
addresses and the daemon listens on loopback. For the host to reach it,
the user sets `daemon.listen` in `config.json` to an address of the
sandbox (`0.0.0.0:6767`), sets a password (`"$PASEO_CLI" daemon set-password`, Paseo's CLI, which
the daemon passes its agents),
restarts Paseo and then grants the port.

Each launch writes into Paseo's `config.json` dictation off where unset
(it would download a 631 MB speech model), and gives the agents the
sandbox's MCP servers and this doc. Claude Code: this doc through
`/etc/claude-code/CLAUDE.md`, the servers in `~/.claude.json`'s
`mcpServers` beside your own (an entry of yours by the same name wins).
Codex: both in its system config, `/etc/codex/config.toml`, read-only,
below your `~/.codex/config.toml`, which wins a key; this doc is its
`developer_instructions` there, so a `developer_instructions` of your
own replaces it.
