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
named `paseo` there (agents, terminals, schedules). The host reaches the
daemon only through a grant of `port` 6767; set a password in
`config.json` before asking for one.

Each launch writes into Paseo's `config.json` dictation off where unset
(it would download a 631 MB speech model), and the sandbox's MCP servers
and this doc for the agents: `/etc/claude-code/CLAUDE.md` imports this
doc for Claude Code, `~/.claude.json` gets the servers in `mcpServers`
beside your own, and `~/.codex/config.toml` and `~/.codex/AGENTS.md` get
them in a block between `agent-sandbox: begin` and `end` markers, which
each launch replaces. Edit outside the blocks.
