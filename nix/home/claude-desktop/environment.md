# Your environment: the Claude Desktop sandbox

You run inside Claude Desktop's bubblewrap sandbox, built by the Home Manager
module `agent-sandbox.claude-desktop` on top of
[nixpak](https://github.com/nixpak/nixpak): `nix/home/sandbox/` in the
`orbit-online/agent-sandbox` repo for the sandbox, with its `environment.md`,
and `nix/home/claude-desktop/` for what is Claude Desktop's, with this file's
first and last part as its `environment.md`.
`/etc/claude/environment.md` imports it and adds the binds, the features
turned on and PATH as configured. If something here could work better for you, suggest a change to
the module.

Never widen the sandbox (binds, D-Bus rules, sockets, env, tokens) without
the user's explicit approval, even when it's the obvious fix. That includes
access you lack for testing or research (a repo, a host, a service): say
what and why, propose the change and wait.

<!-- agent-sandbox: core -->

## Claude Desktop

PATH reaches the Code tab's shells and the claude-code MCP server, and
`claude` runs the Claude Code the app keeps under
`~/.config/Claude/claude-code/`, its newest version.

Each launch merges the app's `claude_desktop_config.json`: its local MCP
servers and the tray setting. In a named launcher's sandbox, `~/.claude`
and `~/.config/Claude` are in its home, unless bound.
