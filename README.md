# agent-sandbox

An agent with a shell runs as you. It can read `~/.ssh`, every repo you have
checked out, and the browser profile, and it can reach whatever your machine
can: the VPN mesh, the auth proxy on `127.0.0.1`, the cluster API behind them.
One prompt injection in a README it was asked to summarise is enough to use
all of that.

agent-sandbox runs Claude Desktop (with its Code tab) in a bubblewrap sandbox
on NixOS, built with [nixpak](https://github.com/nixpak/nixpak). It sees only
the paths you bind into it. It gets its own network namespace with a macvlan
on the LAN, so it reaches the internet like any other machine on your network
but none of the host's VPN routes or local services. It has its own
single-user Nix store, so `nix shell` and `nix build` work without the host's
daemon. The only privileged part is a small helper, `netns-macvlan`, with
`cap_net_admin` to give the sandbox's namespace its interface.

The sandbox comes with a doc for the Claude running inside it,
`/etc/claude/environment.md`, which says what it can see and where its limits
are. Your own `CLAUDE.md` imports it.

How it fits together, namespace by namespace: the diagram at the top of
[`nix/home/claude-desktop/default.nix`](nix/home/claude-desktop/default.nix).
Working on the repo: [`CLAUDE.md`](CLAUDE.md).

## Usage

Import both modules and enable the Home Manager one per user:

```nix
{
  inputs.agent-sandbox.url = "github:orbit-online/agent-sandbox";

  # In the NixOS configuration
  imports = [ inputs.agent-sandbox.nixosModules.claude-desktop ];
  hardware.graphics.enable = true;
  home-manager.sharedModules = [ inputs.agent-sandbox.homeModules.claude-desktop ];
  home-manager.users.alice.agent-sandbox.claude-desktop = {
    enable = true;
    # Keyed by the path in the sandbox, `src` is the host path (default: the same)
    binds."/home/alice/src/project".rw = true;
  };
}
```

The NixOS module installs `netns-macvlan` for group `users`, so the user has
to be in it. Then add `@/etc/claude/environment.md` to `~/.claude/CLAUDE.md`.

Other options: `extraPath` (directories ahead of the PATH packages),
`environmentFile` (your own version of
[`environment.md`](nix/home/claude-desktop/environment.md)), `environmentText`
(appended to it), `env`, `path`, `mcpServers`, `kvm`, `audio`, `tray` and
`sandbox` (extra nixpak configuration). The descriptions are in
[`default.nix`](nix/home/claude-desktop/default.nix).

## State and maintenance

Everything the sandbox keeps lives in `~/.local/share/claude-desktop` on the
host: `home/` (the sandbox's `$HOME`), `nix/` (its store, at `/nix`) and
`tmp-scratchpad/` (Claude Code's temp dir with the session scratchpads, at
`/tmp/claude-<uid>`, so they survive restarts). The rest of `/tmp` is a
tmpfs.

Two scripts on the sandbox's PATH keep it in check. Nothing runs them on its
own; hook them into Claude Code's `SessionStart`, detached:

- `claude-desktop-store-gc` collects the sandbox's store after the launcher
  has moved its GC root (on every rebuild that changes the sandbox), and
  otherwise once a week. It refuses to run outside the sandbox.
- `claude-desktop-scratchpad-prune` removes session scratchpads with nothing
  changed in 30 days.

The shipped `environment.md` tells Claude to offer setting up that hook.
