# agent-sandbox

Sandboxes for AI agents on NixOS. Today that is Claude Desktop under nixpak
(bubblewrap): its own network namespace with a macvlan on the LAN, its own
single-user Nix store, and an environment doc for the Claude running inside.

## Layout

- `nix/home/claude-desktop/`: the Home Manager module
  `agent-sandbox.claude-desktop` (`default.nix`, with a diagram of the
  sandbox's namespaces at the top) and `environment.md`, which ships as
  `/etc/claude/environment.md` in the sandbox.
- `nix/nixos/claude-desktop.nix`: the NixOS module. Installs the
  `netns-macvlan` wrapper (`cap_net_admin`) when any Home Manager user enables
  the Home Manager module.
- `nix/packages/netns-macvlan/`: the Go helper that gives the sandbox's netns
  its macvlan (`netns-macvlan --help`).
- `scripts/claude-desktop-test.sh`: starts a second sandbox built from this
  checkout next to the running one. Run on the host.
- `scripts/nettest.sh`: reachability check, run inside the sandbox.

Flake outputs: `homeModules.claude-desktop`, `nixosModules.claude-desktop`,
`packages.<system>.netns-macvlan`. Consumers import both modules and enable
the Home Manager one per user.

## Rules

- Module defaults only hold what the module can't work without (the Claude
  paths, the `/etc` entries, the Nix store). Machine- and user-dependent
  settings, such as extra binds, go in the consumer's config.
- The sandbox always gets its own netns with a macvlan. There is no option to
  share the host's; the module asserts it.
- Gates and per-user opt-in live in the consumers.
- `environment.md` is what Claude inside the sandbox knows about it. Change it
  in the same commit as the behaviour it describes.
- Anything that widens the sandbox (binds, D-Bus rules, sockets, env,
  devices) needs the user's go.
- Claude doesn't push. Commit locally; a human reviews and pushes.
- Commit subjects: `<area>: <Capitalised summary>`
  (`claude-desktop: Add opt-in /dev/kvm bind`).

## Testing

`nix flake check` runs everything below; run it before every commit. The
checks are in `nix/checks/default.nix` and use a test NixOS system with both
modules and a user alice (the `home-manager` input exists only for it).

- `claude-desktop-eval`: assertions hold, the NixOS wrapper appears only when
  a user enables the module, the netns assertion fires when `sandbox`
  overrides `bubblewrap.network` or `pasta`, the filesystem MCP roots.
- `claude-desktop`: builds alice's sandboxed app (the patched asar and the
  `writeShellApplication` scripts check themselves while building) and checks
  its closure: the binds, `/dev/kvm` and PATH in `claude-environment.md`, and
  nixpak's `bwrap-args.json` (own netns, no `--share-net`, the binds).
- `netns-macvlan`: the package build runs its Go tests (`main_test.go`),
  including `openNetns` against a child in its own user and network
  namespace.
- `scripts`: shellcheck on `scripts/`.

Every new test gets the revert check: break the implementation, see the test
fail, restore it.

Beyond the checks:

- In a consumer: build its config with `--override-input agent-sandbox
  path:<this checkout>`.
- On the host: `scripts/claude-desktop-test.sh` runs the real app from this
  checkout. Inside that sandbox, `scripts/nettest.sh HOST:PORT...` checks
  that the given host-only services are unreachable and the internet is
  reachable.
