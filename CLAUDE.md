# agent-sandbox

Sandboxes for AI agents on NixOS. Today that is Claude Desktop under nixpak
(bubblewrap): its own network namespace with a macvlan on the LAN, its own
single-user Nix store, and an environment doc for the Claude running inside.

## Layout

- `nix/home/claude-desktop/`: the Home Manager module
  `agent-sandbox.claude-desktop` (`default.nix`, with a diagram of the
  sandbox's namespaces at the top), `environment.md`, the default
  `environmentFile`, which `/etc/claude/environment.md` in the sandbox
  imports, and the module's scripts (`*.sh`; `store-gc.sh` and
  `scratchpad-prune.sh` go on the sandbox's PATH for the user's hooks). `default.nix` loads them with its `script` helper: Nix values
  arrive as readonly variables ahead of the script, which names its inputs
  with `: "${VAR:?}"` at the top.
- `nix/nixos/claude-desktop.nix`: the NixOS module. Installs the
  `netns-macvlan` wrapper (`cap_net_admin`, group `users`) when any Home
  Manager user enables the Home Manager module, and asserts they're in
  `users` and have a subuid and subgid range.
- `nix/packages/netns-macvlan/`: the Go helper that gives the sandbox's netns
  its macvlan (`netns-macvlan --help`).
- `nix/packages/subid-broker/`: the Go helper that writes uid and gid maps for
  user namespaces inside the sandbox, and its `newuidmap`/`newgidmap` shims
  (`subid-broker --help`). `bwrap-subid.sh` in the module, the bwrap nixpak
  and the FHS env run, maps the user's subuid range in and starts it.
- `nix/checks/`: the flake checks, see Testing.
- `scripts/claude-desktop-test.sh`: starts a second sandbox built from this
  checkout next to the running one. Run on the host.
- `scripts/nettest.sh`: reachability check, run inside the sandbox.

Flake outputs: `homeModules.claude-desktop`, `nixosModules.claude-desktop`,
`packages.<system>.netns-macvlan`, `packages.<system>.subid-broker`. Consumers import both modules and enable
the Home Manager one per user. The modules carry a `key`, so importing them
twice (nixos-workstation directly and through nixos-andsens' `apps`) is fine.

## Rules

- Module defaults only hold what the module can't work without (the Claude
  paths, the `/etc` entries, the Nix store). Machine- and user-dependent
  settings, such as extra binds, go in the consumer's config.
- The sandbox always gets its own netns with a macvlan. There is no option to
  share the host's; the module asserts it.
- Gates and per-user opt-in live in the consumers.
- `environment.md` is what Claude inside the sandbox knows about it, and
  stays generic: consumers replace it with `environmentFile`. Change it in
  the same commit as the behaviour it describes, and tell the user when a
  consumer's own copy needs the same change.
- Maintenance runs (store GC, scratchpad prune) are the user's: the module
  ships the scripts, the user's hooks run them.
- Anything that widens the sandbox (binds, D-Bus rules, sockets, env,
  devices) needs the user's go.
- Claude doesn't push. Commit locally; a human reviews and pushes.
- Commit subjects: `<area>: <Capitalised summary>`
  (`claude-desktop: Add opt-in /dev/kvm bind`).

## Testing

`nix flake check` runs everything below; run it before every commit. The
checks are in `nix/checks/default.nix` and use a test NixOS system with both
modules and a user alice (the `home-manager` input exists only for it).

- `claude-desktop-eval`: nix-unit runs the flake's `tests` output, with every
  input passed in from the store. Run them directly with `nix run
  --inputs-from . nixpkgs#nix-unit -- --flake .#tests.x86_64-linux`. They
  check that the assertions hold, the NixOS wrapper appears only when a user
  enables the module, for group users, the users-group, subid and
  graphics assertions fire, the netns assertion fires when `sandbox`
  overrides `bubblewrap.network` or `pasta`, the filesystem MCP roots,
  `extraPath` at the front of PATH. The test system imports both modules
  twice.
- `claude-desktop`: builds alice's sandboxed app (the patched asar and the
  `writeShellApplication` scripts check themselves while building) and checks
  its closure: the import of `environment.md` (in the closure) and of
  another `environmentFile`, the binds (with their `src`), the scratchpad,
  `/dev/kvm` and PATH in `claude-environment.md`, and nixpak's
  `bwrap-args.json` (own netns, no `--share-net`, the binds, a module
  default overridden by its sandbox path, the scratchpad's dev bind after
  the `/tmp` tmpfs).
- `netns-macvlan`: the package build runs its Go tests (`main_test.go`),
  including `openNetns` against a child in its own user and network
  namespace.
- `subid-broker`: the package build runs its Go tests (`main_test.go`):
  `parseMap`, and `authorize` against a client in a userns of its own and a
  target below it, refusing a client outside one, a sibling userns, the
  client's own and another uid.
- `scripts`: shellcheck on `scripts/` and the module's scripts.
- `vm`: NixOS VM test (`nix/checks/vm.nix`, needs KVM). A router VM runs
  dnsmasq for DHCP and DNS and stands in for the internet: its DNS points
  api.anthropic.com and github.com at itself, which listens on 443. On the
  workstation VM, alice launches the sandbox with a stub app
  (`nix/checks/stub-app.nix`, shaped like the real package so the asar patch
  and FHS overrides apply), and a fake portal (`nix/checks/fake-portal.py`)
  serves the color scheme on her session bus. The test covers the setcap
  wrapper, the launcher refusing a missing bind source that isn't optional,
  the store sync, the subid maps (alice's auto range in the sandbox's userns
  from the host's view, the FHS env's identity map, `/etc/subuid` and
  `/etc/subgid` inside, `unshare --map-auto` and a root-mapping map through
  the shims and the broker, the shim in `/usr/bin`, a file written inside
  owned by alice, no capabilities over the netns, the broker refusing a
  client on the host and ending with the app), the scratchpad bind (mode 0700) and
  `claude-desktop-scratchpad-prune`, `claude-desktop-store-gc` (due on the
  marker and after a week, not otherwise, refused on the host), the GTK theme following the color scheme (at
  launch, live, and the watcher ending with the app), the macvlan's DHCP
  lease, route and DNS, its own `/etc/hosts`, the closure's GC root on the
  host and `/etc` bound from the store except passwd, group and machine-id,
  `nettest.sh` inside the sandbox against a host
  service on the LAN address, loopback and a dummy interface, the
  `claude://` re-entry, `claude-desktop --shell` (in the app's namespaces,
  the terminal's `TERM` with the fallback when its `TERMINFO` is missing, and
  starting the app when it isn't running), the wrapper refusing system
  users, and
  `netns-macvlan` refusing a second user, bob, alice's namespaces, each of
  its checks on its own. bob's commands go through `runuser`,
  not `setpriv`, which keeps root's capabilities through the exec. Debug it
  with `nix run .#checks.x86_64-linux.vm.driverInteractive`.

CI (`.github/workflows/check.yaml`) runs `nix flake check` on pushes to
`main` and on pull requests.

Every new test gets the revert check: break the implementation, see the test
fail, restore it.

Beyond the checks:

- In a consumer: build its config with `--override-input agent-sandbox
  path:<this checkout>`.
- On the host: `scripts/claude-desktop-test.sh` runs the real app from this
  checkout. Inside that sandbox, `scripts/nettest.sh HOST:PORT...` checks
  that the given host-only services are unreachable and the internet is
  reachable.
