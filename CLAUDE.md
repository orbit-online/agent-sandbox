# agent-sandbox

Sandboxes for AI agents on NixOS. Today that is Claude Desktop under nixpak
(bubblewrap): its own network namespace with a macvlan on the LAN, its own
single-user Nix store, and an environment doc for the Claude running inside.

## Layout

- `nix/home/claude-desktop/`: the Home Manager module
  `agent-sandbox.claude-desktop` (`default.nix`, with a diagram of the
  sandbox's namespaces at the top). Its options configure the default
  launcher; `launchers.<name>` adds sandboxes next to it with the same
  options, each built by `launcher` from the module's defaults alone, with its
  own state dir, app ID, MAC and `claude-desktop-<name>`. Then
  `environment.md`, which `environment-split.sh` turns into the default `environmentFile`, which
  `/etc/claude/environment.md` in the sandbox imports: all of it, or with `memo.enable` the sections without a
  `<!-- memo: FILTER -->` marker, the marked ones going into the memo store `/etc/claude/environment.memo`
  (`<!-- memo-doc: ... -->` lines document its values). The store also injects `environment`, the frontmatter's name
  for the environment. Then the module's scripts (`*.sh`; `store-gc.sh` and
  `scratchpad-prune.sh` go on the sandbox's PATH for the user's hooks). `default.nix` loads them with its `script` helper: Nix values
  arrive as readonly variables ahead of the script, which names its inputs
  with `: "${VAR:?}"` at the top.
  What the host does in the sandbox's home and store, which the sandbox can
  write and plant links in, goes through `state.sh`, run by `confine.sh`
  (`claude-desktop[-<name>]-state`) in a bwrap holding only its closure and
  the directories named: links there resolve within that view.
- `nix/nixos/claude-desktop.nix`: the NixOS module. Installs the
  `netns-macvlan` wrapper (`cap_net_admin`, group `users`) when any Home
  Manager user enables the Home Manager module, and asserts they're in
  `users` and have a subuid and subgid range.
- `go.mod`, `cmd/`, `internal/`: one Go module for the Go helpers below,
  each in `cmd/<binary>`, with `internal/` for what they share (`proc`: the
  pid behind a pidfd and whether it still runs). Their packages in
  `nix/packages/<binary>/` build it with `subPackages`, from a source
  filtered to `go.mod`, `go.sum`, the binary's directory and the `internal/`
  packages it uses, each with its own `vendorHash` (Go vendors only what the
  binary imports). permissions-window has a module of its own, so miqt's cgo
  and Qt stay out of the others' closures.
- `cmd/netns-macvlan/`: the Go helper that gives the sandbox's netns
  its macvlan (`netns-macvlan --help`).
- `cmd/subid-broker/`: the Go helper that writes uid and gid maps for
  user namespaces inside the sandbox, and its `newuidmap`/`newgidmap` shims
  (`subid-broker --help`). `bwrap-subid.sh` in the module, the bwrap nixpak
  and the FHS env run, maps the user's subuid range in and starts it.
- `cmd/permissions-broker/`: the Go daemon that grants the sandbox
  outside access while it runs, per `docs/permissions.md`, and the sandbox's
  `permissions` MCP server (`permissions-broker --help`). A launcher runs it
  with `permissions.enable`, off by default: `claude-desktop.sh` starts it as a
  user unit, nixpak binds its grant directory read-only at `/run/permissions`,
  and `bwrap-subid.sh` asks it to share that mount before the FHS env's bwrap.
  One concern per file: `sockets.go` (listening, peer checks, the request and
  control handlers), `consent.go`, `leases.go` (and logind), `store.go`
  (always grants, replay, the log), `notify.go`, `views.go`, `types.go` and
  `run.go`; `plugins.go`, `instances.go` (`list`, the instance check and exclusive
  locks) and `plugintools.go` for plugins and their MCP tools,
  `mcp.go` the MCP server, `sandbox.go` finding and pinning the sandbox, `members.go` its processes by
  user namespace, `session.go` sessions.
  The attach type: `ceiling.go` (the source ceiling, by path and identity), `tree.go`
  (the clone helper it runs through `nsenter` to clone a host path),
  `helpers.go` (the helpers that join the sandbox's mount namespace only after
  their exec on the host's mounts, to share the grant directory and mount and
  unmount grants there), `mountinfo.go` (mount tables, the grant's mount), `scan.go` (the holders' scan) and `attach.go`
  (mounting, unmounting, cleanup). Each `*_test.go` follows its file;
  `main_test.go` has `TestMain` and the shared fakes.
- `nix/packages/permissions-folders/`: the broker's built-in attach plugin,
  a manifest and two jq scripts. `permissions.folders` lists what it may
  grant.
- `nix/packages/permissions-window/`: the Permissions window (Go with miqt's
  Qt 6 bindings, and QML), a client of the broker's `control.sock`. miqt has
  no moc, so the QML talks to Go through a `QQmlPropertyMap`: state as JSON
  in, actions as JSON out (`window.go` holds the logic, `main.go` the Qt
  glue). The launcher opens it with
  `--permissions` and the `.desktop` file's "Permissions" action; the broker
  opens it on a notification's Options. Its wrapper sets Qt's plugin and QML
  paths to its own Qt's, Plasma's style and platform theme included: the
  host's may be another Qt.
- `nix/checks/`: the flake checks, see Testing.
- `docs/permissions.md`: design of the permissions broker. Built so far:
  everything but device grants.
- `scripts/claude-desktop-test.sh`: starts a second sandbox built from this
  checkout next to the running one. Run on the host.
- `scripts/nettest.sh`: reachability check, run inside the sandbox.
- `scripts/ns-inject-spike.py`: spike for binding host folders and device
  nodes into a running sandbox and detaching them, against two nested bwraps
  shaped like the sandbox's. Run inside the sandbox with a bwrap path; not
  part of the checks.

Flake outputs: `homeModules.claude-desktop`, `nixosModules.claude-desktop`,
`packages.<system>.netns-macvlan`, `packages.<system>.subid-broker`,
`packages.<system>.permissions-broker`, `packages.<system>.permissions-window`,
`packages.<system>.permissions-folders`. Consumers import both modules and enable
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
  stays generic: consumers replace it with `environmentFile`. A section only
  some work needs gets a memo marker; one every session needs stays unmarked.
  Change it in
  the same commit as the behaviour it describes, and tell the user when a
  consumer's own copy needs the same change.
- Maintenance runs (store GC, scratchpad prune) are the user's: the module
  ships the scripts, the user's hooks run them.
- Anything that widens the sandbox (binds, D-Bus rules, sockets, env,
  devices) needs the user's go.
- Claude doesn't push. Commit locally; a human reviews and pushes.
- A Go file stays under about 400 lines, tests included, and holds one
  concern: longer files can't be audited.
- Commit subjects: `<area>: <Capitalised summary>`
  (`claude-desktop: Add opt-in /dev/kvm bind`).

## Testing

`nix flake check` runs everything below; run it before every commit. The
checks are in `nix/checks/default.nix` and use a test NixOS system with both
modules and a user alice (the `home-manager` input exists only for it).

- `claude-desktop-eval`: nix-unit runs the flake's `tests` output, with every
  input passed in from the store. Run them directly with `nix run
  --inputs-from . nixpkgs#nix-unit -- --flake .#tests.x86_64-linux`. They
  check that the assertions hold (with memo too), the memo assertion, the
  files, package and `environmentFile` a launcher with `memo.enable` gets
  (and the default launcher doesn't), the NixOS wrapper appears only when a user
  enables the module, for group users, the users-group, subid and
  graphics assertions fire, the netns assertion fires when `sandbox`
  overrides `bubblewrap.network` or `pasta`, the filesystem MCP roots,
  `extraPath` at the front of PATH, the launchers' packages, the launcher
  name and per-launcher netns assertions, a tray on two launchers at once,
  a launcher's MCP roots without `~/.claude`, and `programs.mcp.servers` in
  every launcher's MCP servers (disabled ones out, env files wrapped, none
  without `programs.mcp.enable`, the assertion on remote servers and the
  sandbox's names), the `permissions` MCP server only with
  `permissions.enable`, and the assertion on binds that reach a launcher's
  state dir or `$XDG_RUNTIME_DIR`. The test system imports both modules twice and has a launcher
  `work`.
- `claude-desktop`: builds alice's sandboxed app (the patched asar and the
  `writeShellApplication` scripts check themselves while building) and checks
  its closure: the import of `environment.md` (in the closure, all
  sections, no markers) and of another `environmentFile`, the binds (with their `src`), the scratchpad,
  the devices (`/dev/kvm` once, from `kvm` and `devices`) and PATH in `claude-environment.md`, the patched asar's tray
  icon (by the colour scheme, also on GNOME), the notification patch (on a
  4.x-shaped asar: the native backend never picked, an app with two such places
  refused), and nixpak's
  `bwrap-args.json` (own netns, no `--share-net`, the binds, a module
  default overridden by its sandbox path, the devices' dev binds, the scratchpad's dev bind after
  the `/tmp` tmpfs, `/nix/store` bound after `/nix`), the launcher's
  `HOME_DIRS` and its state script's paths, `app-pid.sh` dropping ambient capabilities when it can't
  set the pid, and the `files` in the FHS env's bwrap (a directory's
  bind before a file's in it, a disabled one left out, what a file
  references in the closure). For `work`: its wrapper alone in `bin`, its app ID,
  `~/.claude` and the app's config in its home, its GC root link, the name
  netns-macvlan gets, its `claude-environment.md` (with memo: the core
  import, its pointer to memo, the store and memo's config in the FHS env,
  the store right after the embedded ones), its permissions broker (the
  read-only `/run/permissions` bind, the config, the wrapper's variables; none
  of it for the default launcher), and its `.desktop` file (name, Exec, the
  Permissions action, which the default launcher lacks, no `claude://`
  handler).
- `netns-macvlan`: the package build runs its Go tests (`main_test.go`),
  including `openNetns` against a child in its own user and network
  namespace, and the user namespace chain: a netns two user namespaces down
  accepted, refused from a sibling user namespace's view and for one owned by
  the caller's own.
- `subid-broker`: the package build runs its Go tests (`main_test.go`):
  `parseMap`, and `authorize` against a client in a userns of its own and a
  target below it, refusing a client outside one, a sibling userns, the
  client's own and another uid, and `dieWith` ending the broker when the
  parent it was given is gone already.
- `permissions-broker`: the package build runs its Go tests (`*_test.go`):
  durations, parameter validation, consent (denied, allowed, a live grant
  covering the same request only), a request or window answer naming no instance
  a capability's `list` prints refused without asking (and with a failing
  `list`; not for attach capabilities), and an Allow refused when the instance went away
  while the user was asked, a replay of an always grant `list` no longer
  prints, the refusal limit, `always` only from the
  window and with exact parameters, and gone from the store when revoked, the store, duration, lock (none granted when the lock stops being
  watched while the user is asked) and session
  leases (a session anchored at a copy of the test binary named `claude`, none
  at another name), service units in systemd (faked), exclusive instances across
  launchers (locked by the instance `list` prints, whatever other parameters
  a request carries; the default launcher's cleanup leaving a lock without content alone), `share` through nsenter into a child's user and mount namespace
  (refused from another mount namespace, a second time, and once a process of
  the sandbox is in a copy of its mount namespace), `control.sock` refusing a peer in
  another user namespace, a peer gone after its `/proc` entries were read
  refused by `control.sock`, `share` and `request` (S13), the sandbox's
  namespaces pinned (helpers refused once its pid moves to namespaces of its
  own) and not found from a stale instance directory or in a user namespace
  that isn't a child of ours, the sockets end to end with `watch` events, and what
  the sandbox can't do to it: hold every connection (control.sock still
  answers, idle clients time out), send an oversized request, dress up a
  parameter or reason in the notification, make a click on its replacement of
  the broker's notification or an `ActionInvoked` of its own allow (a fake
  notification server on a `dbus-daemon` of the test's), anchor a session at or above the
  sandbox or, from a re-entry (`--shell`), at a host session above nsenter, make one always grant start several units or
  mount an always folder twice (replays, a second `share`), get a command's output after
  its lease ran out or for a grant revoked while its request waited for a
  plugin slot, or hold every plugin slot with one capability whose commands hang (another's run, and its own
  `list` for the window); plus a window answer while the notification is up, pending requests
  in arrival order, unit
  names per launcher, and a broken store set aside. Attach grants against a stand-in
  sandbox (a child in a user and mount namespace of its own with the grant
  directory bound in and shared): the source ceiling, a folder mounted
  read-only where the app sees it and not on the host, its holders listed and
  ended (one ignoring SIGTERM too; one holding it on a thread alone, by that thread's cwd, fd, root,
  mount namespace or an `open_tree` clone in no mount table; a clone of a file of it as a possible
  holder; not a process outside the sandbox; a re-entry's too, found by user
  namespace; on a release from inside too, and not a process by a stale
  record), detached before the holders' scan starts, with its mountpoint
  gone on revoke, a session lease two sessions hold, a release dropping only the releasing
  session's hold (the grant ends with the last, or at once for a caller
  without a session), a daemon started again
  taking over the shared grant directory and replaying an always folder, and
  the sandbox's attacks: a link out of the ceiling, a ceiling root swapped for
  a link, a link to a denied directory, a denied directory under another name
  (found by identity, as the source or beneath it), and a re-bind in a nested
  mount namespace (reported as a holder), a rename of the grant directory in M1
  hiding no holder, and the swap of a directory that is a
  mountpoint in the stand-in's mount namespace from a nested one (pivot_root,
  the old root detached, then a rename): the store directory holding the
  helpers' binary (they still run the daemon's) and the grant directory for a
  link to another mount (not unmounted by a revoke). The MCP server: a service plugin's
  tools (a fake plugin speaking MCP on a socket) offered while its grant
  lives, a call forwarded, a second grant's under names of their own, each
  withdrawn with its grant and every change sent as `list_changed`, also
  for a plugin answering bare JSON-RPC; a hanging plugin holding up only its
  own grant, which is tried again once it answers; a failed offer tried
  again; two tools of a grant under one name told apart; the nudge after 15
  minutes, not again right after, and in tool results; service units bound
  to the daemon's unit, and the cleanup a stopped daemon's `ExecStopPost`
  runs (units stopped, locks removed, folder grants detached, mountpoints
  removed, also without the sandbox).
- `permissions-window`: the package build runs, offscreen in Plasma's
  style, its Go tests (`window_test.go`: the operations against a fake
  `control.sock`, and the Qt glue, checked in `TestMain` since Qt wants the
  main thread: loading without QML warnings, the state arriving, a click
  reaching the broker through the property map) and `tst_permissions.qml`
  through `qmltestrunner` against a mock broker: an answer narrowed in its
  fields (kept through a refresh that rebuilds the list), deny, revoke then end (the holders of ended grants from the state, a possible one marked),
  forget, a repeated action still a change, Allow and Deny off for a second after a pending row moved up.
  Repeater delegates aren't QObject children, so the Go side can't find
  them; Qt Quick Test can.
- `scripts`: shellcheck on `scripts/` and the module's scripts.
- `vm`: NixOS VM test (`nix/checks/vm.nix`, needs KVM). A router VM runs
  dnsmasq for DHCP and DNS and stands in for the internet: its DNS points
  api.anthropic.com and github.com at itself, which listens on 443. On the
  workstation VM, alice launches the sandbox with a stub app
  (`nix/checks/stub-app.nix`, shaped like the real package so the asar patch
  and FHS overrides apply), and a fake portal (`nix/checks/fake-portal.py`)
  serves the color scheme on her session bus. The test covers the setcap
  wrapper, links the sandbox planted in its state (a store dir that's a link
  refused, links in its home replaced, alice's files neither read nor written,
  the keyfile swapped for a link while it runs, the store dir swapped for a
  directory of its own between launches refused), `/nix/store` not renameable
  inside directly, the launcher refusing a missing bind source that isn't optional,
  the store sync, the app's tray item (it owns
  `StatusNotifierItem-<pid>-1` through the proxy at the pid `app-pid.sh`
  set, with no capabilities left), D-Bus through the proxy (`notify-send` reaching the fake portal's
  notifications; a fake Plasma on the fake portal's process: the tray's
  registration reaches it, its notification server, clipboard and another kded
  object don't, by name or by unique name), the subid maps (alice's auto range in the sandbox's userns
  from the host's view, the FHS env's identity map, `/etc/subuid` and
  `/etc/subgid` inside, `unshare --map-auto` and a root-mapping map through
  the shims and the broker, the shim in `/usr/bin`, a file written inside
  owned by alice, no capabilities over the netns, the broker refusing a
  client on the host and ending with the app), the scratchpad bind (mode 0700) and
  `claude-desktop-scratchpad-prune`, `claude-desktop-store-gc` (due on the
  marker and after a week, not otherwise, refused on the host), the GTK theme following the color scheme (at
  launch, live, and the watcher ending with the app), the macvlan's DHCP
  lease, route and DNS (udhcpc in a mount namespace of its own with its
  closure and the sandbox's home, none of alice's files), the launcher `work` running next to the default
  sandbox (its own namespaces, MAC and lease, its own tray item at another
  pid, its re-entry found by app ID, its state dir and GC root, and its
  permissions broker: the daemon's unit and its start limit, `/run/permissions` read-only, shared
  in the outer mount namespace and a slave where the app runs, `share` refused
  from there, a grant of a test plugin through the MCP server after a restart
  of the daemon with `always` grants stored, a SIGKILL of the daemon ending
  its service unit and its folder grant, both back under new ids after its
  restart, an `always` folder then mounted
  read-only, nodev and nosuid where the app runs and one with a mount beneath
  it refused, an `always` service plugin socket-activated by systemd whose tool
  the MCP server inside offers and forwards a call to, the Permissions window
  staying
  up against it, the daemon ending with the sandbox), its own `/etc/hosts`, the closure's GC root on the
  host and `/etc` bound from the store except passwd, group and machine-id,
  `nettest.sh` inside the sandbox against a host
  service on the LAN address, loopback and a dummy interface, a `files`
  script each under `/etc` and `~/.config` running what it references, the
  `claude://` re-entry (in the app's netns and pid ns), both re-entries
  past a process at the app's pid in a pid ns of the sandbox's own, `XDG_CURRENT_DESKTOP`
  with COSMIC ahead of GNOME (KDE as is), `claude-desktop --shell` (in the app's namespaces, with no_new_privs as `claude://` has it,
  the terminal's `TERM` with the fallback when its `TERMINFO` is missing, and
  starting the app when it isn't running), the wrapper refusing system
  users, and
  `netns-macvlan` refusing a second user, bob, alice's namespaces, each of
  its checks on its own, and alice a netns of hers below a user namespace
  root made and mapped her uid into. bob's commands go through `runuser`,
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
