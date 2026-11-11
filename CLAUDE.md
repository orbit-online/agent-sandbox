# agent-sandbox

Sandboxes for AI agents on NixOS. Today that is Claude Desktop under nixpak
(bubblewrap): its own network namespace with a macvlan on the LAN, its own
single-user Nix store, and an environment doc for the Claude running inside.

## Layout

- `nix/home/claude-desktop/`: the Home Manager module
  `agent-sandbox.claude-desktop` (`default.nix`, with a diagram of the
  sandbox's namespaces at the top). Its options configure the default
  launcher; `launchers.<name>` adds sandboxes next to it with the same
  options, each starting from the module's defaults alone, with its
  own state dir, app ID, MAC and `claude-desktop-<name>`. Each launcher, the default one included, is a
  `submoduleWith` of the same feature modules, which take `launcherName` (null for the default one), Home Manager's
  config as `hm` and the shared helpers of `lib.nix` as `sl`, and meet in the internal `build` options
  (`build.nix`: store roots, nixpak config, FHS bwrap arguments, the launcher's JSON config (`cmd/launcher`), the
  `.desktop` actions, assertions): `options.nix` (the general options), `core.nix` (nixpak's config, the binds every
  launcher starts with, the confined state script), `fhs.nix` (the app in its FHS env, `/etc`,
  `/run/current-system/sw`), `environment.nix` (`environment.md` and memo), `network.nix`, `store.nix`, `theme.nix`,
  `mcp.nix` (with `channels.js`, which `patch-asar.sh` hooks into the app for `mcpChannels`), `dbus.nix` (and the tray), `permissions.nix` with `permissions-broker.nix` and `permissions-checks.nix`,
  `request-send.nix`, and `launch.nix` (the launcher, the app's unit, the `.desktop` file). Modules in
  `agent-sandbox.launcherModules` join them on every launcher, for a plugin's own options. The app ID,
  `com.anthropic.Claude[.<name>]`, also names the launcher's `.desktop`
  file, its `StartupWMClass`, the asar's `desktopName` (its windows' app
  ID) and the Permissions window's `--app-id`: the portal names the app's
  notifications by the app ID, and gnome-shell drops them unless a `.desktop`
  file of that name exists. The default launcher's is upstream's, so its
  `.desktop` file keeps upstream's name and stands in for upstream's. Each runs its
  sandbox as a unit in a slice of its own, `claude\x2ddesktop[\x2d<name>].slice`
  (escaped, as a `-` nests one slice in another): the launcher, `cmd/launcher` (`launcher start`, behind a
  generated bash wrapper that expands the sandbox's environment from the caller's), starts `launcher supervise` as
  `claude-desktop[-<name>]-app.service` there with the caller's environment, `Type=notify`, `Delegate=yes` and
  `DelegateSubgroup=supervisor`, and returns once supervise says the app is up or why it isn't (the result file),
  which it prints. The launcher's bwrap (`launcher bwrap`, mode subid, nixpak's bwrap) lays out
  the cgroups below it: nixpak's launcher and the host side in `supervisor/`,
  the sandbox in `sandbox/app/`, its cgroup namespace rooted at `sandbox/`
  (at most 64 cgroups, 4 deep, capped on the unit's cgroup, out of its reach),
  which it sees alone at `/sys/fs/cgroup`: writable when the host's cgroup2 has
  `nsdelegate`, bound read-only with a warning in the journal otherwise, which a
  cgroup2 mount of its own in nested namespaces gets around inside its subtree
  (`docs/permissions.md`, Launcher). The re-entries (`claude://`, `--shell`) join `sandbox/app/`;
  `cgrun.sh` (`cgrun` on the sandbox's PATH) runs a job in a `sandbox/cgrun-<pid>/`
  with a memory limit and a CPU weight (50 against `app/`'s 100: `sandbox/` gets the `cpu` controller where the unit
  has it, which systemd's `user@.service` delegates). Each launcher's slice has `CPUWeight=50`, between
  `app.slice`'s 100 and `background.slice`'s 30 (`default.nix`). The broker and its host command calls are units in
  the slice too. Then
  `environment.md`, which `environment-split.sh` turns into the default `environmentFile`, which
  `/etc/claude/environment.md` in the sandbox imports: all of it, or with `memo.enable` the sections without a
  `<!-- memo: FILTER -->` marker, the marked ones going into a memo store that the module adds to
  `programs.agent-memos.settings.stores` by its store path, so the host's memo config lists it too
  (`<!-- memo-doc: ... -->` lines document its values). The store also injects `environment`, the frontmatter's name
  for the environment. Then the module's scripts (`*.sh`; `store-gc.sh` and
  `scratchpad-prune.sh` go on the sandbox's PATH for the user's hooks, `cgrun.sh` for its jobs). The modules load them with `lib.nix`'s `script` helper: Nix values
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
  filtered to `go.mod`, `go.sum`, the binary's directory (its own `internal/`
  packages included) and the `internal/` packages it uses, each with its own `vendorHash` (Go vendors only what the
  binary imports). permissions-window has a module of its own, so miqt's cgo
  and Qt stay out of the others' closures.
- `cmd/launcher/`: the launcher (`launcher --help`), one binary for the user's entry and the app's unit:
  `main.go` (arguments, the config `launch.nix` writes), `enter.go` (`--permissions`, `--shell`, the re-entry into the
  running app through nsenter after joining its cgroup, the unit started and its result, Ctrl-C or a hangup while it
  starts stopping the unit, a launch while the unit runs without a sandbox (it starts, or shows an error) handing
  supervise the caller's `XDG_ACTIVATION_TOKEN` in a file and SIGUSR1 to bring the splash to the front, or saying so
  without one, as from a terminal), `supervise.go` (the unit:
  the sandbox's state and store prepared, nixpak's launcher run with its output pumped to the journal and a tail
  kept, the app's ready line ending the splash and sending READY=1, a failure shown with that tail, the splash's Abort
  stopping nixpak's launcher (SIGTERM, SIGKILL after 5 s) and the start, shown for at least a second), `store.go` (the
  closure copied into the sandbox's store through `confine.sh`, its progress from the export stream's bytes against
  the NAR sizes), `theme.go` (the portal's colour scheme as the sandbox's GTK theme, live) and `splash.go` (the
  splash's process and its JSON lines). The app prints the ready line (`lib.nix`'s `readyLine`) from a hook
  `patch-asar.sh` adds: the first time one of its windows is visible once its page loaded or when it's shown (not
  `ready-to-show`, which skips a window shown at creation, as the app's main window is, and not gated on
  `isLoading()`, which a frame still loading keeps true), through stdout's write as it was at startup. `bwrap.go`, `helper.go` and `maps.go`: `launcher bwrap`, the bwrap
  that nixpak (mode subid) and the FHS env (mode parent) run, which maps a range of ids into bwrap's user namespace:
  it starts itself as `bwrap-helper` with bwrap's info and block pipes, then execs into bwrap; the helper writes the
  maps once bwrap made the namespace (killing bwrap and its child when they fail), lays out the cgroups and on the host
  sets up the network (`--net`: netns-macvlan, the links up, udhcpc in a mount namespace of its own through
  `dhcp-root.sh`) before it passes bwrap's info on to nixpak, whose pasta slot is a no-op that only keeps the netns.
  `internal/sandbox`: finding a launcher's running
  sandbox from nixpak's instance info (`Find`, which the broker pins) and the app's main process in it (`AppPid`).
- `cmd/netns-macvlan/`: the Go helper that gives the sandbox's netns
  its macvlan (`netns-macvlan --help`).
- `cmd/subid-broker/`: the Go helper that writes uid and gid maps for
  user namespaces inside the sandbox, and its `newuidmap`/`newgidmap` shims
  (`subid-broker --help`). The launcher's bwrap, which nixpak and the FHS env run, maps the user's subuid
  range in and starts it.
- `cmd/dbus-proxy/`: the Go D-Bus proxy that replaces xdg-dbus-proxy
  (`docs/permissions.md`, D-Bus), taking nixpak's argv and its rules from a
  JSON config, the module's `dbus` option, which the module passes as
  `--config` through nixpak's `dbus.args` (`dbus-proxy --help`). The module hands it to nixpak as
  `pkgs.xdg-dbus-proxy` (the package links `bin/xdg-dbus-proxy` to it), so
  nixpak's launcher starts it as the session-bus proxy. Its packages in
  `cmd/dbus-proxy/internal/`, each auditable on its own: `wire` (reading
  messages and their file descriptors, bounded, parsing the header, decoding a
  body where needed, encoding, each side's write queue, and the budget of bytes
  and file descriptors the clients share), `sasl` (SASL toward both sides),
  `rules` (the config, decoded strictly, xdg-dbus-proxy's matching, the
  lookup of a name in the rules) and `judge` (one connection's state and its
  verdict on each message each way, without I/O: forward, drop or replace,
  and the proxy's own calls to the bus, the hold after Hello; one mutex over
  the unique names and the pending replies). Package main: `main.go`
  (arguments, `--fd`), `proxy.go` (listening, the accept loop, the peer's
  uid), `client.go` (a connection's goroutines, doing what the judge says)
  and `address.go` (bus addresses). Two packages for the tests only:
  `spec` (a model of the D-Bus specification written from it alone: names,
  signatures, a message's header and body, the SASL server, and the proxy's
  documented rules, config and verdicts on top) and `gen` (rapid generators from the
  specification's grammar and of configs, valid and near misses, and byte-level mutations).
- `cmd/permissions-broker/`: the Go daemon that grants the sandbox
  outside access while it runs, per `docs/permissions.md`, and the sandbox's
  `permissions` MCP server (`permissions-broker --help`). A launcher runs it
  with `permissions.enable`, off by default: the launcher's supervise starts it as a
  user unit, nixpak binds its grant directory read-only at `/run/permissions`,
  and the launcher's bwrap (mode parent) asks it to share that mount before the FHS env's bwrap.
  Its own packages are in `cmd/permissions-broker/internal/`, each auditable on
  its own: `schema` (the JSON Schema subset
  arguments are checked against), `duration` (the ISO 8601 durations of leases
  and validities), `wire` (the protocol on request.sock and control.sock, and
  `Call`, its client side), `notify` (asking with a notification), `mcpserver`
  (the MCP server inside the sandbox, a client of request.sock, with a tool per
  host command), `hostcmd` (a host command's declaration: its checks, its free
  arguments, the consent's lines (a phrase each, shared by the commands that have
  it) and scope, what it reads on stdin), `hostsock` (what a
  host socket may not be, reaching one without links, the addresses in the grant
  directory), `mountinfo` (mountinfo files) and
  `mounts` (attach grants in the sandbox's mount namespace: the folders ceiling
  by path and identity, the helpers run through `nsenter` that clone a host path
  and join the sandbox's mount namespace only after their exec on the host's
  mounts, to share the grant directory and mount and unmount grants there, the
  grant's mount and the holders' scan; it takes the sandbox as an interface).
  Package main is the core, one concern per file: `main.go` (the arguments),
  `config.go` (the config, the capabilities loaded from it; its `agent` names who asks in the notifications and the
  window, "The agent" without it, the module's "Claude"), `run.go` (serving
  until the sandbox ends), `sockets.go` (listening, peer checks, the request and
  control handlers), `consent.go` (and the log of decisions), `leases.go` (and
  logind), `standing.go` (the standing grants from the config), `views.go` (and
  opening the window), `overview.go` (the config's overview, with what the sandbox's mount table lacks), `types.go`, `clock.go` (the time and timers of leases and
  answers, which tests fake), `capability.go` (a capability, its parameters and
  summary), `kind.go` (what a capability's type adds, which the core calls into:
  its checks, a grant made live and ended, the consent's summary and scope, the
  list), `instances.go` (instances, the instance check and exclusive locks),
  `commands.go` (host command capabilities: bounding arguments, instance globs),
  `call.go` (a call: covered or asked, run as a transient unit, its output),
  `hostsockets.go` (listening at the host sockets' addresses), `splice.go`
  (connections to them, spliced under a grant), `refusal.go` (the categories a
  refused request or call names in its answer's `refused`), `sandbox.go` (finding and pinning the sandbox), `members.go` (its processes by
  user namespace), `folders.go` (the folders capability), `attach.go` (mounting,
  unmounting, cleanup) and `holders.go` (what still held ended grants). Each
  type's kind is in its type's file. Each `*_test.go` follows its file; tests
  that go through a grant stay with the core. The rapid state machines
  (`machine*_test.go`, and `live*_test.go`, which the VM test runs from this
  package's test binary) drive the core's internals, hence package main;
  `main_test.go` has `TestMain`, which runs the test binary as the helpers
  through `main()`, and the shared fakes.
- `nix/packages/permissions-window/`: the Permissions window (Go with miqt's
  Qt 6 bindings, and QML), a client of the broker's `control.sock`. miqt has
  no moc, so the QML talks to Go through a `QQmlPropertyMap`: state as JSON
  in, actions as JSON out (`window.go` holds the logic, `main.go` the Qt
  glue). `Permissions.qml` is the content, a tab each for the requests, the grants,
  the activity (calls and decisions) and the configuration, with its parts in files of their
  own: `TabPage.qml` (a tab's scrolling page), `Section.qml` (a heading and its part), `Card.qml` (a request's or a
  grant's box), `RequestRow.qml`, `GrantRow.qml`, `FieldRow.qml` (a name and its value in a box of its own, or a field
  to edit), `Quote.qml` (Claude's words beside a bar), `CallList.qml` (host command calls),
  `Badges.qml` and `Badge.qml`, `ReadOnlyText.qml` (selectable text), `CommandScope.qml` (what a host
  command grant covers: a line per consent phrase, Details collapsed beneath). `Preview.qml`, `preview.sh` and
  `preview-state.json` are the package's `preview` (`nix run .#permissions-window.preview -- --help`): the window
  against a mock broker with a sample state, live or as a screenshot, from a checkout's QML with `--qml`. The launcher opens it with
  `--permissions` and the `.desktop` file's "Permissions" action; the broker
  opens it on a notification's Options. Its wrapper sets Qt's plugin and QML
  paths to its own Qt's, Plasma's style and platform theme included: the
  host's may be another Qt. Where the compositor leaves decorations to the window (GNOME), they're Adwaita's
  (`qadwaitadecorations-qt6`, `QT_WAYLAND_DECORATION=adwaita` on the Permissions window), with a shadow. The package also builds `sandbox-splash` (`splash/`, `sandbox-splash --help`), the
  launcher's splash: the main logo (the `splash.logo` and `splash.logoDark` options, by default the Orbit logo copied into
  `nix/home/claude-desktop/assets/`, whose README says from where, and that the MIT licence doesn't cover it) under an "Agent
  Sandbox" title (in Lexend SemiBold, the brand's title font, from nixpkgs' `lexend`, which the wrapper passes as
  `--title-font`), the step and its progress with the agent's logo small at the right above the bar
  (`splash.agentLogo`, the app's icon), light or dark as the
  desktop is (the controls' palette too), and when the start fails why and the app's last output until the user
  closes it; JSON lines on stdin (`state.go`) drive it, `activate` with an xdg-activation token bringing the window to
  the front (Qt's `requestActivate` takes it from the environment). Its one button offers Abort after 10 seconds, which says
  "Aborting startup" at once and prints `abort` on its stdout for the launcher, and turns to Close once the start
  failed. SVG logos load through qtsvg; around them the clear space
  brand logos ask for, half the symbol's height.
- `nix/patches/`: patches to what the module builds from its inputs, each
  with a header saying why. `nixpak-launcher-reaper.patch` (meant for
  upstream, in `git format-patch` form below the header) keeps nixpak's
  launcher's child reaper off the children the launcher waits for itself,
  which it could reap first, so the launcher panicked with `waitid: no child
  processes`. The module applies it through `nixpakPkgs`, whose `callPackage`
  patches the package nixpak builds from its `launcher/`.
- `nix/home/claude-desktop/request-send.nix` and `cmd/request-send/`: the host commands `request-send` and
  `request-send-write` (README, request-send), `permissions.request-send` on each launcher, a launcher
  module. `consent.title` and each command's `consent` are the user's words in the notification and the
  window: plain, for someone who isn't technical, without ranges (the window's Details show those from the schemas).
  The binary (`request-send --help`) sends one HTTP request per call: it reads the call, checks every argument again
  (the origin against the `--origin`s the module passes, each with its `--env` and `--ca`, the method against the
  scope's, the path, that origin and path make a URL on that origin, and the body), reads the origin's certificate at
  each call and checks it's the TPM key's and valid now, and sends over TLS 1.3 trusting only the origin's `--ca`, the
  TPM key as a `crypto.Signer` that has `step kms sign` sign the handshake's digest (retrying the TPM's intermittent
  "structure is the wrong size", checking the signature). No redirects followed, no proxy; the answer is refused over
  8 MiB or when it isn't UTF-8. Exits 2 on what it refuses, 1 when sending fails.
- `nix/checks/`: the flake checks, see Testing.
- `docs/permissions.md`: design of the permissions broker, rewritten for
  the broker as gateway (declared host tools, host sockets at stable
  addresses, the Go D-Bus proxy). Its Status says which Steps have landed.
- `scripts/nettest.sh`: reachability check, run inside the sandbox.
- `scripts/ns-inject-spike.py`: spike for binding host folders and device
  nodes into a running sandbox and detaching them, against two nested bwraps
  shaped like the sandbox's. Run inside the sandbox with a bwrap path; not
  part of the checks.

Flake outputs: `homeModules.claude-desktop`, `nixosModules.claude-desktop`,
`packages.<system>.netns-macvlan`, `packages.<system>.subid-broker`,
`packages.<system>.dbus-proxy`, `packages.<system>.permissions-broker`, `packages.<system>.permissions-window`,
`packages.<system>.request-send`, `packages.<system>.launcher`, and for CI
`legacyPackages.<system>.vm-loop-full` (see Testing).
Consumers import both modules and enable
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

`nix flake check` runs everything below; run it before every commit. While
iterating, build only the checks a change reaches (`nix build .#launcher
.#permissions-window`, whose builds run their tests, for the launcher and the
splash): a change to anything in the sandbox's closure rebuilds
the VM images and runs every VM part. Inside
the Claude Desktop sandbox, run heavy jobs under `cgrun`, so going past the
limit kills the job, not the app or the desktop: `cgrun --memory=24G -- nix
flake check -L --max-jobs 4 --cores 4` (at Nix's defaults, 32 jobs with every
core each, it can take the whole machine beside other test workers; at 4 and 4
it peaks at about 21 GiB), extended property runs under `cgrun --memory=4G` (the
broker's at `RAPID_CHECKS=1000 RAPID_STEPS=100` peaks at about 1 GiB in one
process); `models/check` puts itself under `cgrun --memory=8G` when `cgrun` is on
PATH (it peaks at about 1.1 GiB). The
checks are in `nix/checks/default.nix` and use a test NixOS system with both
modules and a user alice (the `home-manager` input exists only for it).

- `claude-desktop-eval`: nix-unit runs the flake's `tests` output, with every
  input passed in from the store. Run them directly with `ulimit -s 61440; nix run
  --inputs-from . nixpkgs#nix-unit -- --flake .#tests.x86_64-linux` (nix-unit keeps the shell's stack, and 8 MiB
  overflows). They
  check that the assertions hold (with memo too), the memo assertion, the
  sandbox's store in memo's config on the host, the
  files, package and `environmentFile` a launcher with `memo.enable` gets
  (and the default launcher doesn't), the NixOS wrapper appears only when a user
  enables the module, for group users, the users-group, subid and
  graphics assertions fire, the netns assertion fires when `sandbox`
  overrides `bubblewrap.network` or `pasta`, the filesystem MCP roots,
  `extraPath` at the front of PATH, the launchers' packages, the launcher
  name assertions (its characters, and its length at and past the cap, the
  `launcherNameMax` at which `cmd/permissions-broker/socketpath_test.go` binds
  the broker's sockets), the per-launcher netns assertion, a tray on two launchers at once,
  a launcher's MCP roots without `~/.claude`, and `programs.mcp.servers` in
  every launcher's MCP servers (disabled ones out, env files wrapped, none
  without `programs.mcp.enable`, the assertion on remote servers and the
  sandbox's names), the `permissions` MCP server only with
  `permissions.enable`, the assertions on standing grants (only with the
  broker, of a host command or host socket it has, none of folders), the assertions on host commands (names, described
  arguments, results, and the consent's title and each command's phrase: present, one line, at most 80 characters,
  counted in UTF-8 characters: Danish of 46 and 80, CJK of 80 taken, of 81 refused),
  the assertions on host sockets (a
  name of their own of 80 characters at most, a path or one instances glob, a clean path, no D-Bus bus, systemd
  user manager, accessibility bus, `/proc` or `/var/run` path, `$XDG_RUNTIME_DIR` as a whole or launcher socket, nor a
  glob that could match one), the `dbus` defaults (the portal's, with `tray` the tray item's name at the
  launcher's pid and the watcher's, the user's rules merged in), the assertions on D-Bus rules (`sandbox`
  setting nixpak's `dbus.policies` or `dbus.rules`, a name the proxy refuses or one giving nothing, a rule it refuses
  and its caps: 64 names, 64 rules a list, 64 KiB of config, each at and past the cap),
  and the assertion on binds that reach a launcher's
  state dir or `$XDG_RUNTIME_DIR`. The test system imports both modules twice and has a launcher
  `work`.
- `claude-desktop`: builds alice's sandboxed app (the patched asar and the
  `writeShellApplication` scripts check themselves while building) and checks
  its closure: the import of `environment.md` (in the closure, all
  sections, no markers) and of another `environmentFile`, the binds (with their `src`), the scratchpad,
  the devices (`/dev/kvm` once, from `kvm` and `devices`) and PATH in `claude-environment.md`, the patched asar's tray
  icon (by the colour scheme, also on GNOME), the notification patch (on a
  4.x-shaped asar: the native backend never picked, an app with two such places
  refused), the channel hook (on a 4.23118-shaped asar: `channels.js` only with `mcpChannels`, hooked into the
  sessions' MCP client with the session manager's chunk, an app with two such clients refused), nixpak's launcher the patched one (its reaper's `Start` in the binary, one launcher in each
  launcher's closure), nixpak's D-Bus proxy wrapper running our `dbus-proxy` (no
  xdg-dbus-proxy in the closure) with the bus address, the socket, `--config` and `--filter` as its argv for
  both launchers, work's config the portal's rules alone and its overview the same, and nixpak's
  `bwrap-args.json` (own netns, no `--share-net`, the binds, a module
  default overridden by its sandbox path, the devices' dev binds, the scratchpad's dev bind after
  the `/tmp` tmpfs, `/nix/store` bound after `/nix`), the launcher's
  `homeDirs` in its launcher config and its state script's paths, `app-pid.sh` dropping ambient capabilities when it can't
  set the pid, and the `files` in the FHS env's bwrap (a directory's
  bind before a file's in it, a disabled one left out, what a file
  references in the closure), `cgrun` on the sandbox's PATH. The launchers' configs, which their wrappers run the Go launcher
  with: their slices, work's app unit and nixpak's launcher, the ready line, the splash with its title and the
  agent's logo from the unwrapped app, the asar's ready hook, its broker's
  slice. For `work`: its wrapper alone in `bin`, its app ID,
  `~/.claude` and the app's config in its home, its GC root link, the name
  netns-macvlan gets, its `claude-environment.md` (with memo: the core
  import, its pointer to memo, memo's config in the FHS env with the store
  right after the embedded ones, the store in the closure), its permissions broker (the
  read-only `/run/permissions` bind, the config with its folders, host sockets, standing grants and the window's overview (binds, devices, D-Bus rules, the network, the implicit lines), the launcher config's; no
  `/run/dbus` or D-Bus capabilities for either launcher), and its `.desktop` file (name, Exec, the
  Permissions action, no `claude://` handler; both launchers' actions running the launcher by name, no store path). For both launchers, their app
  ID in the launcher config and `/.flatpak-info`, which names their only `.desktop`
  file, its `StartupWMClass` and the `desktopName` their asar gets; the
  default launcher's `.desktop` file keeps the `claude://` handler and
  upstream's actions, and lacks the Permissions action. For `work`, the
  Permissions window's `--app-id` in its broker's config.
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
- `dbus-proxy`: the package build runs the Go tests of it and its
  `internal/` packages with `-race`. Package main's go end to end, against a `dbus-daemon` of the test's that allows unrequested
  replies and eavesdropping (each test's control shows the proxy refusing
  what the bus would pass): a hidden name (not listed, no owner, a call unknown),
  `see` (visible, a call denied), `talk` (any call and its reply, by the
  owner's unique name too), `own`, call rules (method and path, an interface on a `/*`
  subtree, `@/*`, `*`), broadcast rules (none without a rule or with `see`,
  and xdg-dbus-proxy's quirk of passing all of a ruled name's broadcasts),
  replies (let through to calls let through, refused unasked both ways, a call
  carrying a pending reply serial refused), NameOwnerChanged by policy,
  `BecomeMonitor` and eavesdropping match rules refused, file descriptors
  both ways, `--fd` (the byte, exit and the socket removed when it closes, as
  nixpak starts it, with a config file), bad arguments refused (xdg-dbus-proxy's rule flags, `--config`
  missing, unreadable or invalid, `--filter` missing), libdbus's `dbus-send` as a
  client, sd-bus's pipelined SASL, an oversized message; through a client
  speaking the wire itself (`raw_test.go`, `guards_test.go`): a serial reused while pending and
  a second Hello, serials 0 and past the client's range, file descriptors
  either way for a client that cancelled their negotiation, bus calls without
  an interface, with a non-string match rule or on another interface, a call
  without a destination, a caller made visible, another uid, file descriptors
  during SASL, the hold after Hello until the rules' names' owners are known,
  both pending-reply caps; the limits
  (`limits_test.go`): `maxClients` connections and no more, a client over the memory budget disconnected while another goes
  on, queued file descriptors past a client's share, and accepting again after
  running out of file descriptors (the test binary as the proxy, with a low
  `RLIMIT_NOFILE`); and bus addresses. A stateful
  property test (`machine*_test.go`, `pgregory.net/rapid`) runs random sequences of `models/proxy.als`'s actions
  against the proxy with a config generated for each sequence from the world's names, paths, interfaces and members
  (`internal/gen`, valid by `spec.ParseConfig`, loaded from a file as `main` loads it), between a `dbus-daemon` of its own (with an activatable
  name whose start stays pending until someone takes the name: the test binary as `DBUS_PROXY_LAZY`), two services
  straight on the bus and up to three clients speaking the wire: clients connecting, saying Hello (twice) and hanging
  up, calls to names allowed and hidden and to unique names with fresh, reused and forged serials (and a call
  carrying a reply serial), calls to the bus (owners, names listed, owned, released and started, match rules with and
  without eavesdropping, `BecomeMonitor`), replies to calls asked and not; services taking and releasing names,
  calling clients, replying, forging replies to clients' pending calls (a pending start included) and broadcasting.
  Each step runs to quiescence (barriers through each connection, the bus dropping a connection that closed), then
  what arrived at each end, the connections closed and every name's owner match a reference model
  (`machine_model_test.go`, `machine_bus_test.go`: each client's name table, pending calls both ways, the bus's
  owners, match rules and pending calls; D1, D2 and D4). Its `Generated` action (`machine_gen_test.go`) sends
  messages from `internal/gen`, to the world's names and the grammar's and to the bus driver with any method, broken
  at the header or the bytes; `spec.ProxyReads` and `spec.ProxyVerdict` predict whether the proxy reads it and
  passes, refuses (which error), drops it or ends the connection, never consulting the proxy's parsers (one the proxy
  would pass with a body that contradicts its signature isn't sent: the bus's reaction is the bus's). `go test` runs 50 sequences of about 30 steps (a few seconds); more with `-rapid.checks=1000
  -rapid.steps=100` (or `RAPID_CHECKS`, `RAPID_STEPS`), a failure again with the `-rapid.seed` it prints.
  The `internal/` packages' tests, each alone: `wire` (a fuzz test of the header parser against godbus's decoder,
  run longer with `go test -run '^$' -fuzz FuzzParseHeader -fuzztime 30s`; a property test of the reader against
  `spec` on generated and mutated messages, `TestParseAgainstSpec`; the header's duplicate, wrong-type, unknown-field,
  IsValid and padding checks, the encode and decode caps; serial 0, file descriptors per message,
  pending and claimed, bodies left undecoded, the budget, and what readers and senders hold of it), `sasl` (`Serve`
  on a socket pair: EXTERNAL accepted with and without an initial response, file descriptors as negotiated,
  refusals, the command and line caps; `TestSASLAgainstSpec`, generated input against `spec.SASLServer`), `rules` (rules parsed as xdg-dbus-proxy's, the lookup, configs refused by
  example, and `TestConfigAgainstSpec`: 3000 generated configs, valid and near misses, taken exactly when
  `spec.ParseConfig` takes them, a field null beside one that gives the entry something among the misses, then each name's policy, calls and broadcasts the model's), `judge` (state alone: a peer's reply to a call to the bus dropped, a unique name that left
  forgotten, a reply only to its caller; the eavesdrop match, the bounded name and owned-name tables; the bus
  driver's default refusal, the monitoring guard on its own, Introspectable passing, the 4 KiB inspection cap; and a
  stateful property test, `machine_test.go`, that drives one connection's judge with the bus as a queue answered in
  order, with a config generated for each sequence, checking D1 and D2 after every step by `spec`'s model of it, with generated messages (`machine_gen_test.go`: grammar names and
  bodies, any bus driver method, mutations) judged against `spec.ProxyVerdict` down to the refusal's error name, 1000
  sequences in about a second; more with `-rapid.checks=20000 -rapid.steps=100`), `spec` (the specification's own
  examples) and `gen` (what it means valid is, by `spec`, configs too).
- `permissions-broker`: the package build runs its Go tests (`*_test.go`):
  durations (one past what a duration holds refused), parameter validation, consent (denied, allowed, a live grant
  covering the same request only, by value: keys in any order, -0 for 0), the requests the state machines once
  sampled as examples, each refused with its category or served (`refusal_test.go`), host commands (the schema subset's
  keywords, numbers against bounds and enums exactly, numbers past what a float64 holds (rounding to 0 too) or written
  in more than 800 digits or an exponent past ±400 refused, numbers written one way in parameters, a long enum said as a count, declarations refused for an undescribed or reserved argument, a
  bad name, result, timeout or glob, no consent title or a command without its phrase, or one blank, past 80
  characters or with a control character; the config's `consent` loaded; instances from a glob; the scope's parts
  in `state`, unrestricted first; the consent's lines in `state`, a phrase each with the commands sharing it, unrestricted
  first, marked by the schemas whatever the phrase says, and the summary's bounding values (alone, by name when
  several, opaque by digest); a call checked
  before the user is asked and told the scope, the window getting the call asking with its arguments whole
  (opaque ones by digest); the notification's summary ("Claude wants to" the title and the lease, the values left to the body) and its
  body's first line (the bounding values and the lease again, then the phrases), markup escaped, leases in hours and
  minutes, word for word for a declaration shaped like nixos-windows-vm's windows-vm, a bounding value as long
  as a parameter may be whole in the body with the lease, and one with U+2028, U+202E and U+200B escaped in the
  summary, the body and the pending request's `bounds` (`consent_text_test.go`); phrases counted in characters (Danish
  and CJK at the cap); a granted request's reason on the grant; a once grant covering only
  its call and refused to a request; a failing call's exit and stderr,
  recorded with opaque arguments by digest and its capability; image and text results, too much
  output stopping the unit; the unit's properties (the launcher's slice too) and a revoke stopping it;
  the validity; a grant ending with its instance; the MCP tools listed from
  the declarations and a call through them, also before the daemon
  listens), a request or window answer naming no instance
  refused without asking (and with a failing glob; not for folders), and an Allow refused when the instance went away
  while the user was asked, the refusal limit, a window answer with its
  narrowed parameters, standing grants (a config error refused: no such
  capability, folders, parameters it doesn't take, one twice; granted at start
  when their instance is there, once however many ask at once; a host command's
  calls without asking, told `maxValidity`; revoked or released, asked for until the
  daemon starts again), duration, lock (granted right after the watch is set up, which
  happens before the daemon serves; none granted when the lock stops being
  watched while the user is asked) leases, call units in systemd (faked), exclusive instances across
  launchers (locked by the instance, whatever other parameters
  a request carries; the default launcher's cleanup leaving a lock without content alone), `share` through nsenter into a child's user and mount namespace
  (refused from another mount namespace, a second time, and once a process of
  the sandbox is in a copy of its mount namespace), `control.sock` refusing a peer in
  another user namespace, a peer gone after its `/proc` entries were read
  refused by `control.sock`, `share` and `request` (S13), the sandbox's
  namespaces pinned (helpers refused once its pid moves to namespaces of its
  own) and not found from a stale instance directory or in a user namespace
  that isn't a child of ours, the sockets end to end with `watch` events, the config's overview passed on in `state` (with the optional binds and devices a stand-in sandbox's mount
  table lacks as `absent`, binds that aren't optional never), and what
  the sandbox can't do to it: hold every connection (control.sock still
  answers, idle clients time out), send an oversized request, dress up a
  parameter or reason in the notification, make a click on its replacement of
  the broker's notification or an `ActionInvoked` of its own allow or
  `default` (a fake notification server on a `dbus-daemon` of the test's),
  or get a body click answered within a second, get `share` served twice, get a call's output after
  its lease ran out or for a grant revoked while it waited for a
  call slot; plus a window answer while the notification is up, pending requests
  in arrival order, a click on the notification's body (the `default`
  action, first: a deny, on cosmic-notifications the window's options and a
  deny without a window), and unit
  names per launcher. Attach grants against a stand-in
  sandbox (a child in a user and mount namespace of its own with the grant
  directory bound in and shared): the source ceiling, the cloned tree
  received close-on-exec, a folder mounted read-only where the app sees it and
  not on the host, its holders listed and
  ended (one ignoring SIGTERM too; one holding it on a thread alone, by that thread's cwd, fd, root,
  mount namespace or an `open_tree` clone in no mount table; a clone of a file of it as a possible
  holder; a shared mapping with its fd closed, a possible holder once the file is deleted; not a process
  outside the sandbox; a re-entry's too, found by user
  namespace; on a release from inside too, and not a process by a stale
  record), detached before the holders' scan starts, with its mountpoint
  gone on revoke, a daemon started again
  taking over the shared grant directory and mounting a folder there, and
  the sandbox's attacks: a link out of the ceiling, a ceiling root swapped for
  a link, a link to a denied directory, a denied directory under another name
  (found by identity, as the source or beneath it), and a re-bind in a nested
  mount namespace (reported as a holder), a rename of the grant directory in M1
  hiding no holder, and the swap of a directory that is a
  mountpoint in the stand-in's mount namespace from a nested one (pivot_root,
  the old root detached, then a rename): the store directory holding the
  helpers' binary (they still run the daemon's) and the grant directory for a
  link to another mount (not unmounted by a revoke). Host sockets: declarations refused (a D-Bus bus, by
  path or by the bus address variables, `$XDG_RUNTIME_DIR`, a path holding it or a glob over it, the launchers'
  control sockets, nixpak's proxies, `.flatpak` and the lock directory, a relative path or an unset variable,
  neither or both of a path and an instances glob, another bounding argument, a bad name, no description, a
  name twice) and a glob match among the refused no instance; the address there before any grant, a connection
  without a grant closed at once, one under a grant spliced to the host (the grant at
  `/run/permissions/sockets/<capability>/<instance>` with the default `PT1H` lease), a revoke closing every
  connection; an instance's address appearing and going with it on the timer, its grant ending with it; 64
  connections per address and the next closed at once until one ends; an address and a host socket past 108
  bytes; what's refused beyond (the systemd user manager, the accessibility bus, `.dbus-proxy`, `dbus-*`, `/proc`
  aliases, `/var/run`, `/run/dbus`, paths that aren't clean, globs whose `*` could fall within those, anything
  without `$XDG_RUNTIME_DIR`); a glob match that is a link, lies through a linked directory or isn't a socket no
  instance; a declared socket swapped for a link after the grant, also between the check and the connect, a
  `/proc/self/root` alias and a file not connected to; an instance name past 80 characters no instance and refused
  for its length, one of 80 reachable through a long grant directory, one of 60 é (120 bytes) no instance; a sync that looked before a grant's not
  closing its listener; a revoke during the connect closing the host's end whole; a grant without an address
  refused; no address made through a link; a stale address taken over; the addresses closed when the daemon
  ends. The MCP server: the nudge after 15
  minutes, not again right after, and in tool results; and the cleanup a stopped daemon's `ExecStopPost`
  runs (call units stopped, locks removed, folder grants detached, mountpoints and host socket addresses
  removed, also without the sandbox). Stateful property tests
  (`machine*_test.go`, `pgregory.net/rapid`) run random sequences of the
  protocol model's actions against the broker on the stand-in sandbox, with
  a fake clock, with standing grants of a host socket by instance, the exclusive host commands and another host
  command in its config: requests of each type and host command calls
  from an anonymous caller, and floods of them, with their inputs generated from the declarations' grammar
  (`machine_gen*_test.go`, `machine_decls_test.go`: capability and command names and near-misses of them,
  parameters and a command's arguments using every keyword of the schema subset, with values at and past each
  limit, of other types, keys missing or extra, unicode (line and paragraph separators, bidi and other format
  characters too, which the question asked must show escaped), control characters, odd number and string encodings (numbers
  at and past the edges of a float64 and of their digits and exponent) and
  objects that aren't, leases, reasons, instance names and folder paths; `TestGeneratorShares` keeps each kind's
  valid share between a fifth and nine tenths), each judged by an oracle written from `docs/permissions.md`
  (`machine_oracle_test.go`, `machine_judge_test.go`) without the broker's own checks: refused with a category
  (`refused` in the answer, `refusal.go`) of a rule it breaks and nothing else changed, or served by a live grant,
  granted as a standing grant or asked; answers on the
  notification and in the window (leases and narrowed parameters generated too), releases of live, ended and made-up grant ids, lock events,
  time passing, revoke, a restart (granting the standing grants whose instance is there and the locks, ended ones
  too), `share`, the instances changing (an instance gone closing its console's connections), connections to the
  instances' consoles (echoed from the host under a live grant, closed at once otherwise, kept open and closed
  when their grant ends), another launcher's exclusive locks and control.sock from inside.
  After every step the broker's grants and gates, its
  mounts, locks, host socket addresses and open connections and the window's view (the standing grants, ended
  and live, included) match a reference model
  (P1-P4, P6, P7, P9-P14, P16, P17; `models/README.md` lists the model's actions they leave to other tests). `go test` runs 150
  sequences of about 30 steps (about 25 seconds); more with
  `-rapid.checks=1000 -rapid.steps=100` (or `RAPID_CHECKS`, `RAPID_STEPS`, about three minutes),
  a failure again with the `-rapid.seed` it prints. Each of these broken on its own fails the extended run, and
  mostly the default one: a length limit off by one, the control-character check, a type check, the multiline rule,
  the integer check, the lease parser taking zero, an enum check.
- `permissions-window`: the package build runs, offscreen in Plasma's
  style, its Go tests (`window_test.go`: the operations against a fake
  `control.sock`, and the Qt glue, checked in `TestMain` since Qt wants the
  main thread: loading without QML warnings, the state arriving, a click
  reaching the broker through the property map) and `tst_permissions.qml`
  through `qmltestrunner` against a mock broker: an answer narrowed in its
  fields (kept through a refresh that rebuilds the list), deny, revoke then end (the holders of ended grants from the state, a possible one marked),
  a standing grant shown as from the config, the tabs (the requests in front while there are some and when one
  arrives, the user's pick otherwise), a folder request's resolved folder from the summary, the overview of the configuration (binds, devices, D-Bus, the
  network, the standing grants live and ended, the implicit lines; an item a row each, its value selectable; an optional bind or a device present or missing by
  the broker's `absent`), a repeated action still a change, Allow and Deny off for a second after a pending row moved up or was
  replaced in place, a grant expanded and collapsed (kept through a refresh), the
  badges (lease, from config, free arguments with a warning for an unrestricted one), a host command
  grant's summary as a sentence, parameters, holders, reason, consent lines (the phrase, an unrestricted badge, the
  commands sharing it), Details collapsed until opened (a long enum listed) and calls, the calls of ended grants, a host
  command request headed "Claude wants to" and the consent's title, its bounding values a row each and never
  editable (escaped runes escaped, in Claude's reason too), its heading on the lease picked, its consent lines,
  Details (the scope) and the call asking, its arguments a row each, its lease still editable (once
  and Claude's proposal offered, no session lease) and Allow sending no parameters, and the text read-only and selectable.
  Repeater delegates aren't QObject children, so the Go side can't find
  them; Qt Quick Test can. `splash/splash_test.go`: the splash loads without QML warnings through a start and a
  failure without logos, the button's Abort once it shows writing the command and turning to aborting, then Close after a failure closing the window, an `activate` line putting its token in the
  environment and telling the window, and a line sets what it names (a new step's progress unknown until it says).
- `launcher`: the package build runs the Go tests of `cmd/launcher` and `internal/` with fake tools (the state
  script, nix-store, nixpak's launcher and the splash as scripts) and a notify socket of the test's: supervise
  sending READY=1 on the app's ready line and passing its arguments and output on, a refusal (a missing bind source)
  left in the result file before READY=1 with nixpak's launcher never run, an app failing before it's up shown in the
  splash with its status and last output, no splash being no obstacle, the tail's size, an abort from the splash while
  the app starts (nixpak's launcher stopped with SIGTERM, the result, READY=1, at least a second shown), Ctrl-C while
  the unit starts stopping it (`abort_test.go`); a launch while the unit runs leaving its token and signalling
  supervise, or failing without a token, and an inactive unit started; SIGUSR1 handing the token to the splash of a
  failed start and of the app ended (`activate_test.go`); the store sync deleting nix/
  without a record, copying only what the store lacks with its progress short of 1, leaving a recorded store alone,
  refusing a store dir that is a link and deleting nix/ for a swapped one; the id maps (`maps_test.go`: the subuid
  range around the user's own id, an identity map and its subuid lines with the own id at either end, inside and
  outside a range); `launcher bwrap` in mode parent against a fake bwrap (`bwrap_test.go`: the maps written once it
  reported its child, then unblocked, the subuid and subgid lines on fds 22 and 23, its arguments after the
  launcher's; a failing newuidmap killing bwrap before it's unblocked); `internal/sandbox`'s `AppPid` on a real pid
  namespace tree (the app one level below the init, not one further down, two at its level ambiguous).
- `request-send`: the build runs the Go tests (`cmd/request-send/main_test.go`), each call run through `run` as the
  broker runs the binary, with the test binary as a fake `step` (its key standing in for the TPM's, every run
  recorded) against an httptest TLS server that requires a client certificate from the test users CA: a read and
  writes arriving as sent, the client certificate seen by the server, the TPM signing the handshake, the staging key
  and certificate, the answer as it came (an error status, a redirect not followed), the TPM's intermittent error
  retried and given up on, and exit 1 for an answer over 8 MiB or not UTF-8, a server from another CA, a certificate
  of another key, an expired or missing one and step failing. Refusals with exit 2 before step runs: methods outside
  the scope's, a GET with a body, paths that aren't from / or printable ASCII, too long, with a fragment or leaving
  the origin, bodies too long or with control characters, missing, extra or mistyped arguments, origins not in the
  list, bad flags.
- `request-send-module` (`nix/checks/request-send.nix`, its eval tests in `claude-desktop-eval` as
  `testRequestSend*`): both capabilities on the launchers that enable them with their own origins, CA, env and step,
  the origin as the bounding enum and in `run`, their consent title and phrases, the read command's GET only and the
  write one's GET and POST with a multiline body, the default step finding step-kms-plugin, origins that aren't https
  origins or none failing to evaluate, the assertion without `permissions.enable`, and `permissions-broker serve`
  loading the declaration while refusing a broken one. Not covered: the real osTicket API.
- `scripts`: shellcheck on `scripts/` and the module's scripts.
- `vm-launch`, `vm-store`, `vm-work`, `vm-live`, `vm-loop`: the NixOS VM test
  (`nix/checks/vm/`, needs KVM), in five parts that Nix runs in parallel;
  `vm` builds them all. Each boots the same two machines (built once) and
  runs the shared prelude in `vm/default.nix` (helpers, the boot), then its
  part's script, `vm/<part>.nix`: `launch` the default launcher and the
  network, `store` its store dir swapped or without a record, `--shell`
  starting the app, and a launch without `nsdelegate` (cleared by a second cgroup2 mount, as Cilium's does: the
  journal's warning, the cgroup read-only, a cgroup2 mount of its own still writing its subtree and nothing above it, `cgrun` refusing, the warning's remount restoring the options), `work` the launcher `work` next to the default one with
  its permissions broker, `live` the broker's state machine tests, `loop` the
  default launcher launched and stopped 20 times, none failing (100 in `legacyPackages.<system>.vm-loop-full`, which
  CI's `test-vm` builds and `nix flake check` only evaluates: about 4 minutes; it prints the count; nixpak's launcher without `nixpak-launcher-reaper.patch` fails
  some, see `nix/patches/`). A router VM runs
  dnsmasq for DHCP and DNS and stands in for the internet: its DNS points
  api.anthropic.com and github.com at itself, which listens on 443. On the
  workstation VM, alice launches the sandbox with a stub app
  (`nix/checks/stub-app.nix`, shaped like the real package so the asar patch
  and FHS overrides apply), and a fake portal (`nix/checks/fake-portal.py`)
  serves the color scheme on her session bus. The test covers the setcap
  wrapper, links the sandbox planted in its state (a store dir that's a link
  refused, links in its home replaced, alice's files neither read nor written,
  the keyfile swapped for a link while it runs, the store dir swapped for a
  directory of its own between launches refused, and with no record of the
  store dir, `nix/` deleted, a subuid's files included, and the closure synced into a fresh one, recorded), `/nix/store` not renameable
  inside directly, the launcher refusing a missing bind source that isn't optional,
  the store sync, the app's tray item (it owns
  `StatusNotifierItem-<pid>-1` through the proxy at the pid `app-pid.sh`
  set, with no capabilities left), D-Bus through the proxy (`notify-send` reaching the fake portal's
  notifications; `xdg-open` reaching its OpenURI from a caller whose `/.flatpak-info` names the app, also by bare name
  without PATH, as Electron runs it (`/usr/bin/xdg-open`); a
  method of the portal no rule lists refused, a name without rules hidden (no owner, not listed); a
  fake Plasma on the fake portal's process: the tray's
  registration reaches it, its notification server, clipboard and another kded
  object don't, by name or by unique name; the proxy process running `dbus-proxy` from its store path), the subid maps (alice's auto range in the sandbox's userns
  from the host's view, the FHS env's identity map, `/etc/subuid` and
  `/etc/subgid` inside, `unshare --map-auto` and a root-mapping map through
  the shims and the broker, the shim in `/usr/bin`, a file written inside
  owned by alice, no capabilities over the netns, the broker refusing a
  client on the host and ending with the app), the scratchpad bind (mode 0700) and
  `claude-desktop-scratchpad-prune`, `claude-desktop-store-gc` (due on the
  marker and after a week, not otherwise, refused on the host), the GTK theme following the color scheme (at
  launch, live, and the launcher's supervise, which follows it, being the app's unit and ending it), the macvlan's DHCP
  lease, route and DNS (udhcpc in a mount namespace of its own with its
  closure and the sandbox's home, none of alice's files), the launcher `work` running next to the default
  sandbox (its own namespaces, MAC and lease, its own tray item at another
  pid, its re-entry found by app ID, its state dir and GC root, a
  `notify-send` from each launcher reaching the fake portal from its app ID,
  which names a `.desktop` file in alice's profile with that `StartupWMClass`, and its
  permissions broker: the daemon's unit and its start limit, `/run/permissions` read-only, shared
  in the outer mount namespace and a slave where the app runs, `share` refused
  from there, the standing grants from the config: the host command, a tool of
  the MCP server's from its start, called without asking, and the host socket: an echo server of alice's
  reached at `/run/permissions/sockets/echo` (the test binary's `live-connect` as the client), a held connection
  closed by the revoke, one without a grant closed at once; grants through the MCP
  server that the test answers on `control.sock`: the host socket again, a folder
  mounted read-only, nodev and nosuid where the app runs and one with a mount
  beneath it refused; a SIGKILL of the daemon closing its connections and ending its
  folder grant, the standing grants alone back under new ids after its restart, the overview in its state, no
  system bus socket inside, the Permissions window
  staying up against it with the launcher's app ID as its `--app-id`, the state machine tests run live (below), the daemon ending with the
  sandbox; its cgroups: the app's unit delegated, nothing in its root or in `sandbox/`, nixpak's launcher in
  `supervisor/`, bwrap's child and the app in `sandbox/app/` with the launching unit's environment, the default
  launcher's in a unit and slice of its own, the broker and a host command call units in the
  slice, both re-entries in `app/`; inside, `/sys/fs/cgroup` the sandbox's subtree alone, writable, without a unit's
  name, the host's cgroup2 with `nsdelegate`, the caps (66 and 5) on the unit's cgroup; `cgrun` giving a job a cgroup of its own with its `memory.max` and `cpu.weight` (50, or `--cpu-weight`'s, a bad one
  refused), the work slice's `cpu.weight` 50, killing one past 64M with the app running
  on, and removing the cgroup; the sandbox refused writing its root's `memory.max` and `cgroup.max.descendants`, a
  process in its root, unmounting the bind from a nested user namespace, a 64th cgroup and a fifth level, both still
  refused after it lifts `sandbox/`'s own caps from a nested cgroup namespace rooted at `app/` (which nsdelegate allows),
  and a cgroup2 mount of its own in a nested cgroup namespace rooted at `sandbox/app/`, without `supervisor/` or the unit's caps), its own `/etc/hosts`, the closure's GC root on the
  host and `/etc` bound from the store except passwd, group and machine-id,
  `nettest.sh` inside the sandbox against a host
  service on the LAN address, loopback and a dummy interface, a `files`
  script each under `/etc` and `~/.config` running what it references, the
  `claude://` re-entry (in the app's netns and pid ns), both re-entries
  past a process at the app's pid in a pid ns of the sandbox's own, `XDG_CURRENT_DESKTOP`
  with COSMIC ahead of GNOME (KDE as is), `claude-desktop --shell` (in the app's namespaces, with no_new_privs as `claude://` has it,
  the terminal's `TERM` with the fallback when its `TERMINFO` is missing, and
  starting the app when it isn't running, in the app's unit), the wrapper refusing system
  users, and
  `netns-macvlan` refusing a second user, bob, alice's namespaces, each of
  its checks on its own, and alice a netns of hers below a user namespace
  root made and mapped her uid into. bob's commands go through `runuser`,
  not `setpriv`, which keeps root's capabilities through the exec. Debug it
  with `nix run .#checks.x86_64-linux.vm-<part>.driverInteractive`.
  The broker's state machine tests also run live there (`TestLiveMachine`,
  `live*_test.go`, skipped elsewhere): the test binary, built with `go test
  -c`, drives the work launcher's daemon under systemd from the host as
  alice, with a copy of itself inside the sandbox (through the launcher's
  re-entry) as the caller on `request.sock` and the client of the echo socket.
  The daemon has standing grants of the test host command and the echo socket.
  The actions: requests and calls generated as above from the declarations the daemon lists (folders beneath
  `/srv/notes`, outside it and `/srv/mounted`; no lease shorter than an hour) and judged by the same oracle,
  floods, and `share` from inside, connections to the echo socket (kept open while their grant lives), the
  user's answers and revoke through `control.sock`, releases, `systemctl restart`
  (the standing grants back),
  and logind's Lock of a graphical session of alice's made for
  it. After every step the window's state, the open connections,
  the grant directory and the mounts in the outer mount namespace and where
  the app runs match the reference model. 15 sequences with seed 1 (about a
  minute); by hand, `LIVE_RAPID` replaces the flags, for example
  `LIVE_RAPID='-rapid.seed=0 -rapid.checks=100' LIVE_TIMEOUT=3600 nix run
  .#checks.x86_64-linux.vm-live.driverInteractive`, then `test_script()`.
  A failure shrinks slowly here (each attempt replays its sequence live):
  `-rapid.seed` of the failing sequence with `-rapid.checks=1` and a long
  `-rapid.shrinktime` gets further.

CI runs on pushes to `main` and on pull requests, split by what changed
(`.github/workflows/test-*.yaml`, each with its own `paths:`): `test-go`
builds the Go packages with their tests, `test-module` the eval tests, the
app's closure and shellcheck, `test-vm` the VM test's parts (one job,
in parallel, the loop at 100 launches), and `test-models`
runs `models/check`. A change to docs alone runs none.

Every new test gets the revert check: break the implementation, see the test
fail, restore it.

Heavy runs go one at a time, under a memory cap: on 2026-11-04 a `nix flake
check` at this machine's defaults (`max-jobs = 32`, `cores = 0`) beside a
mutation run of four parallel `go test` workers most likely took the 64 GiB
machine down. Measured since: the flake check with `--max-jobs 4 --cores 4`
peaks at about 21 GiB, a serial mutation run at 1.5 GiB, `models/check` at
1.1 GiB. `models/check` caps itself (each model alone, a 4 GiB JVM heap with
SAT4J inside it, an 8 GiB address space): a model that needs more has too big
a scope, so shrink it and say what that costs; in the Claude Desktop sandbox
it also runs under `cgrun --memory=8G`. There, the rest goes under `cgrun` as
above; elsewhere, `nix flake check -L --max-jobs 4 --cores 4`, and extended
rapid runs and mutation runs one at a time under `prlimit --as=12884901888`
(not with `-race`, whose shadow memory needs a large address space).

Beyond the checks:

- In a consumer: build its config with `--override-input agent-sandbox
  path:<this checkout>`.
- Inside a running sandbox, `scripts/nettest.sh HOST:PORT...` checks that
  the given host-only services are unreachable and the internet is
  reachable.
