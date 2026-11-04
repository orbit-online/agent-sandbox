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
  pid behind a pidfd and whether it still runs; `dbuspolicy`: what a D-Bus rule
  set may not hold, per bus, from `policy.json`, which the module reads too
  and the broker and the proxy embed). Their packages in
  `nix/packages/<binary>/` build it with `subPackages`, from a source
  filtered to `go.mod`, `go.sum`, the binary's directory (its own `internal/`
  packages included) and the `internal/` packages it uses, each with its own `vendorHash` (Go vendors only what the
  binary imports). permissions-window has a module of its own, so miqt's cgo
  and Qt stay out of the others' closures.
- `cmd/netns-macvlan/`: the Go helper that gives the sandbox's netns
  its macvlan (`netns-macvlan --help`).
- `cmd/subid-broker/`: the Go helper that writes uid and gid maps for
  user namespaces inside the sandbox, and its `newuidmap`/`newgidmap` shims
  (`subid-broker --help`). `bwrap-subid.sh` in the module, the bwrap nixpak
  and the FHS env run, maps the user's subuid range in and starts it.
- `cmd/dbus-proxy/`: the Go D-Bus proxy that replaces xdg-dbus-proxy
  (`docs/permissions.md`, D-Bus), taking the subset of its arguments nixpak
  passes (`dbus-proxy --help`). The module hands it to nixpak as
  `pkgs.xdg-dbus-proxy` (the package links `bin/xdg-dbus-proxy` to it), so
  nixpak's launcher starts it as the session-bus proxy. `main.go`
  (arguments, listening, `--fd`), `address.go` (bus addresses), `sasl.go`
  (SASL toward both sides), `wire.go` (reading messages and their file
  descriptors, bounded), `header.go` (parsing the header, decoding a body
  where needed, encoding), `budget.go` (each client's share of bytes and file
  descriptors and the whole proxy's), `sender.go` (each side's write queue),
  `rules.go` (rule sets and xdg-dbus-proxy's matching), `names.go` (a client's
  unique names and what they owned), `client.go` (a connection's lifecycle),
  `fromclient.go` and `frombus.go` (the filtering each way), `busmsg.go` (the
  messages the proxy makes up), `control.go` (the control socket the
  permissions broker adds and removes live rule sets on, `--control`, and its
  peer check) and `livesets.go` (a set's names looked up, the connections that
  used it ended). With D-Bus capabilities on the system bus, `bwrap-subid.sh`
  starts a second instance for the system bus as a unit of its own.
- `cmd/permissions-broker/`: the Go daemon that grants the sandbox
  outside access while it runs, per `docs/permissions.md`, and the sandbox's
  `permissions` MCP server (`permissions-broker --help`). A launcher runs it
  with `permissions.enable`, off by default: `claude-desktop.sh` starts it as a
  user unit, nixpak binds its grant directory read-only at `/run/permissions`,
  and `bwrap-subid.sh` asks it to share that mount before the FHS env's bwrap.
  Its own packages are in `cmd/permissions-broker/internal/`, each auditable on
  its own: `schema` (the JSON Schema subset
  arguments are checked against), `duration` (the ISO 8601 durations of leases
  and validities), `wire` (the protocol on request.sock and control.sock, and
  `Call`, its client side), `notify` (asking with a notification), `mcpserver`
  (the MCP server inside the sandbox, a client of request.sock, with a tool per
  host command), `hostcmd` (a host command's declaration: its checks, its free
  arguments, the consent's scope, what it reads on stdin), `hostsock` (what a
  host socket may not be, reaching one without links, the addresses in the grant
  directory), `dbusgrant` (a D-Bus capability's rule set, its checks and scope,
  the connection to a proxy's control socket), `mountinfo` (mountinfo files) and
  `mounts` (attach grants in the sandbox's mount namespace: the folders ceiling
  by path and identity, the helpers run through `nsenter` that clone a host path
  and join the sandbox's mount namespace only after their exec on the host's
  mounts, to share the grant directory and mount and unmount grants there, the
  grant's mount and the holders' scan; it takes the sandbox as an interface).
  Package main is the core, one concern per file: `main.go` (the arguments),
  `config.go` (the config, the capabilities loaded from it), `run.go` (serving
  until the sandbox ends), `sockets.go` (listening, peer checks, the request and
  control handlers), `consent.go` (and the log of decisions), `leases.go` (and
  logind), `standing.go` (the standing grants from the config), `views.go` (and
  opening the window), `types.go`, `clock.go` (the time and timers of leases and
  answers, which tests fake), `capability.go` (a capability, its parameters and
  summary), `kind.go` (what a capability's type adds, which the core calls into:
  its checks, a grant made live and ended, the consent's summary and scope, the
  list), `instances.go` (instances, the instance check and exclusive locks),
  `commands.go` (host command capabilities: bounding arguments, instance globs),
  `call.go` (a call: covered or asked, run as a transient unit, its output),
  `hostsockets.go` (listening at the host sockets' addresses), `splice.go`
  (connections to them, spliced under a grant), `dbus.go` (D-Bus capabilities, a
  proxy per bus, a bus's grants ended when its proxy's connection breaks),
  `sandbox.go` (finding and pinning the sandbox), `members.go` (its processes by
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
  glue). `Permissions.qml` is the content, with its parts in files of their
  own: `Section.qml` (a collapsible section), `RequestRow.qml`, `GrantRow.qml`,
  `Badges.qml` and `Badge.qml`, `ReadOnlyText.qml` (selectable text). The launcher opens it with
  `--permissions` and the `.desktop` file's "Permissions" action; the broker
  opens it on a notification's Options. Its wrapper sets Qt's plugin and QML
  paths to its own Qt's, Plasma's style and platform theme included: the
  host's may be another Qt.
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
`packages.<system>.dbus-proxy`, `packages.<system>.permissions-broker`, `packages.<system>.permissions-window`.
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
  `permissions.enable`, the assertions on standing grants (only with the
  broker, of a host command, host socket or D-Bus capability it has, none of folders), the assertions on D-Bus
  capabilities (a name of their own, 1 to 64 rules the proxy takes, and the shared policy: a refused name, a wildcard
  short of three elements, the portal's ScreenCast and a `*.Get` rule, own of a host program's name and of another
  launcher's, polkit and login1's every method on the system bus, own and wildcards there; its names of its own and
  the tray's, and an explicit login1 call, accepted), the assertions on host sockets (a
  name of their own of 80 characters at most, a path or one instances glob, a clean path, no D-Bus bus, systemd
  user manager, accessibility bus, `/proc` or `/var/run` path, `$XDG_RUNTIME_DIR` as a whole or launcher socket, nor a
  glob that could match one),
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
  refused), nixpak's D-Bus proxy wrapper running our `dbus-proxy` (no
  xdg-dbus-proxy in the closure), and nixpak's
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
  read-only `/run/permissions` bind, the config with its folders, host sockets, standing grants and the window's overview (binds, devices, D-Bus rules, the network, the implicit lines), the wrapper's variables; its
  D-Bus capabilities: `--control` (in `session/`), `--bus` and `--app-id` in the session proxy's arguments, the system-bus proxy started by its bwrap and
  bound read-only at `/run/dbus`, both control sockets and the capabilities in the broker's config; none
  of it for the default launcher), and its `.desktop` file (name, Exec, the
  Permissions action, which the default launcher lacks, no `claude://`
  handler, `StartupWMClass` matching the `desktopName` its asar gets, which
  the default launcher's keeps from upstream).
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
- `dbus-proxy`: the package build runs its Go tests (`*_test.go`) with
  `-race`, against a `dbus-daemon` of the test's that allows unrequested
  replies and eavesdropping (each test's control shows the proxy refusing
  what the bus would pass): a hidden name (not listed, no owner, a call unknown),
  `--see` (visible, a call denied), `--talk` (any call and its reply, by the
  owner's unique name too), `--own`, `--call` rules (method and path, an interface on a `/*`
  subtree, `@/*`, `*`), `--broadcast` (none without a rule or with `--see`,
  and xdg-dbus-proxy's quirk of passing all of a ruled name's broadcasts),
  replies (let through to calls let through, refused unasked both ways, a call
  carrying a pending reply serial refused), NameOwnerChanged by policy,
  `BecomeMonitor` and eavesdropping match rules refused, file descriptors
  both ways, `--fd` (the byte, exit and the socket removed when it closes, as
  nixpak starts it), bad arguments refused (`--filter` missing too), libdbus's `dbus-send` as a
  client, sd-bus's pipelined SASL, SASL refusals, an oversized message and a
  message claiming file descriptors that never came; through a client
  speaking the wire itself (`raw_test.go`, `guards_test.go`): a serial reused while pending and
  a second Hello, serials 0 and past the client's range, file descriptors
  either way for a client that cancelled their negotiation, bus calls without
  an interface, with a non-string match rule or on another interface, a call
  without a destination, a caller made visible, another uid, file descriptors
  during SASL, the hold after Hello until the rules' names' owners are known,
  both pending-reply caps, SASL's command and line caps; the limits
  (`limits_test.go`): file descriptors per message and pending, bodies left
  undecoded, a client over the memory budget disconnected while another goes
  on, queued file descriptors past a client's share, and accepting again after
  running out of file descriptors (the test binary as the proxy, with a low
  `RLIMIT_NOFILE`); state alone (`judge_test.go`): a peer's reply to a call to
  the bus dropped, a unique name that left forgotten, a reply only to its
  caller; and the rule parser (wildcards refused), name lookup, the eavesdrop match, bus
  addresses, the budget and the bounded name table. Live rule sets
  (`control_test.go`, `control_args_test.go`): a set added applying to the
  next message (by the owner's unique name too), a removal refusing the next
  one and ending the connections that used it (their names dropped on the
  bus) but not the others, the broker's disconnect dropping every set and a
  next broker's applying, live call and broadcast rules passing only matching
  broadcasts, sets refused (the bus driver, a wildcard, no rules,
  too many, a bad id or name, an unknown op, past 32 sets, a line past 64
  KiB, what the bus's policy refuses), a peer of another uid and a second broker refused, which
  connection a removal ends, each way of using a set alone (`liveuse_test.go`: a broadcast received, a name
  owned and dropped, a name's owner asked, names listed, a NameOwnerChanged received), each direction taking
  the rules there are as its message is judged, the match rules for a removed set's names removed, and
  `--control` and `--pid` as the module passes them (the socket 0600 in a 0700
  directory, a path not clean or not relative or a bus not named refused, the exit with the pid). A stateful
  property test (`machine*_test.go`, `pgregory.net/rapid`) runs random sequences of `models/proxy.als`'s actions
  against the proxy with static rules and a control socket, between a `dbus-daemon` of its own (with an activatable
  name whose start stays pending until someone takes the name: the test binary as `DBUS_PROXY_LAZY`), two services
  straight on the bus and up to three clients speaking the wire: clients connecting, saying Hello (twice) and hanging
  up, calls to names allowed and hidden and to unique names with fresh, reused and forged serials (and a call
  carrying a reply serial), calls to the bus (owners, names listed, owned, released and started, match rules with and
  without eavesdropping, `BecomeMonitor`), replies to calls asked and not; services taking and releasing names,
  calling clients, replying, forging replies to clients' pending calls (a pending start included) and broadcasting;
  the broker adding and removing live sets, alone or right before a client's next message, and its connection
  dropping. Each step runs to quiescence (barriers through each connection, the bus dropping a connection that
  closed), then what arrived at each end, the connections closed, the replies on the control socket and every name's
  owner match a reference model (`machine_model_test.go`, `machine_bus_test.go`: the rules in force, each client's
  name table, pending calls both ways, the sets each client used, the bus's owners, match rules and pending calls;
  D1-D4). `go test` runs 50 sequences of about 30 steps (a few seconds); more with `-rapid.checks=1000
  -rapid.steps=100` (or `RAPID_CHECKS`, `RAPID_STEPS`), a failure again with the `-rapid.seed` it prints.
- `permissions-broker`: the package build runs its Go tests (`*_test.go`):
  durations, parameter validation, consent (denied, allowed, a live grant
  covering the same request only), host commands (the schema subset's
  keywords, a long enum said as a count, declarations refused for an undescribed or reserved argument, a
  bad name, result, timeout or glob; instances from a glob; the scope's parts
  in `state`, unrestricted first, and the bounding values by description; a call checked
  before the user is asked and told the scope, the window getting the call asking with its arguments whole
  (opaque ones by digest); the notification's "Covers" line with the lease and bounding values,
  leases in hours and minutes; a granted request's reason on the grant; a once grant covering only
  its call and refused to a request; a failing call's exit and stderr,
  recorded with opaque arguments by digest and its capability; image and text results, too much
  output stopping the unit; the unit's properties and a revoke stopping it;
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
  that isn't a child of ours, the sockets end to end with `watch` events, the config's overview passed on in `state`, and what
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
  for its length, one of 80 reachable through a long grant directory; a sync that looked before a grant's not
  closing its listener; a revoke during the connect closing the host's end whole; a grant without an address
  refused; no address made through a link; a stale address taken over; the addresses closed when the daemon
  ends. `internal/dbuspolicy` (built with the broker for its tests): each name, wildcard, method, own and system-bus
  rule of the policy, and how a rule's METHOD reads. D-Bus capabilities against a fake proxy (`dbus_test.go`):
  declarations refused (as the module's assertions, plus a unique name), the consent's scope naming the bus and
  rules as the proxy reads them, own and talk with what they bring, a grant adding its set to its bus's proxy only and
  a revoke removing it, a set the proxy refuses no grant, a standing grant's set pushed at start, a broken connection
  to the proxy ending the bus's grants (found by a removal or by an add) and the next grant dialling again. The MCP server: the nudge after 15
  minutes, not again right after, and in tool results; and the cleanup a stopped daemon's `ExecStopPost`
  runs (call units stopped, locks removed, folder grants detached, mountpoints and host socket addresses
  removed, also without the sandbox). Stateful property tests
  (`machine*_test.go`, `pgregory.net/rapid`) run random sequences of the
  protocol model's actions against the broker on the stand-in sandbox, with
  a fake clock, with standing grants of a host socket by instance, the exclusive host commands, another host
  command and a D-Bus rule set in its config, the last pushed to a stand-in for the proxy's control socket: requests of each type and host command calls (once leases
  included) from an anonymous caller, floods and crafted requests, answers on the
  notification and in the window, releases, lock events,
  time passing, revoke, a restart (granting the standing grants whose instance is there and the locks, ended ones
  too), `share`, the instances changing (an instance gone closing its console's connections), connections to the
  instances' consoles (echoed from the host under a live grant, closed at once otherwise, kept open and closed
  when their grant ends), another launcher's exclusive locks and control.sock from inside.
  After every step the broker's grants and gates, its
  mounts, locks, host socket addresses and open connections, the proxy's live rule sets and the window's view (the standing grants, ended
  and live, included) match a reference model
  (P1-P4, P6, P7, P9-P14, P16, P17; `models/README.md` lists the model's actions they leave to other tests). `go test` runs 50
  sequences of about 30 steps (half a minute or less); more with
  `-rapid.checks=1000 -rapid.steps=100` (or `RAPID_CHECKS`, `RAPID_STEPS`),
  a failure again with the `-rapid.seed` it prints.
- `permissions-window`: the package build runs, offscreen in Plasma's
  style, its Go tests (`window_test.go`: the operations against a fake
  `control.sock`, and the Qt glue, checked in `TestMain` since Qt wants the
  main thread: loading without QML warnings, the state arriving, a click
  reaching the broker through the property map) and `tst_permissions.qml`
  through `qmltestrunner` against a mock broker: an answer narrowed in its
  fields (kept through a refresh that rebuilds the list), deny, revoke then end (the holders of ended grants from the state, a possible one marked),
  a standing grant shown as from the config, the overview of the configuration (binds, devices, D-Bus, the
  network, the standing grants live and ended, the implicit lines), a repeated action still a change, Allow and Deny off for a second after a pending row moved up or was
  replaced in place, a grant expanded and collapsed (kept through a refresh) and a section collapsed, the
  badges (lease, from config, free arguments with a warning for an unrestricted one), a host command
  grant's parameters, holders, reason, scope (a long enum listed) and calls, the calls of ended grants, a host
  command request with no editable bounding value, its scope and the call asking, its lease still editable (once
  and Claude's proposal offered, no session lease) and Allow sending no parameters, and the text read-only and selectable.
  Repeater delegates aren't QObject children, so the Go side can't find
  them; Qt Quick Test can.
- `scripts`: shellcheck on `scripts/` and the module's scripts.
- `vm-launch`, `vm-store`, `vm-work`, `vm-live`: the NixOS VM test
  (`nix/checks/vm/`, needs KVM), in four parts that Nix runs in parallel;
  `vm` builds them all. Each boots the same two machines (built once) and
  runs the shared prelude in `vm/default.nix` (helpers, the boot), then its
  part's script, `vm/<part>.nix`: `launch` the default launcher and the
  network, `store` its store dir swapped or without a record and `--shell`
  starting the app, `work` the launcher `work` next to the default one with
  its permissions broker, `live` the broker's state machine tests. A router VM runs
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
  notifications; `xdg-open` reaching its OpenURI from a caller whose `/.flatpak-info` names the app; a
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
  launch, live, and the watcher ending with the app), the macvlan's DHCP
  lease, route and DNS (udhcpc in a mount namespace of its own with its
  closure and the sandbox's home, none of alice's files), the launcher `work` running next to the default
  sandbox (its own namespaces, MAC and lease, its own tray item at another
  pid, its re-entry found by app ID, its state dir and GC root, and its
  permissions broker: the daemon's unit and its start limit, `/run/permissions` read-only, shared
  in the outer mount namespace and a slave where the app runs, `share` refused
  from there, the standing grants from the config: the host command, a tool of
  the MCP server's from its start, called without asking, and the host socket: an echo server of alice's
  reached at `/run/permissions/sockets/echo` (the test binary's `live-connect` as the client), a held connection
  closed by the revoke, one without a grant closed at once; grants through the MCP
  server that the test answers on `control.sock`: the host socket again, a folder
  mounted read-only, nodev and nosuid where the app runs and one with a mount
  beneath it refused; a SIGKILL of the daemon closing its connections and ending its
  folder grant, the standing grants alone back under new ids after its restart, the overview in its state, D-Bus
  grants on the restarted daemon (the system-bus proxy's unit, holding only its own control directory,
  `/run/dbus/system_bus_socket` a socket on a read-only
  bind, hostnamed's `Hostname` on the system bus and the fake Plasma's clipboard on the session bus refused before a
  grant, passed under one and refused after the revoke, which closes a held `gdbus monitor`; polkit through a grant
  of login1's `CanReboot`: `challenge` without a graphical session of alice's, `yes` with an active one, as for a
  process of hers in a user unit on the host; the VM has polkit for it), the Permissions window
  staying up against it, the state machine tests run live (below), the daemon and the system-bus proxy ending with the
  sandbox), its own `/etc/hosts`, the closure's GC root on the
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
  with `nix run .#checks.x86_64-linux.vm-<part>.driverInteractive`.
  The broker's state machine tests also run live there (`TestLiveMachine`,
  `live*_test.go`, skipped elsewhere): the test binary, built with `go test
  -c`, drives the work launcher's daemon under systemd from the host as
  alice, with a copy of itself inside the sandbox (through the launcher's
  re-entry) as the caller on `request.sock` and the client of the echo socket.
  The daemon has standing grants of the test host command and the echo socket.
  The actions: requests of each type (the host command and the host socket, calls of the host command,
  folders beneath `/srv/notes` and outside it) and lease, floods, crafted
  requests and `share` from inside, connections to the echo socket (kept open while their grant lives), the
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
in parallel), and `test-models`
runs `models/check`. A change to docs alone runs none.

Every new test gets the revert check: break the implementation, see the test
fail, restore it.

Beyond the checks:

- In a consumer: build its config with `--override-input agent-sandbox
  path:<this checkout>`.
- Inside a running sandbox, `scripts/nettest.sh HOST:PORT...` checks that
  the given host-only services are unreachable and the internet is
  reachable.
