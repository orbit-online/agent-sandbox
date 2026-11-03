# Permissions: granting the sandbox outside access while it runs

Status: written 2026-10-31, rewritten 2026-11-03 for the broker as gateway. Built before the rewrite: the daemon
(`cmd/permissions-broker/`) with consent, leases, standing grants from the Nix config and the MCP server, the
Permissions window (`nix/packages/permissions-window/`) and folder mounts (`permissions.folders`), behind a launcher's
`permissions.enable`. Built since: declared host commands (`permissions.commands`), with a consent that names what a
grant covers and the window's redesign; the first half of step 3 (2026-11-03): plugins, their service units and tools
and session leases removed, folders built into the broker, and host sockets at stable addresses
(`permissions.sockets`). The Alloy models (`models/`) still describe what step 3 removed. Not built yet: the Go D-Bus
proxy, device grants. Steps lists the order.

## Why

Everything the sandbox can reach today is fixed when it starts: binds, devices, D-Bus rules, the network. Anything
else needs a config change, a rebuild and a restart, so access tends to get granted broadly and kept forever. Some
access is only needed for a task: a folder for an afternoon, a VM while it runs, a cert for an hour.

The permissions broker grants and revokes such access while the sandbox runs. The user answers each request in a
notification drawn on the host, picks how long it lasts, and sees and revokes live grants in a Permissions window.

The first design had plugins run on the host per grant: a `service` grant started a socket-activated unit and created
its socket, named after the grant, and the MCP server offered the plugin's tools while the grant lived. Three things
went wrong with it:

1. Access was the socket existing. Nothing had a stable address, so everything above it had to follow the grants.
2. Tools that appear mid-session never reach Claude: Claude Code ignores `notifications/tools/list_changed` (What's
   verified, 8). The interface has to be there from the start, with a refusal at call time for what isn't granted,
   as other permission systems do.
3. xdg-dbus-proxy takes its rules from argv only (verified, 7), so every change of scope needed a new process. It bent
   three designs.

## Goal

- One host-side daemon per launcher, outside bwrap, owned by this repository. It is the only place that enforces
  anything: what runs on the host for the sandbox carries no consent or grant checks of its own, so a bug there can't
  leak access.
- On the host, for the sandbox, run only the broker and declared host commands. A host command is a script, an argument
  schema, a description and a capability, declared in the sandbox's Nix config. It runs only under a grant the user
  gave, with its bounding arguments fixed by the grant and its free arguments named in the consent.
- A static surface: the permissions MCP server lists every declared host command from its start, and host sockets sit at
  addresses that don't change. Authorization happens at call or connection time.
- Everything else runs inside the sandbox: ordinary MCP servers over granted primitives (a socket, a folder, a device,
  a D-Bus name).
- A Go D-Bus proxy with live rules replaces xdg-dbus-proxy, nixpak's session-bus proxy included: one D-Bus gate for
  the session and system buses.
- A notification for every request (reason, Allow, Deny, Options), and a Permissions window from the launcher's
  desktop actions, next to "New shell", listing what's granted and what can be.
- Leases: once, until the screen locks, for a duration. Grants end on their lease, on revoke, on release from inside
  and when their instance goes away. What should always be granted is declared in Nix as standing grants.

What the broker guarantees: nothing runs without a grant; a grant covers exactly the values of the bounding arguments it
names; arguments stay data, which the broker validates and never interprets; and the consent says what is really
granted, free arguments included. The schema keeps a config tidy and guarantees nothing: a command may declare a free
string with no pattern, and then the grant hands that string over whole. What a script does with its input is the
config's responsibility, as with a sudoers entry. Whether a script leaves something running isn't a security property
either: a script can start a server, and the program it drives (QEMU) may be resident anyway.

## What's verified

On kernel 6.18, bubblewrap 0.12.0, Claude Code 2.1.309 (`scripts/ns-inject-spike.py` covers the first four):

1. An unprivileged host process can bind folders (rw, ro) and device nodes into a running sandbox and detach them:
   a helper joins the userns owning the target's mount namespace, unshares a mount namespace of its own,
   `open_tree(OPEN_TREE_CLONE|AT_RECURSIVE)` there (plus `mount_setattr` for read-only) and passes the fd on; a
   second process joins that userns and mount namespace and `move_mount`s it. `open_tree` straight on a path from
   another mount namespace fails (EINVAL).
2. The owner of the mount namespace is found with `ioctl(NS_GET_USERNS)` on it. Without `--userns-block-fd`, bwrap
   runs the sandbox in a second userns that has no capabilities over its mounts; the sandbox passes the block fd at
   both levels, so there they coincide.
3. The sandbox can't unmount a grant. `MNT_DETACH` leaves files and cwds already open inside working.
4. With the grant directory `MS_SHARED` in M1 (nixpak's mount namespace) before the FHS env's bwrap copies it,
   mounts and unmounts there propagate into M2, where the app runs, and further down to anything that keeps slave
   propagation. That holds with the grant directory a read-only bind of a directory outside, the mountpoints made
   outside; the sandbox can't write to it.
5. `SO_PEERCRED` and `SO_PEERPIDFD` give a peer's pid as seen by the daemon (and a pidfd) from three pid namespaces
   down; the daemon reads the peer's ancestors and environment in `/proc`.
6. Claude Code sets `CLAUDE_CODE_SESSION_ID` in the environment of what it spawns (MCP servers, shells), not in its
   own. The app starts its MCP servers itself with only `HOME`, `PATH`, `SHELL` and `USER`, so a server it starts
   finds no session above it (tested on the host, 2026-11-01). Session leases were dropped for this (Decisions).
7. xdg-dbus-proxy takes its rules from its arguments only; there is no way to change them while it runs.
8. Tested on the host on 2026-11-01, and failed: Claude Code doesn't pick up tools an MCP server adds mid-session
   with `notifications/tools/list_changed`, in the app's Code tab or in `claude -p`. The documentation said it would.
9. nixpak (as locked here) starts one D-Bus proxy, `XDG_DBUS_PROXY_EXE` with the argv from `XDG_DBUS_PROXY_ARGS`
   (bus address, outside path, its `dbus.args`, `--filter`) plus `--fd=3`, and waits for a byte on that fd
   (`launcher/dbus_proxy.go`). Its launcher wrapper sets `XDG_DBUS_PROXY_EXE` at build time (`makeWrapper --set`) to
   a script of its own that runs `pkgs.xdg-dbus-proxy` in a bwrap with `/.flatpak-info`, because portals read
   `/proc/<caller>/root/.flatpak-info` and the caller they see is the proxy (`modules/launch.nix`). `dbus.args` are
   passed literally, without expanding variables.
10. godbus/dbus v5 decodes and encodes single wire messages with their file descriptors
    (`DecodeMessageWithFDs`, `Message.EncodeToWithFDs`, v5.2.4), which is what a filtering proxy needs.

## Components

```
host (user, no capabilities)                       sandbox
┌──────────────────────────────┐                   ┌───────────────────────────────────────────┐
│ permissions-broker (daemon)  │  request.sock     │ /run/permissions/                         │
│  consent, leases, grants     ├──────────────────►│   request.sock     (requests, calls)      │
│  host command calls (units)  │  grant dir bind   │   <grant>/         (mounts)               │
│  socket splicing             │                   │   sockets/<cap>[/<instance>]              │
│  mount helpers               │                   │                                           │
│ control.sock (host only) ◄───┼─ Permissions      │ permissions MCP server (stdio)            │
│                              │  window           │                                           │
│ D-Bus proxies (session,  ◄───┼─ live rules       │ session bus, system bus sockets           │
│  system), in nixpak's bwrap  │                   │                                           │
└──────────────────────────────┘                   └───────────────────────────────────────────┘
```

- `permissions-broker`, Go, in `cmd/permissions-broker/`. One per launcher, as the transient user unit
  `claude-desktop[-<name>]-permissions.service` with `Restart=on-failure`, which `bwrap-subid.sh` starts with
  `systemd-run --user` before it execs bwrap. It listens on:
  - `request.sock` in the grant directory, for the sandbox.
  - `control.sock` in the launcher's runtime directory on the host, mode 0600, for the window and the launcher. It
    answers only peers in the daemon's own user namespace, so nothing in the sandbox can use it even if a ceiling
    exposes the path.
  - one socket per declared host socket under `sockets/` in the grant directory (Host sockets).
- The grant directory: `$XDG_RUNTIME_DIR/claude-desktop[-<name>]/permissions/` on the host, bound **read-only** at
  `/run/permissions` in the sandbox. This is the one bind the feature adds. Connecting to a socket on a read-only
  bind works; creating, renaming or replacing anything in it doesn't, so the sandbox can't plant a symlink where a
  mountpoint or socket will go, or remove `request.sock`. The daemon creates every entry on the host side, through a
  dirfd with `O_NOFOLLOW`, and refuses to start when the directory isn't its own or is a link. Mountpoints get names
  it picks at random; sockets get the stable names their declarations give.
- `permissions-mcp`, the same binary as an MCP server, run inside the sandbox from the module's MCP servers. A client
  of `request.sock`.
- The D-Bus proxies, Go, the same module: the session-bus proxy nixpak starts, and a second instance for the system
  bus that the launcher starts. The broker sets their live rules over a control socket each (D-Bus).
- The Permissions window, a Qt 6 QML app in Go (miqt's bindings) talking to `control.sock`, opened by the desktop
  action "Permissions" (`claude-desktop[-<name>] --permissions`). Qt because it's native under Plasma; Go like the
  rest. It is a client only: all state lives in the daemon. Above the grants it shows, read-only, what the
  configuration gives the sandbox from its start (Overview, below). It refreshes on every watch event, which the
  sandbox can cause at will. So pending requests come in the order they arrived, and a row doesn't move under the
  pointer. What the user set on a row (narrowed parameters, a lease, a grant expanded, a section collapsed) is kept
  by id through the refresh.

  Its sections (waiting requests, what's still open in ended folder grants, the configuration, the grants, host
  command calls, recent decisions) each collapse to their header. A grant is one line: its summary (capability and
  bounding values), its badges and the time it has left, with Revoke; expanded, it shows its parameters by their
  declarations' descriptions, who may use it (the sandbox as a whole), Claude's reason, and for a host command capability what it covers and the calls made under it. Badges: the
  lease (or "from config" for a standing grant) and a host command
  capability's free arguments, with a warning badge for each unrestricted one. A waiting request shows its summary,
  the same badges for free arguments, for a host command its bounding values, what a grant covers and the call
  asking (its command and free arguments, opaque ones by digest, the rest whole), and Claude's reason. Fields narrow a
  folder or service request; a host command request has none, only its lease, which offers `once` for a call and
  Claude's own proposal. Everything the broker or Claude wrote is in read-only text boxes the user can select and
  copy from. The broker sends what this needs in `state`: each host command capability's `scope` (its commands and
  free arguments, unrestricted ones first, each with its description and what its schema allows), a pending call's
  `command` and `arguments`, a grant's `reason`, and each call's `capability`.

### Handle on the sandbox, and restarts

The daemon finds the sandbox the way `claude-desktop.sh`'s `sandbox_pid` does: nixpak's `bwrapinfo.json` for the
launcher's app ID gives the outer bwrap's `child-pid`, valid once its mount namespace differs from the host's. The
daemon takes a pidfd for it and accepts it only while the pid is in the mount and pid namespaces `bwrapinfo.json`
reports, its parent is a process in the daemon's user namespace, and its user namespace, which owns its mount
namespace, is a child of the daemon's: a stale instance directory's pid, held by now by a process in another sandbox
or a nested namespace, doesn't pass. It then pins the sandbox's user, mount and uts namespaces as open files, and every
helper joins those. Code running as bwrap's init could move the pid into namespaces of its own (`unshare -Um`); the
daemon refuses to act once the pid shows other namespaces than the pinned ones, and reads M1's mount table only while
the pid is checked to be in it. The pidfd turning readable means the sandbox ended, upon which the daemon stops its
units and exits. At first start it waits for the sandbox to appear and creates `request.sock` only then.

Started again after a crash, it finds the same sandbox the same way and reconciles before serving: it detaches
everything mounted under `/run/permissions` in M1, stops leftover call units of its launcher (bound to the old daemon's
unit, so normally gone already), and starts with its standing grants alone. Leases that ran while it was down are gone
rather than extended; Claude asks again. It finds the grant directory shared by the daemon before it (its mountinfo says
so) and takes it over.

Grants end with the daemon, a crash included: the connections it splices close with it, the D-Bus proxies drop its rule
sets when its connection to them closes, the units host command calls run in are bound to its unit (`BindsTo=`), so
systemd stops them when it stops or fails, and its unit's `ExecStopPost=` (`permissions-broker cleanup`, which systemd
runs after a crash too) detaches the folder grants and removes their mountpoints. Credentials a host command printed
stay valid until they expire: they can't be taken back. A daemon starting runs the same cleanup first, in case it didn't
happen.

### Sharing the grant directory

The FHS env's bwrap copies M1 when it starts. Before it does, `bwrap-subid.sh` (`SUBID_MAP=parent`, inside M1)
sends `share` on `request.sock` and waits for the answer (up to 10 s, for the daemon to come up). The daemon
checks that the client is in M1 and makes
`/run/permissions` shared there. In M1 that mount is a bind of the host directory, so it stays a slave of the host
too; files the daemon creates on the host side (sockets) show up as before. The daemon serves `share` once per sandbox: a
second one, from anything else in M1, would come after the FHS env's bwrap copied M1, where
grants no longer reach the app. If `share` fails, the launcher goes on without mount grants rather than not
starting; the daemon then refuses mount requests, and the window says why.

### Privileged steps in a Go process

Go processes are multithreaded from the start, and the kernel refuses to move a multithreaded process into another
user namespace (`setns` and `unshare` both fail with EINVAL). As subid-broker does, the daemon runs these steps as helpers of
its own binary through util-linux: `nsenter --user=<owner> -- permissions-broker clone-tree <root> <rel> <mode>`
unshares a mount namespace of its own, and sends the detached tree's fd back over a socket pair, and `nsenter --user=<owner>
-- permissions-broker move-tree <dir> <dirid> <name>` attaches it.

None of them is exec'd in M1, where a path shows what the sandbox wants: from a nested user and mount namespace,
after `pivot_root` and a lazy unmount of the old root, it can rename a directory that is a mountpoint in M1
(`/nix/store`, `/run/permissions`), as the kernel refuses that only for mounts in the caller's own namespace, and
put one of its own in its place. nsenter joins only the user namespace (and the uts namespace, without which its
`--keep-caps` has no effect), so it execs the daemon's binary on the host's mounts. `make-shared`, `move-tree` and
`detach` then join M1 themselves, on a thread with a filesystem context of its own (`unshare(CLONE_FS)`, then
`setns`), and resolve nothing there but the grant directory: opened with `RESOLVE_NO_SYMLINKS`, and refused unless
it's a mount root with the device and inode of the host's directory. They act on single entries beneath it, which
only the daemon creates.

## What can be granted

A grant is of a capability, with values for its bounding arguments where it has any. Four types, each named for what
is granted and declared in the launcher's `permissions` options:

- `command` (`permissions.commands`): host commands, scripts run on the host per call;
- `socket` (`permissions.sockets`): host sockets, each reachable at a stable address inside (the first design's
  `service`, which named what ran behind the socket rather than what was granted);
- `mount` (`permissions.folders`, later devices): a folder or device node mounted in the sandbox's namespaces;
- `dbus` (`permissions.dbus`): rules added to a D-Bus proxy.

### Declared host commands

A capability groups commands that one grant covers. It declares its bounding arguments; each command declares its free
arguments, its result type and what it runs:

```nix
permissions.commands.windows-vm = {
  description = "Control a running Windows VM";
  bounding.vm = {
    description = "the VM";
    instances = "$XDG_RUNTIME_DIR/windows-vm/*/qmp-agent.sock";
  };
  exclusive = true;
  commands = {
    screenshot = {
      description = "Take a screenshot of the VM's screen";
      result = "image/png";
      run = [ "${windows-vm}/bin/windows-vm" "screenshot" ];
    };
    click = {
      description = "Click at a position on the screen";
      arguments = {
        x = { type = "integer"; minimum = 0; maximum = 7679; description = "column, in pixels"; };
        y = { type = "integer"; minimum = 0; maximum = 4319; description = "row, in pixels"; };
      };
      run = [ "${windows-vm}/bin/windows-vm" "click" ];
    };
    exec = {
      description = "Run PowerShell in the guest";
      arguments.script = {
        type = "string"; multiline = true; maxLength = 65536;
        description = "any PowerShell, run as SYSTEM";
      };
      run = [ "${windows-vm}/bin/windows-vm" "exec" ];
      timeout = "PT5M";
    };
  };
};
```

- Bounding arguments belong to the capability, so every command of it takes them, and a grant fixes their values: one
  grant of `windows-vm` with `vm = "win11"` covers every command's calls on that VM and no other. A capability without
  bounding arguments is granted whole.
- Free arguments belong to the command. A grant covers any value the schema allows, for the grant's lease.
- The schemas are a subset of JSON Schema the broker validates itself: `string` (`maxLength`, `pattern`, `enum`),
  `integer` and `number` (`minimum`, `maximum`), `boolean`, and arrays of those (`maxItems`). Strings carry no control
  characters unless declared `multiline` (newlines and tabs then). A string marked `opaque` is data the user has nothing
  to read in (a public key, a CSR), shown by its digest (Requests). Every argument needs a description; the consent is
  built from them. A call must give every free argument; a bounding argument it leaves out is a value of its own (the
  grant covers calls that leave it out too), except one with `instances`, which an instance must match. A free string
  without `maxLength` may be 64 Ki characters. Bounding arguments are scalars on one line: no arrays, no `multiline`,
  as the summary quotes them.
- `result` is `text` (the default) or an image MIME type.
- `maxValidity` (optional) caps the validity the command is told (below), for commands that issue credentials.
- `exclusive` (optional): an instance may be granted to one launcher at a time. The daemons share lock files in
  `$XDG_RUNTIME_DIR/agent-sandbox-permissions/`, one per instance, holding the launcher's name and linked into place
  so only one daemon wins. A daemon removes its locks when the grant ends and in its cleanup after a crash; a
  standing grant takes one like any other. Grants of one launcher share a lock only with the same parameters (a
  `once` grant beside another): other parameters are another client of the instance, refused as before. A request
  for an instance another launcher holds is refused, naming it.

The module checks at eval time what it can: names fit MCP's tool names (`<capability>_<command>`, at most 64 characters
of `[A-Za-z0-9_-]`), every argument is described, no argument is named `reason` or `lease` (the broker adds those),
`run` is a list. The daemon checks the rest at start and doesn't start on a config error.

A plugin is now a Nix module that sets such a declaration with its package's scripts in `run`. Nothing of it runs on
the host except those scripts, per call.

### Running a call

A call is a request: `call` on `request.sock`, which the MCP server sends for the command's MCP tool. The broker:

1. validates the arguments against the schemas, and the bounding values against the instances (below);
2. looks for a live grant of the capability with the same bounding values; without one, it asks the user with the
   call's `reason` and proposed `lease`, and makes the grant on Allow. A `once` grant is tied to the call it was made
   for and covers no other, queued or concurrent;
3. runs the command's `run` as a transient user unit (`systemd-run --user --pipe --collect`, named
   `perm-<launcher>_call-<id>`, or `perm_call-<id>` for the default launcher), bound to the
   daemon's unit, with `RuntimeMaxSec=` its `timeout` (default one minute), in the user manager's environment and
   nothing of the sandbox's. The arguments go on stdin as one JSON object, never on argv and never through a shell:

   ```json
   {"capability": "windows-vm", "command": "click", "grant": "g-3f2a91",
    "bounding": {"vm": "win11"}, "arguments": {"x": 120, "y": 40}, "validity": "PT58M"}
   ```

   `validity` is the time the grant has left, capped by `maxValidity`; a lease without an end (lock, standing, once)
   gives `maxValidity`, or none when the command declares none.
4. answers with what the script printed: exit 0 gives its stdout as MCP text (UTF-8, or the call fails) or as image
   content of the declared type. A non-zero exit, a timeout or more than 16 MiB on stdout is an MCP tool error
   carrying the last 4 KiB of stderr.

One call per set of bounding values runs at a time, and at most four in all; a call waits two minutes at most for its
turn. A command that hangs holds up its own bounding values until its timeout, and one of the four. A grant's end stops
its running calls with their units, a call whose unit systemd is still starting included.

The daemon records every call, covered or not, with its grant: the command, the time, the exit status, the tail of
stderr and the arguments (opaque ones by digest, strings cut at 200 characters), the last 200 calls, in memory, kept
after their grant ends. Only the window gets them, so a one-hour `exec` grant shows what ran under it.

### Writing a host command

The broker stops at the grant and the schema. The rest is the script's, and it runs as the user on the host. What
keeps one safe:

- Fix in the script, or in a bounding argument, everything that bounds access. Leave free only what the consent can
  say plainly: "any text typed", "any PowerShell as SYSTEM".
- Read arguments from stdin with a JSON parser and pass each as one argv element of what it runs. Never `eval`,
  `sh -c` or string interpolation into a command line; put `--` before arguments that could start with `-`.
- Prefer enums and bounded integers to strings, and a fixed set of operations to a general one. Raw protocol access
  (QMP, a shell) is a capability of its own and gets a consent that says so: QMP can make QEMU open host files.
- Take no paths. If a command must, resolve them under a fixed root without following links, as the broker's mounts
  do.
- Print only what the sandbox may see. Secrets stay on the host: a signing command reads its CA key, takes a public key
  as an opaque argument, fixes the principals and the validity, and prints the certificate.
- Exit when done. What a script leaves running is the config's to answer for.

### Instances

A bounding argument with `instances` takes only values the glob matches now: one `*` in one path segment, its match
being the value (`$XDG_RUNTIME_DIR` and `~` expanded by the broker). For windows-vm, a VM is an instance while its
runtime directory has `qmp-agent.sock`. The broker globs at each request and call, at the user's answer (an instance
gone by then isn't granted), and every 30 seconds; a grant whose instance is gone ends. The window and the MCP `list`
show the instances. Bounding arguments without `instances` take any value their schema allows.

### Host sockets

A declared host socket is reachable inside at a stable address while a grant covers it, for MCP servers and other
clients in the sandbox:

```nix
permissions.sockets.ssh-agent = {
  description = "Sign with the keys in the host's SSH agent";
  path = "$XDG_RUNTIME_DIR/ssh-agent.sock";
};
```

The broker listens at `/run/permissions/sockets/<capability>`, or `sockets/<capability>/<instance>` with a bounding
`instances` glob whose matches are the sockets, from its start or from when the instance appears. On a connection it
checks for a live grant; without one it closes the connection at once (the MCP `request` asks for the grant, since a
connection carries no reason). With one, it connects to the host socket and copies bytes both ways. It parses nothing
and passes no file descriptors. A revoke closes the grant's connections.

The host service sees the broker as its peer: an unsandboxed process with no `/.flatpak-info`, whose pid and
credentials are what `SO_PEERCRED` and polkit see. So a host socket must be one whose service authorizes nothing by
its peer, or whose peer checks the grant is meant to pass. Never declare a D-Bus bus, a portal or a service that
trusts `SO_PEERCRED`: that would hand the sandbox the host user's standing past every rule of the D-Bus proxies. An SSH
agent fits: it authorizes by holding the socket.

The module (at eval, on the literal path) and the daemon (at start, on the expanded one, and again at every
connection) refuse what's known to hand over more than its own service: anything beneath `/proc` (aliases of any path),
`/run/dbus`, `/var/run` (an alias of `/run`), and in `$XDG_RUNTIME_DIR` its `bus`, `systemd/` (the user manager's
private bus: a transient unit runs code on the host), `at-spi/`, `.dbus-proxy/`, `dbus-*`, `claude-desktop/`,
`.flatpak/`, `agent-sandbox-permissions/` and `nixpak-*`; the paths the D-Bus address variables name; and
`$XDG_RUNTIME_DIR` itself or what holds it. A path must be clean (no `.`, `..` or empty segments). A glob is refused
when its `*` could fall within one of those: when the segments before it lead to or into one. Without
`$XDG_RUNTIME_DIR` the daemon refuses every host socket. The broker reaches a socket without following a link anywhere
on its path (`openat2` with `RESOLVE_NO_SYMLINKS`), requires it to be a socket, and connects through that fd, so a link
planted in a glob's directory or swapped in for a declared socket leads nowhere, and a glob match that is a link isn't
an instance. This list is a guard against the known buses, not a proof: what any other socket gives the sandbox is the
config's responsibility, as with host commands.

### Mounts

The broker mounts a host folder or device node into the sandbox's namespaces, at `/run/permissions/<grant>`. Folder
mounts are built in, with `permissions.folders` as their source ceiling (below); nothing outside the broker resolves a
path or touches a namespace. Revoking detaches the mount. Fits: live folder mounts, single `/dev` nodes, block devices
mounted on the host and handed over as a folder. Moving a network device (a wifi phy) into the sandbox's netns is no
mount and would be a type of its own, left for later.

Open files survive a revoke of a mount grant (verified item 3), and so does a copy of the mount a process in the
sandbox made in a mount namespace of its own (`unshare -Urm`, `mount --rbind`): the detach and the removal of the
mountpoint end the grant's mounts in every namespace it propagated to, not copies made elsewhere. Neither can be
taken back short of ending the processes. The daemon knows the grant's mount by the mount id of the tree it attached,
read from M1's mountinfo right after the attach with its device, root and peer group (no grant if that fails), not by
its path: the sandbox can rename `/run/permissions` in M1 as above and put another directory there. That hides no
holder, and the detach still goes through: the helper refuses the directory in its place, and the daemon removing the
mountpoint on the host unmounts the grant in every namespace. `/run` in M1 stays writable to the sandbox: it's a
directory on bwrap's root tmpfs, nixpak passes bwrap no `--remount-ro`, and a read-only root would need checking
against everything that runs there, for a rename that no longer hides anything.
The daemon detaches first: how many processes, namespaces and mounts the scan below reads is the sandbox's choice, so
nothing of it comes before the detach. Then it lists the holders, within ten seconds, reading the mountinfo of each
mount namespace in the sandbox once (of every process of the sandbox's, found by its user namespace,
re-entries included):
- processes with a thread whose working directory, root or an open file is on the grant's mount or one propagated
  from it (its peer group, by `shared:` and `master:`), should the detach have left one, by `statx`'s mount id;
- processes with a thread whose working directory, root or an open file is on a detached mount of the grant's
  filesystem, one in no mountinfo the daemon reads (a lazy unmount's, an `open_tree` clone's, one in a namespace no
  process is in);
- processes mapping a file of the grant's, from `/proc/<pid>/maps`: the mapping's device (the superblock's, as
  mountinfo gives it), inode and path. `/proc/<pid>/map_files` would give the mapping's mount, but following its
  links takes `CAP_SYS_ADMIN` or `CAP_CHECKPOINT_RESTORE` in the initial user namespace, which the daemon lacks;
- processes with a thread whose mount namespace has a mount of the grant's filesystem and root.

A file on a detached mount, or a mapping on the grant's filesystem, is the grant's when the path `/proc` gives for it
(relative to a detached mount's root, or below a copy's mount point) names the same inode beneath the grant: the
daemon keeps the tree it attached open, and looks each tail of the path up there without links. Otherwise a file on a
detached mount makes its process a possible holder: it may hold another file of that filesystem, a file of the
grant's through a clone of something beneath it, or one deleted since; so does a mapping of a deleted file whose
directory is still the grant's. Every thread counts: one can have a working directory, file table and mount
namespace of its own (`unshare` with `CLONE_FS`, `CLONE_FILES` or `CLONE_NEWNS`). It does so however the grant ended
(revoked, released from inside, its lease run out) and keeps the last twenty grants' holders for the window, which shows them and offers to
end them: `SIGKILL`, which a process can't ignore, through a pidfd, only for processes in the sandbox, and only to the
process recorded (by its start time), not to a later one that got its pid. The daemon doesn't refuse a revoke because
something is in use, and doesn't kill anything without the user saying so.

Finding holders is best effort. A file descriptor can stay open where `/proc` shows no process holding it: in flight
in an `SCM_RIGHTS` message queued on a socket nobody reads yet, or registered with an io_uring as a fixed file. Either
keeps a grant that ended readable (and writable, for a read-write one) through that descriptor, for as long as the
sandbox likes, and the window lists nobody to end. Detached mounts and mappings show only partly:
- A detached mount is listed only through a file a process has open on it: an `open_tree` clone or a lazily
  unmounted copy, attached again in a mount namespace no process is in, shows nowhere.
- A mapping names no mount, only a path, so one the daemon can't look up beneath the grant isn't listed: through a
  detached clone of a directory beneath the grant (its path is relative to that directory), of a file renamed out
  of the grant through another mount of the filesystem, of a file deleted along with its directory, or beneath a
  directory the user can't search (the sandbox's subordinate ids own it).
- Past ten seconds the scan stops, and the processes it didn't get to aren't listed.

That limit comes from Linux itself. An open file description keeps its file and the mount it was opened on alive,
whatever happens to the mount after: unmounting it, even lazily, only takes it out of the tree. Linux has no general
`revoke()` that cuts off descriptors already open. So an fd queued in an `SCM_RIGHTS` message, an io_uring fixed
file, a detached `open_tree` clone, or a grant's mount propagated into a nested mount namespace that then made it
private, so the unmount doesn't reach it, all keep their access until the processes holding them end. Ending those
processes, at worst the whole sandbox, is the only way to take it back. Only mediating every access, a FUSE layer in
front of each grant that the daemon controls, could cut access off at revoke, at a cost in speed and machinery this
design doesn't pay. Only ending the sandbox ends every access to a grant for sure.

#### Source ceiling and resolving paths

The sandbox has rw binds of its own, which may lie under a ceiling root, and there it can plant links that point
anywhere on the host, including at what only the daemon, with the host user's rights, can read. So a path check
followed by a mount of the path isn't enough. The daemon checks the path lexically first: it refuses a path at,
beneath or above a denied directory, and what no ceiling source covers (the longest matching source decides whether
rw is allowed). Then the clone helper, after its `unshare`:

- opens the ceiling root without following any link (`openat2(RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)`): a root
  swapped for a link to elsewhere fails;
- opens the requested path beneath it without following links or crossing mounts
  (`RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV`);
- clones that one mount without its submounts (no `AT_RECURSIVE`): in the helper's namespace every mount is locked,
  so a source with mounts beneath it fails instead of bringing them along unchecked;
- mounts it read-only if asked, and a directory always `nodev` and `nosuid`.

With no link followed and no mount crossed beneath the root, the path checked is the path cloned, so the denied
list holds on the path alone. A ceiling root on a host mount that aliases a denied directory (a ceiling on
`/mnt/home` where that is a bind of `/home`) gets around it: that's the user's own mount and ceiling, and their
responsibility.

The path shown to the user is the one resolved, read back from the fd. A grant is of the path: what's mounted is
whatever is at the path at mount time, within the ceiling and outside the denied list. Between the question and the mount
the sandbox can only rename within its own rw binds, so a directory it swaps into the path is one it could read and
write already: that gains it nothing.

Never grantable, whatever a ceiling says: every launcher's state directory (another sandbox's home and store) and
`$XDG_RUNTIME_DIR` (the control sockets and every launcher's grant directory). A grant there would let the sandbox
approve its own requests. The daemon refuses to start when one of them expands to an empty or relative path.
A ceiling over `$HOME` or `~/.config`, rw, would hand the sandbox code execution on the host (user units, autostart):
that's the ceiling's choice, and one to avoid.

### D-Bus

A proxy written here replaces xdg-dbus-proxy. Like it, the proxy parses what the sandbox sends on the host, inside
a bwrap. Unlike it, it is in Go and takes rule sets while it runs.

The session bus: the module keeps nixpak's `dbus.enable` and calls nixpak with a `pkgs` whose `xdg-dbus-proxy` is
the new proxy (its binary under that name). Then nixpak's launcher still starts it in the wrapper that carries
`/.flatpak-info` and waits on `--fd=3` (verified, 9); `XDG_DBUS_PROXY_EXE` can't be pointed elsewhere, since
nixpak's wrapper sets it at build time.

The proxy takes the argv subset nixpak passes: the bus address and the path to listen on, `--fd`, `--filter`, `--see`,
`--talk`, `--own`, `--call` and `--broadcast`, with xdg-dbus-proxy's meaning (`[METHOD][@PATH]`, the path with an
optional `/*`). It does SASL toward both sides, passes file descriptors, tracks unique and well-known names, lets
replies through to calls it let through, and filters match rules. It refuses what would let a client read traffic not
addressed to it: `BecomeMonitor`, and match rules with `eavesdrop=true`. Those are the static rules, the ones the
Overview lists.

Built as `cmd/dbus-proxy` (static rules only so far). Where it differs from xdg-dbus-proxy 0.1.7, read from its source:

- It terminates SASL on both sides (EXTERNAL only, for the proxy's own uid) instead of passing the client's lines on,
  and forwards each message with the header fields it parsed and checked, re-encoded, and the body as it came. Bodies
  are decoded only where the proxy looks into them (bus driver calls up to 4 KiB, NameOwnerChanged, the bus's replies
  to calls it filters), so a message costs about its size.
- A serial reused while its call awaits a reply ends the connection, a second Hello is refused, and a reply to a call
  to the bus counts only from the bus: otherwise one call's reply could be judged as another's (a GetNameOwner reply
  read as Hello's raises the name's owner to TALK). A client's reply goes only to the caller waiting for it, and a
  method call without a destination is refused.
- A reply is a reply by its type. xdg-dbus-proxy takes any message with a reply serial for one, so a method call
  carrying the serial of a pending call to the client passes to any destination unchecked; the proxy refuses it.
- Monitoring and eavesdropping are refused without `--filter` too, and an `AddMatch` without an interface counts.
- Names in `--see`/`--talk`/`--own`/`--call`/`--broadcast` and rule paths must be valid; a unique name that leaves
  the bus is dropped from the client's table, which is bounded, as are pending replies, SASL lines and clients.
- Messages are at most 4 MiB (the sandbox's largest are icons; dbus-daemon's default is 32 MiB). Bytes (reader
  buffers, messages in hand, write queues) and file descriptors (received and not yet passed on) count against each
  client's share and a budget for the whole proxy (128 MiB, half the soft `RLIMIT_NOFILE`); a client that would go
  over is disconnected. Out of file descriptors, the proxy waits and accepts again.

Kept for compatibility: any rule gives its name TALK, and TALK passes all the name's broadcasts, so a `--call` or
`--broadcast` rule lets every broadcast of the name through (the module's rules rely on it). Live rule sets will
want this tightened.

The system bus: a second instance, which `bwrap-subid.sh` starts as a transient user unit next to the broker's, before
it execs bwrap, and waits for on `--fd` as nixpak does. It runs in a bwrap of its own holding its closure, the host's
system bus socket and its runtime directory. The host's socket is in that bwrap only, never in the sandbox. It listens
in `$XDG_RUNTIME_DIR/claude-desktop[-<name>]/dbus/`, which the module binds read-only at `/run/dbus`, so the socket is
at `/run/dbus/system_bus_socket` where clients look. It has no static rules beyond what any client needs to connect
(`Hello`, its own name), so until a grant adds rules it reaches nothing. It ends with the sandbox. What the bind gives
the sandbox is the proxy's listening socket, as nixpak's bind of the session proxy's socket does today: every message
through it passes the proxy's rules.

Live rules: each proxy listens on a control socket on the host side, mode 0600, which only the broker connects to. The
proxy takes it as `--control=<path>` relative to its `XDG_RUNTIME_DIR` (`dbus.args` aren't expanded, verified 9), in the
launcher's runtime directory, which nixpak's wrapper reaches through its `/run` bind. A D-Bus capability is a rule set,
granted whole:

```nix
permissions.dbus.timedate = {
  description = "Read and set the host's time zone";
  bus = "system";
  talk = [ "org.freedesktop.timedate1" ];
};
```

A grant adds its rule set under the grant's id; a revoke removes it. Either applies from the next message the proxy
reads. A revoke also closes every client connection that sent or received a message under the rule set: that drops
its names, match rules and exported objects on the bus, which a removed rule alone would leave. The client sees its
connection close, as when a bus goes away. When the broker's connection closes, the proxy drops every live rule set,
closing those connections the same way, and keeps its static rules.

What a revoke can't take back: file descriptors a client received over the bus (a logind inhibitor, a portal's fd)
stay valid until closed, as with mount grants. Every client's upstream connection is the proxy's, so services see one
process for the whole sandbox: polkit's `auth_admin_keep` and the like, keyed on that process, carry an admin
authorization across clients and grants for their keep time. Rule sets on services that authorize that way should
say so in their description.

## Requests

`request.sock` takes one JSON request per connection and answers with one JSON object.

| op        | parameters                                          | answer                                         |
|-----------|-----------------------------------------------------|------------------------------------------------|
| `list`    |                                                     | capabilities and instances, with live grants   |
| `request` | `capability`, `params`, `reason`, `lease`           | the grant: its id, and a mount or socket path  |
| `call`    | `capability`, `command`, `params`, `arguments`, `reason`, `lease` | the command's output              |
| `release` | `grant`                                             | ends the grant                                 |
| `status`  |                                                     | the live grants                                |
| `watch`   |                                                     | a stream of grant events, one JSON per line    |
| `share`   |                                                     | (from `bwrap-subid.sh` only, see above)        |

`request` grants ahead of use: a folder, a host socket, a D-Bus rule set, or a host command capability before its first
call (`params` holds the bounding values). `call` asks only when no grant covers it.

`reason` is required and goes into the notification as text: whitespace and control characters folded to single
spaces, 300 characters, quoted, markup escaped. Parameter values are quoted in the summary, and a string value is at
most 200 characters without control characters, so neither can pass itself off as more of the notification. An opaque
one may be up to 8192 characters, still without control characters (a CSR goes as one line of base64 DER), and is shown
as `sha256:<16 hex digits> (<n> characters)` in the summary and the log; the window shows it as opaque, with no field
to narrow it, and passes it back unchanged. A free argument of a call is never in the summary, whatever its
declaration: the consent covers the values the schema allows, and the window shows the asking call's values with the
same rules (a multiline one in a read-only text box). `lease` is the caller's proposal: `lock` or `PT<n>H` (`PT<n>M`
too), and `once` for a call; a `request` with `once` is refused, since its grant would end at once. A request or call
without one proposes `PT1H`.

What the sandbox can make the daemon spend is bounded: each socket has its own budget of 64 connections (watch streams
and spliced host socket connections counted per socket), so a full `request.sock` leaves `control.sock` to the window; a
client has 10 seconds to send a request of at most 1 MiB, enough for a call's free arguments; accept errors are waited
out rather than ending the socket; calls are limited as Running a call describes; instance globs are kept for five
seconds; and requests a grant already covers are answered one at a time per capability, without logging them.

A grant belongs to the sandbox. Every process in the sandbox runs as the same user in the same namespaces, so nothing
could keep one Claude session from another's grant: a folder is mounted in the mount namespace everyone shares, a host
socket sits in the grant directory everyone sees, and every session's MCP server offers every tool. A request or call
a live grant covers is answered without asking, from anywhere in the sandbox, and anything in the sandbox may release
any grant. The sandbox is one trust domain toward the broker.

### Consent

The daemon asks with a notification on the host (`org.freedesktop.Notifications` on the session bus). Its summary is
built by the daemon from the validated, resolved request ("Claude wants read-write access to
~/Workspace/agent/notes"), and the reason follows below it, quoted and marked as Claude's. The reason never stands
in for what's granted. Buttons: Allow (with the proposed lease, "Allow for 1 h"), Deny, and Options, which opens
the window on the request to pick another lease or, for a folder, narrow it (read-only instead of rw). A host command
grant has only its lease to change: its bounding values are what the call needs. A click on the body sends the action
`default`, which denies, as closing the notification does. It comes first in the list, since cosmic-notifications draws
no buttons and otherwise answers a body click with the first action; when `GetServerInformation` names that server and
a window is configured, `default` opens the window on the request instead, and the body says so.

A grant of a host command capability covers all its commands. The summary names the capability, its bounding values and
the lease ("Claude wants to control the Windows VM win11 for 1 hour"). The body starts with what that covers, for how
long and on which bounding values, before the reason: unrestricted free arguments first, each said to be
unrestricted, then the others with what their declaration allows, from the declaration's descriptions ("Covers, for
1 h, where the VM is "win11": Run PowerShell in the guest: any PowerShell, run as SYSTEM, unrestricted (exec). Click
at a position on the screen: column, in pixels, a number within 0–7679 (click). ..."). An enum of more than 8 values
reads as a count ("one of 161 values"); the window lists them in a grant's details. Leases read as "1 h 30 min". Summaries are one line and servers may cut them, so nothing the user
must see goes only there. A declaration with an undescribed free argument is a config error. The window shows the
same, with the call that asked.

The sandbox can post notifications too, through the notification portal (`org.freedesktop.portal.Notification`; the
proxy doesn't let it reach `org.freedesktop.Notifications`), with any title, body and buttons. A look-alike's
buttons only reach the sandbox, so it can't grant anything, but it can be timed to sit where the user is about to
click. The daemon ignores an action that arrives within a second of its notification appearing, and asks again. The
window turns Allow and Deny off for a second whenever another request takes a row's place: one moving up, one in
the place of one that ended ([A] turning [B]), or one where there was no row, as the sandbox can time when its
requests end and arrive. The portal keys notifications by app ID, so the sandbox can't replace or close the daemon's,
which the notification server itself would let anyone do by id (Plasma's does). The daemon guards against that
anyway: each of its buttons has a random action key, new for every notification, it counts only `ActionInvoked` and
`NotificationClosed` sent by the server's own connection (the current owner of its name), and an action key that
isn't one of its own is a deny.

Limits on asking:

- No answer in 2 minutes denies, and the notification is replaced by one without buttons. Once the user clicks
  Options, the window owns the request: the timeout pauses while it's open, for 10 minutes at most.
- One open request per capability; three refusals in a row stop requests for that capability for 2 minutes.

A live grant answers later requests with exactly the same parameters without asking, as does a standing grant
(below); a host command grant answers every call of its capability with the same bounding values. A read-only grant
never covers a read-write request, and a folder never covers its subfolders or parent.

The consent UI is only ever drawn on the host. Nothing the sandbox sends is shown other than as plain text.

## Leases and triggers

| lease      | ends when                                                                                   |
|------------|---------------------------------------------------------------------------------------------|
| `once`     | the call or request it was given for is answered; host commands only                           |
| `lock`     | the graphical session's `LockedHint` turns true, its `Lock` signal, or `PrepareForSleep`     |
| duration   | the time runs out; the window can extend it                                                 |
| `standing` | revoked in the window or released from inside; back when the daemon starts again; only from the config |

Every grant also ends on revoke in the window, on release from inside, when its instance goes away, and with the
sandbox. What a host command printed under it stays with the sandbox: a certificate is valid for the validity the
command was told, whenever the grant ends. A command issuing credentials should keep `maxValidity` short. The daemon
watches logind on the system bus from the host, where it has access. It runs in a user unit, outside any login session,
so `session/self` doesn't resolve for it, and logind sends no signals on that alias anyway: it reads the `Display`
property of `user/self` for the graphical session's object path and watches that one. It sets that watch up before it
serves requests, so a lock lease asked for right after it starts isn't refused for a watch still being set up. The
`Lock` signal, a request to lock, also ends `lock` leases.

Releasing voluntarily: the MCP server appends a line to its tool results listing the grants older than 15 minutes and
asking Claude to release what it no longer needs, at most every 10 minutes. By age, not idleness: the daemon can't
tell whether a folder or a host socket is still in use. Claude Code's channels could push this instead, but they need
`--channels` at startup, which the app doesn't pass.

## Standing grants

A launcher's `permissions.grants` lists grants the daemon makes whenever it starts, without asking: each a capability
and the values of its bounding arguments, of host commands, host sockets and D-Bus. Folders get none: what should always
be there is a bind, and the module asserts it. What stays granted is declared in Nix, reviewed with the rest of the
config, and taken away by a rebuild. One click in a dialog the sandbox brought up never widens access for good.

The module writes them into the daemon's config. At start the daemon checks them against the declarations: a
capability none has, a folder, bounding values it doesn't take or one listed twice is a config error, and the daemon
doesn't start. The module catches what it can at eval time. Then it grants each with lease `standing`, under the same
checks as a request: one whose instance isn't there (a VM not running yet) or another launcher holds is left out with
a warning, and a later request or call with exactly its bounding values gets it without asking. A host command's calls
under it are told `maxValidity`.

Revoke in the window, or a release, ends a standing grant for the daemon's life: later requests ask the user like any
other. The next start brings it back. The config is the only place they live, so there is no stored grant to forget.

The window lists them among the grants as "from config", with Revoke, and in its overview (below), each live or ended.

## MCP

`permissions-mcp` is an MCP server in the module's defaults when the broker is enabled. Its tools are fixed when it
starts, from the declarations the module writes into the store for it (`--commands`): the daemon's, without `run`,
which the sandbox has no use for. So it lists them before the daemon answers (the app starts its MCP servers at once)
and needs no `list` to do it; a call waits up to 30 seconds for `request.sock` to answer. The tools:

- `list`: what can be granted, with instances, and what's granted.
- `request(capability, params, reason, lease)`: blocks until the user answers, 2 minutes at most (10 with the window
  open), well inside Claude Code's MCP tool timeouts. Returns the grant, with the mount path under `/run/permissions`
  for a folder and the socket path for a host socket.
- `release(grant)`, `status`.
- `<capability>_<command>` for every declared host command, taking the capability's bounding arguments, the command's
  free ones, `reason` and `lease`. A call goes to the daemon as `call` and blocks like `request` when it has to ask.

Claude Code defers MCP tools behind its tool search, so a declared command costs a tool name until it's used. Its tool's
description says that a call may ask the user, and how its grant is scoped.

## Host commands planned

windows-vm, as a Nix module in secoya/agent-sandbox-plugins: `screenshot`, `click`, `keys` (an enum of key names),
`type` and `exec`, each one QMP or guest agent command on the VM given by `vm`, with the instance glob above. Raw QMP
never reaches the sandbox.

Designed for: SSH and Kubernetes certificates signed with fixed principals, certs from a host CA. Host sockets and D-Bus
rule sets cover systemd, the journal and BlueZ; host commands or device grants cover TPM operations and UEFI variables.
Host applications through AT-SPI need their own design: the accessibility bus is neither proxy's.

## Overview

The window shows what the sandbox reaches without asking, under "From the configuration", so the user sees the
whole of its access in one place. The module writes it into the daemon's config, derived from the launcher's
settings and nixpak's, and the daemon passes it on unchanged as `overview` in control.sock's `state`, next to
`standing` (the standing grants, each with its live grant or ended):

- `binds`: path, source, read-only or read-write, and whether it's skipped when the source is missing;
- `devices`: from `devices` and `kvm`, each bound if present;
- `dbus`: the proxy's policies and its call and broadcast rules;
- `network`: its own network namespace with a macvlan on the LAN, which the module always sets up;
- `implicit`: a few lines on what the module adds: the sockets (Wayland, and PipeWire and PulseAudio with `audio`),
  the GPU, what's bound read-only from the Nix store (the closure, `/run/current-system/sw`, `/etc` entries,
  `files`), `/tmp` with the scratchpad, and `/run/permissions`.

It carries no consent: nothing in it can be changed from the window. A config change and a rebuild change it.

## Launcher

`claude-desktop[-<name>] --permissions` opens the window. `claude-desktop.sh` handles it first, before it looks for a
running sandbox: otherwise it would hand the flag to the running app through nsenter, as it does with `claude://`
URLs. With no sandbox running, the window says so. The recent decisions it lists are the daemon's, kept in memory:
a daemon started again starts them afresh.

## Threat model

`models/` holds the Alloy model of the sandbox and the broker's protocol, and the stateful property tests run its
actions against the broker. The property tests follow the rewrite since step 3's first half (no sessions, host socket
requests, connections and revokes); the models still describe the first design (plugins, `service` units, session
leases) until step 3's second half adjusts them: host command calls, bounding values and instances, host socket connections, and the
D-Bus proxies' rule sets come in as those land.

## Steps

The first design's steps are built (Status). The rewrite's:

1. Declared host commands in the broker: the module's options, schema validation, consent per call or a covering grant,
   the stdin JSON, results, instances, static tools in the MCP server; the first design's `command` delivery folded in.
   Tests with revert checks for every validation, the stateful ones included.
2. Consent that names what's granted, in the notification and the window, and the window's redesign: each section and
   grant collapsible to one line (capability, bounding values, lease, time left), badges for the lease, "from config"
   and free arguments (a warning for unrestricted ones), all text selectable. Tests in qmltestrunner.
3. Remove what the rewrite replaces: per-grant service units, plugin tools and `list_changed`, plugin executables
   (folders built into the broker), session leases. Host sockets at stable addresses. Tests and models adjusted.
   Built but for the models.
4. windows-vm as declared host commands, in secoya/agent-sandbox-plugins.
5. The Go D-Bus proxy with static rules: the argv subset, SASL, fd passing, name tracking, replies, match rules.
   Tests against a real `dbus-daemon`, a revert check per rule kind, `-race`.
6. The sandbox on the new proxy: VM test that OpenURI, a portal notification and the tray still work, and a call
   outside the rules is refused.
7. Live rules: D-Bus capabilities as grants on the session proxy and the system-bus instance. Tests: a grant and a
   revoke applied to the next message.
8. Consumers: the home SSH and kubectl plugins ported to declared host commands; windows-vm's tools listed before any
   grant, a call asking once for the VM and later calls not, a revoke
   making the next call ask again; the portal, notifications and the tray still working.

## Decisions

Decided with Anders, 2026-11-02 and 2026-11-03:

1. The surface is static and authorization happens at call or connection time; enforcement lives only in the broker; on
   the host run only the broker and declared host commands; everything else runs inside over granted primitives.
2. Declared host commands replace the first design's `command` delivery and plugins' `service` backends, rather than
   signing and the like built into the broker.
3. A schema keeps a config tidy and guarantees nothing. The broker guarantees grants, bounding values, arguments as data
   and a consent that names free arguments, and doesn't pretend to more. "Nothing stays resident" is no requirement: it
   can't be enforced.
4. A grant names a capability and its bounding values, and covers all the capability's commands with any free
   arguments; a capability without bounding arguments is granted whole.
5. Arguments reach a script as JSON on stdin, with the validity and the bounding values; never argv, never a shell.
6. A command declares its result type, text or an image type; a non-zero exit is an MCP tool error with stderr.
7. Instances are a glob over paths; a list command waits until a command needs one.
8. A Go D-Bus proxy replaces xdg-dbus-proxy, nixpak's session-bus proxy included, swapped in so that nixpak keeps
   its launch sync and the `.flatpak-info` wrapper. (Agreed as "through `XDG_DBUS_PROXY_EXE`"; that variable turned
   out to be fixed at build time, see the decisions below.)
9. Session leases are dropped. They worked only with Claude Code starting the server, which the app doesn't do (What's
   verified, 6), and the session id they rest on is one anything in the sandbox can set. A duration does the job.
10. Grants die with the daemon: its call units are bound to its unit, its connections and live rule sets end with it,
    and its `ExecStopPost=` detaches the folder grants.
11. The window is Qt with QML in Go (miqt), after a PySide6 start whose closure came to 2.4 GB. miqt is young (v0.15,
    since 2024-08); the window uses only the QML engine and a property map.
12. The grant types are named for what's granted: `command` for host commands, `socket` for host sockets (the first
    design's `service`), `mount` (its `attach`), `dbus`; the options follow (`permissions.commands`,
    `permissions.sockets`).

## Decisions made without the user

Each can be revisited.

1. The grant directory is made shared in M1 on a `share` request from the FHS env's launcher script, before the FHS
   env's bwrap starts. The alternative, injecting into M2 directly, would need the daemon to find the app's mount
   namespace and wouldn't reach namespaces nested in it.
2. Revoking a mount grant detaches and reports the holders; ending them is the user's choice in the window.
3. Nudges ride on the MCP server's tool results, since channels aren't available to the app's sessions.
4. The daemon is a restartable user unit that finds the sandbox by app ID, rather than a child of the launcher with a
   pidfd handed over: a crash ends its grants, and started again it has its standing grants alone (Claude asks again for
   the rest).
5. Refining decision 4: bounding arguments are declared on the capability and free ones on the command, so one grant
   covers all of a capability's commands by construction. Per-argument marking on each command would allow commands of
   one capability to disagree on what bounds them.
6. A call proposes a `PT1H` lease unless it names one, and `once` exists for per-call consent: windows-vm makes many
   calls in a row, and Claude can ask for less.
7. A call runs as a transient user unit with a timeout, bound to the daemon's unit: the same cleanup as the old
   service units, a cgroup to kill on revoke, and nothing of the sandbox's environment.
8. A host socket is spliced by the broker at a stable address rather than created per grant: the address is fixed,
   the check happens at connect, a revoke closes the connections. It passes no file descriptors; a service that needs
   them is a host command or a D-Bus rule set instead.
9. A connection to a host socket without a grant is closed, not held while the user is asked: a connection carries
   no reason to show.
10. Folders become part of the broker when plugin executables go. They were the last plugin with commands on the host
    (`list`, `resolve`), and the ceiling was the broker's already.
11. The system bus gets a proxy instance with no rules at `/run/dbus/system_bus_socket`, so D-Bus capabilities on it
    need no restart and the address is where clients look. It reaches nothing until a grant adds rules.
12. A call's free arguments stay out of the notification's summary (they can be anything the schema allows); the
    consent states what the schema allows, and the window shows the values.
13. The new proxy reaches nixpak through the `pkgs` the module passes it, with `xdg-dbus-proxy` replaced. nixpak
    sets `XDG_DBUS_PROXY_EXE` to its own wrapper at build time (verified, 9), so pointing the variable elsewhere
    can't work, and a wrapper of our own would have to copy nixpak's `.flatpak-info` handling. The override keeps
    both of nixpak's.
14. The system-bus proxy is started by `bwrap-subid.sh`, like the broker, since nixpak's launcher starts only one
    proxy. It runs in a bwrap of its own: the system bus has no portals to read `/.flatpak-info`.
15. A D-Bus revoke closes the client connections that used the rule set, rather than only removing the rules: that
    is the one way to drop the names, match rules and exported objects the grant let a client set up.
16. A host socket of a D-Bus bus or of `$XDG_RUNTIME_DIR` as a whole is refused by the module: splicing hands over the
    broker's identity, which would get around the D-Bus proxies.
17. Every call is recorded with its arguments, the last 200 per grant: covered calls ran without anyone seeing them
    otherwise.
18. The MCP server reads the declarations from the store rather than asking the daemon, since the app starts it before
    the daemon may have found the sandbox. The rejected build-time copies were schemas routed to host backends; here
    the daemon still validates every call against its own config, made from the same Nix values.
19. The consent's scope goes in the notification body ahead of the reason, unrestricted arguments first, because
    servers may cut a long summary.
20. The broker sends a host command capability's scope as a list (`scope` in `state`) that its notification line is
    built from, rather than the window working it out from the declarations: one wording of what's covered, in both.
21. A waiting request doesn't collapse: it is the consent, and the user answers it with what it covers in view.
    Sections and grants do.
22. The call asking for a grant reaches the window with its free arguments whole (opaque ones by digest), unlike the
    call log's, cut at 200 characters: a script is read before it's allowed.
23. An enum of more than 8 values reads as a count in the consent: windows-vm's 161 key names would bury the rest of
    the notification. The window lists the values in a grant's details.
24. The folders capability keeps the id it had as a plugin's, `folders/folder`, so requests, tests and consumers that
    name it are unchanged. It is the one id with a `/`; declared capabilities can't take one.
25. A host socket is declared with either `path` or no path and one bounding argument with `instances`, whose glob
    matches are the sockets; the instance's value names its address, `sockets/<capability>/<value>`. One socket per
    instance leaves nothing else to bound, so no other bounding arguments. No `exclusive`: an SSH agent or a console
    can take clients from two launchers.
26. What host sockets are refused is a list of known buses and the launchers' own (Host sockets), checked on clean
    paths reached without links; a glob is refused when its `*` could fall within one of them, more than its matches
    would need, so that the module can check it on the literal string as the daemon does. The list guards against the
    known ones and doesn't claim more: the rest is the config's. An instance's value is its address's file name, which
    is bound through `/proc/self/fd/<fd>/`, so it may have 80 characters at most (an instances argument's `maxLength`
    is capped there), as may a host socket capability's name.
27. Every host socket address has a budget of its own, 64 connections like `request.sock`'s, so a full one leaves
    the others and `request.sock` alone. Past it a connection is closed at once.
28. The broker listens at a host socket's addresses from its start, at every grant of it and every 30 seconds (as it
    looks for instances), and stops listening at an instance's address once the glob no longer matches it. A
    connection's peer isn't checked: the address is only reachable from the sandbox and the host user.
29. A splice passes half-closes on: the host closing its end ends the sandbox's reading, and the other way round. A
    connection closed with bytes it hasn't read reaches the client as a reset rather than an end of file.
30. The broker binds an address and connects to a host socket through its directory's `/proc/self/fd` path, so
    neither is held to a socket path's 108 bytes.
31. With session leases gone, `release` ends the grant for the whole sandbox and `status` lists every live grant; a
    request without a lease proposes `PT1H`, as a call does. The nudge says what the sandbox, not the session, still
    holds.
