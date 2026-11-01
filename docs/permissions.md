# Permissions: granting the sandbox outside access while it runs

Status: written 2026-10-31. Built: the daemon (`cmd/permissions-broker/`) with the service and command types, consent,
leases, the grant store, the MCP server with plugin tools and nudges, the Permissions window
(`nix/packages/permissions-window/`) and the attach type with the folders plugin (`nix/packages/permissions-folders/`,
`permissions.folders`), behind a launcher's `permissions.enable`. Not yet: device grants.

A daemon started again while the sandbox runs finds the grant directory shared by the one before (its mountinfo
says so) and replays the `always` folders into it.

## Why

Everything the sandbox can reach today is fixed when it starts: binds, devices, D-Bus rules, the network. Anything
else needs a config change, a rebuild and a restart, so access tends to get granted broadly and kept forever. Some
access is only needed for a task: a folder for an afternoon, a VM while it runs, a cert for an hour.

The permissions broker grants and revokes such access while the sandbox runs. The user answers each request in a
notification drawn on the host, picks how long it lasts, and sees and revokes live grants in a Permissions window.
What can be granted comes from plugins; the sandbox carries no plugin-specific code, and plugins carry no consent
code.

## Goal

- A host-side daemon per launcher, outside bwrap, owned by this repository.
- A notification for every request (reason, Allow, Deny, Options), and a Permissions window from the launcher's
  desktop actions, next to "New shell", listing what's granted and what can be.
- Leases: this session, until the screen locks, for a duration, always. Grants end on their lease, on revoke, on
  release from inside, and on plugin triggers.
- One plugin API with three delivery types, `service`, `command` and `attach` (below). Folder mounts are the first
  plugin and live here; others, such as the Windows VM, live in secoya/agent-sandbox-plugins.
- One MCP server inside the sandbox for every plugin.

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
   own.
7. xdg-dbus-proxy takes its rules from its arguments only; there is no way to change them while it runs.
8. Claude Code refreshes an MCP server's tool list on `notifications/tools/list_changed` in `-p` mode and in the
   Agent SDK, which the app uses (documented, not yet tested live).

## Components

```
host (user, no capabilities)                       sandbox
┌──────────────────────────────┐                   ┌──────────────────────────────────────────┐
│ permissions-broker (daemon)  │  request.sock     │ /run/permissions/                         │
│  consent, leases, grant store├──────────────────►│   request.sock   (core requests)          │
│  plugins, mount helpers      │  grant dir bind   │   <grant>/       (attach mounts)          │
│                              │                   │   <grant>.sock   (service sockets)        │
│ control.sock (host only) ◄───┼─ Permissions      │                                          │
│                              │  window           │ permissions MCP server (stdio, per session)│
└──────────────────────────────┘                   └──────────────────────────────────────────┘
```

- `permissions-broker`, Go, in `cmd/permissions-broker/`. One per launcher, as the transient user unit
  `claude-desktop[-<name>]-permissions.service` with `Restart=on-failure`, which `bwrap-subid.sh` starts with
  `systemd-run --user` before it execs bwrap. It listens on:
  - `request.sock` in the grant directory, for the sandbox.
  - `control.sock` in the launcher's runtime directory on the host, mode 0600, for the window and the launcher. It
    answers only peers in the daemon's own user namespace, so nothing in the sandbox can use it even if a ceiling
    exposes the path.
- The grant directory: `$XDG_RUNTIME_DIR/claude-desktop[-<name>]/permissions/` on the host, bound **read-only** at
  `/run/permissions` in the sandbox. This is the one bind the feature adds. Connecting to a socket on a read-only
  bind works; creating, renaming or replacing anything in it doesn't, so the sandbox can't plant a symlink where a
  mountpoint or socket will go, or remove `request.sock`. The daemon creates every entry on the host side, through a
  dirfd with `O_NOFOLLOW`, under names it picks at random, and refuses to start when the directory isn't its own
  or is a link.
- `permissions-mcp`, the same binary as an MCP server, run inside the sandbox from the module's MCP servers. A client
  of `request.sock`.
- The Permissions window, a Qt 6 QML app in Go (miqt's bindings) talking to `control.sock`, opened by the desktop
  action "Permissions" (`claude-desktop[-<name>] --permissions`). Qt because it's native under Plasma; Go like the
  rest. It is a client only: all state lives in the daemon. It refreshes on every watch event, which the sandbox can
  cause at will, so pending requests come in the order they arrived (a row doesn't move under the pointer) and what
  the user set on a row (narrowed parameters, a lease) is kept by request id through the refresh.

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
plugin units and exits. At first start it waits for the sandbox to appear and creates `request.sock` only then.

Started again after a crash, it finds the same sandbox the same way and reconciles before serving: it detaches
everything mounted under `/run/permissions` in M1, stops leftover `perm-*` units of its launcher, and replays only
the `always` grants. Leases that ran while it was down are gone rather than extended; Claude asks again.

Grants end with the daemon, a crash included: service units are bound to its unit (`BindsTo=`), so systemd stops them
when it stops or fails, and its unit's `ExecStopPost=` (`permissions-broker cleanup`, which systemd runs after a
crash too) detaches the folder grants and removes their mountpoints. Credentials a command printed stay valid until
they expire: they can't be taken back. A daemon starting runs the same cleanup first, in case it didn't happen.

### Sharing the grant directory

The FHS env's bwrap copies M1 when it starts. Before it does, `bwrap-subid.sh` (`SUBID_MAP=parent`, inside M1)
sends `share` on `request.sock` and waits for the answer (up to 10 s, for the daemon to come up). The daemon
checks that the client is in M1 and makes
`/run/permissions` shared there. In M1 that mount is a bind of the host directory, so it stays a slave of the host
too; files the daemon creates on the host side (sockets) show up as before. The daemon serves `share` once per sandbox: a
second one, from anything else in M1, would come after the FHS env's bwrap copied M1, where
grants no longer reach the app. Replaying makes no grant of what's live already. If `share` fails, the launcher goes
on without attach grants rather than not starting; the daemon then refuses attach requests and skips them when
replaying, and the window says why.

### Privileged steps in a Go process

Go processes are multithreaded from the start, and the kernel refuses to move a multithreaded process into another
user namespace (`setns` and `unshare` both fail with EINVAL). As subid-broker does, the daemon runs these steps as helpers of
its own binary through util-linux: `nsenter --user=<owner> -- permissions-broker clone-tree <src> [ro]` unshares
a mount namespace of its own, and sends the detached tree's fd back over a socket pair, and `nsenter --user=<owner>
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

## Delivery types

A plugin declares capabilities, each of one delivery type: `service`, `command` or `attach`.

**`service`: a host-side unit.** The daemon runs the plugin's `serve` command as a socket-activated transient unit:
`systemd-run --user --unit=perm-<launcher>_<grant> --socket-property=ListenStream=<grant dir>/<grant>.sock`
(`perm_<grant>` for the default launcher; launcher names can't contain `_`, so no launcher's units match another's
pattern). The plugin gets the socket the standard way (`sd_listen_fds`, which needs `LISTEN_PID` to match, so the
daemon can't hand the fd over itself). Revoking stops the unit, which kills its whole cgroup, double-forked children
included, and removes the socket (`RemoveOnStop`), which cuts live connections. After a crash the units are found by
name. `serve` exiting doesn't end the grant: the next connection starts it again. A plugin ends grants through
`watch`. Fits: Windows VM, systemd
(a filtered systemd1 proxy), BlueZ, TPM operations, UEFI variable reads, journal queries (the plugin runs the query
and streams it), D-Bus services (an xdg-dbus-proxy instance per grant, since rules can't change in a running one),
website logins (an HTTP proxy that adds cookies the sandbox never sees).

**`command`: run once on the host.** The daemon runs the plugin's `run` command with the request's parameters (the
sandbox's public key or CSR among them) and the validity as JSON on stdin, and returns what it prints. The validity
is the shorter of the plugin's `maxValidity` (from its ceiling) and a duration lease. The lease decides only whether
another `run` asks the user first. What a command printed can't be taken back: revoke means "won't run again". Fits:
credentials (certs from a host CA, SSH certificates, Kubernetes client certs) and host actions.

**`attach`: into the sandbox's namespaces.** The daemon runs the plugin's `resolve` command, which answers with what
to attach: `{"source": "/host/path", "ro": true}` for a folder or a device node. The daemon attaches it at
`/run/permissions/<grant>`; the plugin never touches namespaces. The daemon, not the plugin, enforces the source
ceiling (below), the same way for every attach plugin. Revoking detaches it. Like every grant
it is the sandbox's (see Requests): a session lease's mount goes when the last session holding it ends. Fits: live folder
mounts, single `/dev` nodes, block devices mounted on the host and handed over as a folder. Moving a network device
(a wifi phy) into the sandbox's netns is also `attach`, with an attach kind of its own, left for later.

Open files survive a revoke of an attach grant (verified item 3), and so does a copy of the mount a process in the
sandbox made in a mount namespace of its own (`unshare -Urm`, `mount --rbind`): the detach and the removal of the
mountpoint end the grant's mounts in every namespace it propagated to, not copies made elsewhere. Neither can be
taken back short of ending the processes. So the daemon reads the grant's mount ids in each mount namespace in the
sandbox (of every process of the sandbox's, found by user namespace as for sessions below, re-entries included),
detaches, and then lists the holders, within ten seconds: processes with a thread whose working directory, root or
open files are on those mounts, or with mappings there (by `statx`'s mount id, which an open file keeps), and
processes with a thread whose mount namespace has a mount of the grant's filesystem and root. Every thread counts:
one can have a working directory, file table and mount namespace of its own (`unshare` with `CLONE_FS`,
`CLONE_FILES` or `CLONE_NEWNS`). It does so however the grant ended (revoked, released from
inside, its lease run out) and keeps the last twenty grants' holders for the window, which shows them and offers to
end them: `SIGTERM` through a pidfd, only for processes in the sandbox, and only to the process recorded (by its start
time), not to a later one that got its pid. The daemon doesn't refuse a revoke because something is in
use, and doesn't kill anything without the user saying so.

Finding holders is best effort. A file descriptor can stay open where `/proc` shows no process holding it: in flight
in an `SCM_RIGHTS` message queued on a socket nobody reads yet, or registered with an io_uring as a fixed file. Either
keeps a grant that ended readable (and writable, for a read-write one) through that descriptor, for as long as the
sandbox likes, and the window lists nobody to end. Only ending the sandbox ends every access to a grant for sure.

### Source ceiling and resolving paths

The sandbox has rw binds of its own, which may lie under a ceiling root, and there it can plant links and rename
directories at will. So a path check followed by a mount of the path isn't enough. The daemon checks the path
lexically first, refusing early what no ceiling source covers (the longest matching source decides whether rw is
allowed). Then the clone helper, after its `unshare`:

- opens the ceiling root without following any link (`openat2(RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)`): a root
  swapped for a link to elsewhere fails;
- opens the requested path beneath it without following links or crossing mounts
  (`RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV`);
- refuses the source if it, or a directory between it and the root, is a denied directory, or if a denied directory
  lies beneath it, by device and inode, so no other path to a denied directory (a link, a bind mount, the host's
  own links) gets around the list;
- clones that one mount without its submounts (no `AT_RECURSIVE`): in the helper's namespace every mount is locked,
  so a source with mounts beneath it fails instead of bringing them along unchecked;
- mounts it read-only if asked, and a directory always `nodev` and `nosuid`.

The path shown to the user is the one resolved, read back from the fd. What's mounted is the folder the user was
asked about: the daemon opens the source the way the clone helper does before asking (or when the window narrows the
request, as the user answers) and records its device and inode, and the helper refuses a source that isn't that file
any more. So the sandbox renaming another directory under the ceiling into the path between the question and the
mount gets an error, not the other directory. An `always` grant is of the path: replayed at a later launch, or matched
by a later request, it mounts whatever is at the path then, within the ceiling and outside the denied list.

Never grantable, whatever a ceiling says: every launcher's state directory (the grant store) and
`$XDG_RUNTIME_DIR` (the control sockets and every launcher's grant directory). A grant there would let the sandbox
approve its own requests. The daemon refuses to start when one of them expands to an empty or relative path.
A ceiling over `$HOME` or `~/.config`, rw, would hand the sandbox code execution on the host (user units, autostart):
that's the ceiling's choice, and one to avoid.

### Plugin manifest

A plugin is a package with `share/agent-sandbox/permissions/<plugin>.json`:

```json
{
  "name": "windows-vm",
  "capabilities": [
    {
      "name": "vm",
      "type": "service",
      "description": "Control a running Windows VM",
      "params": { "vm": { "type": "string", "description": "the VM, as list names it" } },
      "list": ["windows-vm-plugin", "list"],
      "serve": ["windows-vm-plugin", "serve"],
      "tools": true
    }
  ]
}
```

- `params` is a JSON Schema properties object; the daemon validates requests against it.
- `list` (optional) prints the grantable instances (running VMs, folder roots) for the window and the MCP `list`, as
  a JSON array of objects. Outside `attach`, a request must match one of them, or it is refused without asking the
  user: an instance matches when each of its keys has the same value in the request's params. A `list` that fails
  refuses every request. `list` runs again when the user answers and when an `always` grant is replayed, so an
  instance gone by then (a VM shut down) isn't granted. Attach requests may name a folder below a listed root, so
  `sources` decide there.
- `exclusive` (optional): an instance may be granted to one launcher at a time (a VM's QMP connection takes one
  client). The daemons share lock files in `$XDG_RUNTIME_DIR/agent-sandbox-permissions/`, one per instance `list`
  prints that the request matches (per parameters without a `list`), so parameters `list` doesn't print (a mode) don't
  make one VM two instances; a request for an instance
  another launcher holds is refused, naming it.
- `serve`, `run`, `resolve` per type as above.
- `watch` (optional) runs for as long as a grant lives; its exit ends the grant (VM shut down, device unplugged).
- `tools` (`service` only): the plugin speaks MCP on its socket, and its tools appear in the core MCP server while the
  grant lives (see MCP).

The module's option `permissions.plugins.<name>` enables a plugin and sets its ceiling. The ceiling is
plugin-specific JSON the daemon passes to the plugin's commands, plus fields the daemon enforces itself: `sources`
(path prefixes, devices, rw allowed or not) for `attach` and `maxValidity` for `command`. A request outside the ceiling
is refused without asking the user.

## Requests

`request.sock` takes one JSON request per connection and answers with one JSON object, as windows-vm's broker does.

| op        | parameters                              | answer                                      |
|-----------|-----------------------------------------|---------------------------------------------|
| `list`    |                                         | capabilities and instances, with live grants |
| `request` | `capability`, `params`, `reason`, `lease` | the delivery: socket path, credential or mount path |
| `release` | `grant`                                 | drops the caller's session's hold; ends the grant once nobody holds it |
| `status`  |                                         | the grants the caller's session holds        |
| `watch`   |                                         | a stream of grant events, one JSON per line |
| `share`   |                                         | (from `bwrap-subid.sh` only, see above)     |

`reason` is required and goes into the notification as text: whitespace and control characters folded to single
spaces, 300 characters, quoted, markup escaped. Parameter values are quoted in the summary, and a string value is at
most 200 characters without control characters, so neither can pass itself off as more of the notification.

What the sandbox can make the daemon spend is bounded: each socket has its own budget of 64 connections (watch
streams included), so a full `request.sock` leaves `control.sock` to the window; a client has 10 seconds to send a
request of at most 64 KiB; accept errors are waited out rather than ending the socket; at most four `run` and
`resolve` commands run at once, one per capability, so a capability whose commands hang holds up only its own
requests; `list` runs one per capability, outside those four, so the window's state isn't held up by them, and its
output is kept for five seconds; and requests a grant already covers are answered one at a time
per capability, without logging them. `lease` is the
caller's proposal: `session`, `lock`, `PT<n>H` or `always`.

The caller's session comes from its pidfd (`SO_PEERPIDFD`): the daemon walks its ancestors to the first with
`CLAUDE_CODE_SESSION_ID` in its environment, and takes that process's parent as the session's anchor if it is the
Claude Code binary (by `/proc/<pid>/exe`), in the sandbox and not a pid namespace's init. The walk never leaves the
sandbox: a process is the sandbox's when its user namespace (or the one owning its mount namespace) is the sandbox's
or below it. That counts re-entries (`claude-desktop --shell`), which nsenter starts from the host, and stops their
walk at nsenter rather than at a host shell that may carry a host Claude Code session's variable. A caller without
such an anchor gets no session leases.

A grant belongs to the sandbox, not to the session that asked for it. Every process in the sandbox runs as the same
user in the same namespaces, so nothing could keep one session from another's grant: any process in the sandbox can
use any live grant (a folder is mounted in the mount namespace everyone shares, a service's socket sits in the grant
directory everyone sees, a credential is a string), and every session's MCP server offers every grant's tools. The
session id only ties a "this session" lease's lifetime to that session's `claude` process, and records who still
holds a grant for `release` and the nudge. Anything in the sandbox can set the variable; nothing relies on it to
authenticate a caller. A request a live grant covers is answered without asking, from any session: a Claude Code
subagent runs in its parent's `claude` process with the parent's session id, and a new Claude session in the app
gets what the sandbox already has. The notification and the window say "until this Claude session ends", at most
until the app quits.

### Consent

The daemon asks with a notification on the host (`org.freedesktop.Notifications` on the session bus). Its summary is
built by the daemon from the validated, resolved request ("Claude wants read-write access to
~/Workspace/agent/notes"), and the reason follows below it, quoted and marked as Claude's. The reason never stands
in for what's granted. Buttons: Allow (with the proposed lease, "Allow for 1 hour"), Deny, and Options, which opens
the window on the request to pick another lease or narrow it (read-only instead of rw). `always` is offered only in
the window, never as a notification button.

The sandbox can post notifications too (its D-Bus policy talks to `org.freedesktop.Notifications`), with any app
name, icon and buttons. A look-alike's buttons only reach the sandbox, so it can't grant anything, but it can be
timed to sit where the user is about to click. The daemon ignores an action that arrives within a second of its
notification appearing, and asks again. The notification server also lets anyone replace a notification by its id
(Plasma's does), and ids are counted up, so the sandbox can swap the daemon's notification for one with its own text
and buttons. It can't make a click grant anything: each of the daemon's buttons has a random action key, new for every
notification, the daemon counts only `ActionInvoked` and `NotificationClosed` sent by the server's own connection (the
current owner of its name), and an action key that isn't one of its own is a deny.

Lifted from windows-vm:

- No answer in 2 minutes denies, and the notification is replaced by one without buttons. Once the user clicks
  Options, the window owns the request: the timeout pauses while it's open, for 10 minutes at most.
- One open request per capability; three refusals in a row stop requests for that capability for 2 minutes.

A grant with lease `always` skips the notification on later requests with exactly the same parameters. A read-only
grant never covers a read-write request, and a folder never covers its subfolders or parent.

The consent UI is only ever drawn on the host. Nothing the sandbox sends is shown other than as plain text.

## Leases and triggers

| lease     | ends when                                                                  |
|-----------|----------------------------------------------------------------------------|
| `session` | the session's anchor process exits (pidfd); attach counts holding sessions |
| `lock`    | the graphical session's `LockedHint` turns true, its `Lock` signal, or `PrepareForSleep` |
| duration  | the time runs out; the window can extend it                                |
| `always`  | revoked (or forgotten) in the window, which removes it from the store too; replayed at every launch |

Every grant also ends on revoke in the window, on its plugin's `watch` or `serve` exiting, and with the sandbox.
`release` from inside drops only the releasing session's hold: the daemon records every session a grant was given to
(asked for it, or covered by it), whatever its lease, and the grant ends on release once none of them holds it. So one
session releasing a grant, after the nudge below say, doesn't cut off another that's using it. A caller without a
session (nothing found above it) ends the grant on release: that only takes access away. The lease's own end (time,
lock, the session lease's last anchor), revoke and the plugin's triggers end it for everyone. An `always` grant ended
by release is replayed at the next launch; only revoke and forget remove it from the store. The daemon watches logind on the system bus from the host, where it has access. It runs in a
user unit, outside any login session, so `session/self` doesn't resolve for it, and logind sends no signals on that
alias anyway: it reads the `Display` property of `user/self` for the graphical session's object path and watches that
one. `LockedHint` is set by the screen locker (whether Plasma's does is to be checked in step 1); the `Lock` signal,
a request to lock, also ends `lock` leases.

Releasing voluntarily: once a session has held grants for 15 minutes, the core MCP server appends a line to its
tool results listing them and asking Claude to release what it no longer needs, at most every 10 minutes. By age,
not idleness: the daemon can't tell whether a socket-activated plugin's socket or a folder is still in use. Claude
Code's channels could push this instead, but they need `--channels` at startup, which the app doesn't pass.

## Grant store

`$stateDir/permissions.json` on the host, outside every bind, written only by the daemon, one save at a time,
synced before the rename that replaces it. A store that doesn't parse is set aside as `permissions.json.broken`, and
the daemon starts without it. It holds `always` grants
(capability, parameters, when granted) and a log of recent decisions for the window. At launch, after `share`, the
daemon replays the `always` grants: attach grants are mounted, service plugins started; a command runs on request
without asking. Persisting a grant needs no config change or rebuild; Nix only sets what may be granted at all.

## MCP

`permissions-mcp` runs per Claude Code session (an MCP server in the module's defaults when the broker is
enabled). Tools:

- `list`: what can be granted, with instances, and what's granted.
- `request(capability, params, reason, lease)`: blocks until the user answers, 2 minutes at most (10 with the
  window open), well inside Claude Code's MCP tool timeouts (about 28 hours, 30 minutes idle for stdio servers).
  Returns the socket path (service), the command's output (command) or the path under `/run/permissions` (attach).
- `release(grant)`, `status`.

Plugins with `tools`: while a grant of theirs lives, the core MCP server connects to the grant's socket as an MCP
client, lists its tools and offers them as `<plugin>_<tool>` (a second grant of the plugin, a second VM, adds its
grant's id), then sends `notifications/tools/list_changed`. When the grant ends they're gone with another
`list_changed`. It learns about grants through `watch` and syncs every 30 seconds besides, and each call is a session
of its own with the plugin, which socket activation may have started anew. Offering a grant's tools runs on its own,
with a 10-second deadline, since socket activation accepts a connection whether or not the plugin answers: a plugin
that hangs holds up nothing else, and its grant is tried again. Tools without an object schema are left out; two of a
grant's tools that come out under one name (`a.b`, `a_b`) are told apart by the grant's id. So Claude only sees tools
it can use, and the plugin's MCP code runs on the host behind the socket, with nothing to install inside.

Grants, and so their tools, are the sandbox's, not a session's: every session's MCP server offers them, and any
process in the sandbox may release any grant it can name (for its own session's hold, or outright without a session).
The sandbox is one trust domain; session ties only decide when session leases end, and who still holds a grant.

Fallback, if `list_changed` turns out not to work in the app: such a plugin also ships a stdio MCP server that is a
plain client of its socket, with no consent code, which answers ungranted calls with the `request` to make.

## Plugins planned

Built in, here: folder mounts (`attach`). Ceiling: path prefixes, rw allowed or not. `list` shows the prefixes.

In secoya/agent-sandbox-plugins: the Windows VM (`service`, `tools`, `watch` on the VM's runtime directory). Its
consent code (notification, refusal limit, allow and revoke signals) goes away from secoya/nixos-windows-vm, and the
hosts drop the `windows-vm-claude` bind.

Designed for, not planned: certs from a host CA, SSH and Kubernetes certs (`command`); systemd, journal, BlueZ, TPM,
UEFI variables, host applications, website logins (`service`); devices and wifi (`attach`).

## Launcher

`claude-desktop[-<name>] --permissions` opens the window. `claude-desktop.sh` handles it first, before it looks for a
running sandbox: otherwise it would hand the flag to the running app through nsenter, as it does with `claude://`
URLs. With no sandbox running, the window says so and shows the stored `always` grants.

## Steps

1. Daemon: request and control sockets, consent, refusal limit, leases with logind and session triggers, the grant
   store, plugin runner for `service` and `command`, `share`, tests in Go and in the VM test.
2. Permissions window and the desktop action.
3. Folder mounts as the first attach plugin, with the mount helpers, persisted grants and revoke reporting holders.
4. Windows VM plugin in agent-sandbox-plugins; consent code out of windows-vm.
5. Hosts switch over and drop the `windows-vm-claude` bind.

## Decisions made without the user

These were open when the design was written and decided while the user was away. Each can be revisited.

1. The grant directory is made shared in M1 on a `share` request from the FHS env's launcher script, before the FHS
   env's bwrap starts. The alternative, injecting into M2 directly, would need the daemon to find the app's mount
   namespace and wouldn't reach namespaces nested in it.
2. Revoking an attach grant detaches and reports the holders; ending them is the user's choice in the window.
3. The window is Qt with QML: first PySide6, then ported to Go with miqt at Anders' word (one language, and the
   PySide6 closure came to 2.4 GB). miqt is young (v0.15, since 2024-08); the window uses only the QML engine
   and a property map.
4. Plugins are executables with a JSON manifest, run per grant or per request, rather than long-running services
   with an RPC API: nothing to supervise when no grant is live, and socket activation for `service` is a convention
   plugin authors know.
5. Nudges ride on the core MCP server's tool results, since channels aren't available to the app's sessions.
6. The daemon is a restartable user unit that finds the sandbox by app ID, rather than a child of the launcher with
   a pidfd handed over: a crash ends its grants (bound units, `ExecStopPost`), and started again it replays the
   `always` ones (Claude asks again for the rest).
7. Service plugins run as socket-activated transient user units: real socket activation and a cgroup to kill.
8. Grants die with the daemon (Anders): service units `BindsTo=` its unit, folder grants detached by its
   `ExecStopPost=`.
