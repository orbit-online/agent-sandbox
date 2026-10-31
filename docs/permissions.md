# Permissions: granting the sandbox outside access while it runs

Status: design, nothing built yet. Written 2026-10-31.

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
- One plugin API with three delivery types (below). Folder mounts are the first plugin and live here; others, such
  as the Windows VM, live in orbit-online/agent-sandbox-plugins.
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
   propagation.
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
│  plugins, mount helpers      │  grant dir bind   │   <grant>/       (type C mounts)          │
│                              │                   │   <grant>.sock   (type A channels)        │
│ control.sock (host only) ◄───┼─ Permissions      │                                          │
│                              │  window           │ permissions MCP server (stdio, per session)│
└──────────────────────────────┘                   └──────────────────────────────────────────┘
```

- `permissions-broker`, Go, in `nix/packages/permissions-broker/`. One per launcher, started by `bwrap-subid.sh`
  next to subid-broker and ending with the sandbox the same way (parent death). It listens on:
  - `request.sock` in the grant directory, for the sandbox.
  - `control.sock` in the launcher's runtime directory on the host, mode 0600, never bound into the sandbox, for
    the window and the launcher.
- The grant directory: `$XDG_RUNTIME_DIR/claude-desktop[-<name>]/permissions/` on the host, bound at
  `/run/permissions` in the sandbox. This is the one bind the feature adds.
- `permissions-mcp`, the same binary as an MCP server, run inside the sandbox from the module's MCP servers. A client
  of `request.sock`.
- The Permissions window, a Qt 6 QML app (PySide6) talking to `control.sock`, opened by the desktop action
  "Permissions" (`claude-desktop[-<name>] --permissions`). Qt because it's native under Plasma; PySide6 because it's
  Qt's official binding, and Go has no Qt binding that is both maintained and standard. It is a client only: all
  state lives in the daemon.

### Handle on the sandbox

`bwrap-subid.sh` (`SUBID_MAP=subid`) reads the outer bwrap's `child-pid` from its info fd while bwrap waits on
`--userns-block-fd`, so the pid can't be reused yet. It starts the daemon with a pidfd for it on a fixed fd before
unblocking bwrap. From that pidfd the daemon finds M1 and its owner userns, and learns when the sandbox ends.

### Sharing the grant directory

The FHS env's bwrap copies M1 when it starts. Before it does, `bwrap-subid.sh` (`SUBID_MAP=parent`, inside M1)
sends `share` on `request.sock` and waits for the answer. The daemon checks that the client is in M1 and makes
`/run/permissions` shared there. In M1 that mount is a bind of the host directory, so it stays a slave of the host
too; files the daemon creates on the host side (sockets) show up as before. If `share` fails, the launcher goes on
without type C grants rather than not starting.

### Privileged steps in a Go process

Go processes are multithreaded from the start, and the kernel refuses to move a multithreaded process into another
user namespace (`setns` and `unshare` both fail with EINVAL). As subid-broker does, the daemon runs these steps as helpers of
its own binary through util-linux: `nsenter --user=<owner> -- unshare --mount --propagation unchanged --
permissions-broker clone-tree <src> [ro]` sends the detached tree's fd back over a socket pair, and `nsenter
--user=<owner> --mount=<m1> -- permissions-broker move-tree <dst>` attaches it.

## Delivery types

A plugin declares capabilities, each of one delivery type.

**A. Mediated channel.** The daemon creates `<grant>.sock` in the grant directory and starts the plugin's `serve`
command with the listening socket as fd 3 (`LISTEN_FDS=1`, as systemd socket activation does), in a process group of
its own. Revoking kills the group and removes the socket, which cuts live connections. Fits: Windows VM, systemd
(a filtered systemd1 proxy), BlueZ, TPM operations, UEFI variable reads, journal queries (the plugin runs the query
and streams it), D-Bus services (an xdg-dbus-proxy instance per grant, since rules can't change in a running one),
website logins (an HTTP proxy that adds cookies the sandbox never sees).

**B. Issued credential.** The daemon runs the plugin's `issue` command with the request's parameters (the sandbox's
public key or CSR among them) and the validity as JSON on stdin, and returns what it prints. The validity is capped
at the lease. A credential can't be taken back: revoke means "won't issue again". Fits: certs from a host CA, SSH
certificates, Kubernetes client certs.

**C. Namespace injection.** The daemon runs the plugin's `resolve` command, which answers with what to attach:
`{"source": "/host/path", "ro": true}` for a folder or a device node. The daemon validates it against the ceiling
and attaches it at `/run/permissions/<grant>`; the plugin never touches namespaces. Revoking detaches it. Grants are
sandbox-wide, so session ties are counted: the mount goes when the last session holding it ends. Fits: live folder
mounts, single `/dev` nodes, block devices mounted on the host and handed over as a folder. Moving a network device
(a wifi phy) into the sandbox's netns is also type C, with an attach kind of its own, left for later.

Open files survive a revoke of type C (verified item 3). On revoke the daemon detaches, then lists the processes in
the sandbox that still hold files or a cwd under the grant (`/proc/*/fd`, `/proc/*/cwd`); the window shows them and
offers to end them. It doesn't refuse a revoke because something is in use, and it doesn't kill anything without
the user saying so.

### Plugin manifest

A plugin is a package with `share/agent-sandbox/permissions/<plugin>.json`:

```json
{
  "name": "windows-vm",
  "capabilities": [
    {
      "name": "vm",
      "type": "A",
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
- `list` (optional) prints the grantable instances (running VMs, folder roots) for the window and the MCP `list`.
- `serve`, `issue`, `resolve` per type as above.
- `watch` (optional) runs for as long as a grant lives; its exit ends the grant (VM shut down, device unplugged). For
  type A, the `serve` process exiting does the same.
- `tools` (type A only): the plugin speaks MCP on its socket, and its tools appear in the core MCP server while the
  grant lives (see MCP).

The module's option `permissions.plugins.<name>` enables a plugin and sets its ceiling. The ceiling is
plugin-specific JSON the daemon passes to the plugin's commands and checks itself where it can (for folder mounts:
the path prefixes that may be granted and whether rw is allowed). A request outside the ceiling is refused without
asking the user.

## Requests

`request.sock` takes one JSON request per connection and answers with one JSON object, as windows-vm's broker does.

| op        | parameters                              | answer                                      |
|-----------|-----------------------------------------|---------------------------------------------|
| `list`    |                                         | capabilities and instances, with live grants |
| `request` | `capability`, `params`, `reason`, `lease` | the delivery: socket path, credential or mount path |
| `release` | `grant`                                 |                                             |
| `status`  |                                         | the caller's session's grants, idle times    |
| `watch`   |                                         | a stream of grant events, one JSON per line |
| `share`   |                                         | (from `bwrap-subid.sh` only, see above)     |

`reason` is required and goes into the notification as text (markup escaped, 300 characters). `lease` is the
caller's proposal: `session`, `lock`, `PT<n>H` or `always`.

The caller's session comes from its pidfd (`SO_PEERPIDFD`): the daemon walks its ancestors to the first with
`CLAUDE_CODE_SESSION_ID` in its environment, and takes that process's parent, the `claude` process, as the session's
anchor. A caller without one gets no session leases. Anything in the sandbox can set that variable, so session ties
serve leases and the window's bookkeeping. They don't authenticate a caller, and no grant relies on them for that.

### Consent

The daemon asks with a notification on the host (`notify-send` with actions, as windows-vm does): "Claude wants
<capability>: <reason>", buttons Allow (with the proposed lease, "Allow for 1 hour"), Deny and Options. Options
opens the window on the request, where the user picks another lease or narrows the parameters (read-only instead of
rw). Lifted from windows-vm:

- No answer in 2 minutes denies, and the notification is replaced by one without buttons.
- One open request per capability; three refusals in a row stop requests for that capability for 2 minutes.
- A grant with lease `always` skips the notification on later requests that match it.

The consent UI is only ever drawn on the host. Nothing the sandbox sends is shown other than as plain text.

## Leases and triggers

| lease     | ends when                                                                  |
|-----------|----------------------------------------------------------------------------|
| `session` | the session's anchor process exits (pidfd); type C counts holding sessions |
| `lock`    | the logind session's `LockedHint` turns true, or `PrepareForSleep`         |
| duration  | the time runs out; the window can extend it                                |
| `always`  | revoked in the window; replayed at every launch                            |

Every grant also ends on revoke in the window, on `release` from inside, on its plugin's `watch` or `serve` exiting,
and with the sandbox. The daemon watches logind on the system bus from the host, where it has access. `LockedHint`
is set by the screen locker; whether Plasma's does is to be checked in step 1, with the `Lock` signal (a request to
lock) as the fallback.

Releasing voluntarily: the core MCP server appends a line to every tool result listing the session's grants that
have been idle for more than 15 minutes (type A: no connection; type C: nothing open under it), asking Claude to
release what it no longer needs. Claude Code's channels could push this instead, but they need `--channels` at
startup, which the app doesn't pass.

## Grant store

`$stateDir/permissions.json` on the host, outside every bind, written only by the daemon. It holds `always` grants
(capability, parameters, when granted) and a log of recent decisions for the window. At launch, after `share`, the
daemon replays the `always` grants: type C mounts are attached, type A plugins started; type B is issued on request
without asking. Persisting a grant needs no config change or rebuild; Nix only sets what may be granted at all.

## MCP

`permissions-mcp` runs per Claude Code session (an MCP server in the module's defaults when the broker is
enabled). Tools:

- `list`: what can be granted, with instances, and what's granted.
- `request(capability, params, reason, lease)`: blocks until the user answers. Returns the socket path (A), the
  credential (B) or the path under `/run/permissions` (C).
- `release(grant)`, `status`.

Plugins with `tools`: while a grant of theirs lives, the core MCP server connects to the grant's socket as an MCP
client, lists its tools and offers them as `<plugin>_<tool>`, then sends `notifications/tools/list_changed`. When the
grant ends they're gone with another `list_changed`. It learns about grants through `watch`. So Claude only sees
tools it can use, and the plugin's MCP code runs on the host behind the socket, with nothing to install inside.

Fallback, if `list_changed` turns out not to work in the app: such a plugin also ships a stdio MCP server that is a
plain client of its socket, with no consent code, which answers ungranted calls with the `request` to make.

## Plugins planned

Built in, here: folder mounts (type C). Ceiling: path prefixes, rw allowed or not. `list` shows the prefixes.

In orbit-online/agent-sandbox-plugins: the Windows VM (type A, `tools`, `watch` on the VM's runtime directory). Its
consent code (notification, refusal limit, allow and revoke signals) goes away from secoya/nixos-windows-vm, and the
hosts drop the `windows-vm-claude` bind.

Designed for, not planned: certs from a host CA, SSH and Kubernetes certs (B); systemd, journal, BlueZ, TPM, UEFI
variables, host applications, website logins (A); devices and wifi (C).

## Steps

1. Daemon: request and control sockets, consent, refusal limit, leases with logind and session triggers, the grant
   store, plugin runner for A and B, `share`, tests in Go and in the VM test.
2. Permissions window and the desktop action.
3. Folder mounts as the first type C plugin, with the mount helpers, persisted grants and revoke reporting holders.
4. Windows VM plugin in agent-sandbox-plugins; consent code out of windows-vm.
5. Hosts switch over and drop the `windows-vm-claude` bind.

## Decisions made without the user

These were open when the design was written and decided while the user was away. Each can be revisited.

1. The grant directory is made shared in M1 on a `share` request from the FHS env's launcher script, before the FHS
   env's bwrap starts. The alternative, injecting into M2 directly, would need the daemon to find the app's mount
   namespace and wouldn't reach namespaces nested in it.
2. Revoking a type C grant detaches and reports the holders; ending them is the user's choice in the window.
3. The window is PySide6 with QML.
4. Plugins are executables with a JSON manifest, run per grant or per request, rather than long-running services
   with an RPC API: nothing to supervise when no grant is live, and socket activation for type A is a convention
   plugin authors know.
5. Nudges ride on the core MCP server's tool results, since channels aren't available to the app's sessions.
