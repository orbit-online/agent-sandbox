# Threat model of the sandbox

[Alloy 6](https://alloytools.org/) models of the Claude Desktop sandbox
and its permissions broker. This file is the inventory they start from:
who runs where, what crosses the sandbox's boundary and how each crossing
checks its peer, what the attacker can do, and the properties the models
check. Properties are numbered (S for structure, P for the broker's
protocol, L for the launch path, D for the D-Bus proxy) so model files, Go tests and commit
messages can cite them.

Sources, as of main 491eb09 (the broker's protocol as of acbceda):
`docs/permissions.md`, the namespace diagram at the top of
`nix/home/claude-desktop/default.nix`, the module's scripts, and the Go
in `cmd/`. Where the docs and the code disagree, the
inventory follows the code and says so.

## Running

```bash
models/check
```

Runs every model with a command and prints `ok`, `known` or `FAIL` per
command; works from any directory. A check holds when Alloy finds no
counterexample within its scope. A check with `expect 1` is a known
finding: it has a counterexample, and `check` prints `known`. A known
finding whose counterexample goes away is a `FAIL`, so its `expect 1`
can't go stale. The comment right above each command says which claim it
encodes, with its number from this file. Without `alloy6` and `jq` on
`PATH`, `check` re-runs itself in `nix shell nixpkgs#alloy6 nixpkgs#jq`.

```bash
models/check -v sandbox   # one model, every command's claim and instance
models/check --known      # the known findings and their claims
nix run nixpkgs#alloy6    # the GUI, to draw an instance
```

## Principals

Host side, trusted. All run as the host user (uid 1000 in the diagram)
in the init namespaces unless noted.

1. **Host user**: the terminal, the desktop, a host Claude Code session.
   Launches the sandbox and answers consent.
2. **permissions-broker daemon**: one per launcher, the transient user
   unit `claude-desktop[-<name>]-permissions.service`
   (`Restart=on-failure` up to 3 starts in 10 minutes,
   `ExecStopPost=permissions-broker cleanup`). Listens on `request.sock`
   and `control.sock` and at the host sockets' addresses, runs host
   command calls, grants the config's standing grants at start. Its
   helpers (`make-shared`, `clone-tree`, `move-tree`, `detach`) run
   through `nsenter` in the user namespace that owns M1, with every
   capability there, exec'd on the host's mounts; all but `clone-tree`
   then join M1 on a thread of their own and resolve only the grant
   directory there.
3. **Permissions window**: Qt app, a client of `control.sock`. Answers
   pending requests, revokes, ends holders.
4. **Notification daemon** (Plasma's): draws the consent notification the
   broker posts over D-Bus (godbus) and signals the action. The sandbox
   talks to it too.
5. **xdg-dbus-proxy**: nixpak's, in a plain bwrap; filters the session bus
   for the sandbox, by call rules only (no `talk`, which reaches every
   object the name's owner exports): OpenURI, Settings and Notification
   on the portal (the app's notifications go through it: libnotify with
   `NOTIFY_FORCE_PORTAL`, the app's own backend patched out), with the
   tray `RegisterStatusNotifierItem` and `Properties.Get` on
   `/StatusNotifierWatcher` and one StatusNotifierItem name to own. Not
   `org.freedesktop.Notifications`. A call to an owner's unique name
   is checked against the rules of every name it holds. Its rules are
   fixed at start.
6. **Launcher**: `claude-desktop.sh`, nixpak's launcher, `bwrap-subid.sh`
   (`SUBID_MAP=subid` on the host), `net-setup.sh` in nixpak's pasta slot,
   the GTK theme scripts, `store-sync.sh`. What they do in the sandbox's
   home and store runs confined (`confine.sh` and `state.sh`: a bwrap with
   only its closure and those directories). Re-entries (`claude://`,
   `--shell`) and `--permissions` go through it.
7. **subid-broker**: started by `bwrap-subid.sh`, dies with bwrap
   (`PR_SET_PDEATHSIG`, and at once if the shell that started it is gone
   by then). Writes uid and gid maps for user namespaces in
   the sandbox, on `/run/subid-broker.sock`.
8. **netns-macvlan**: setcap `cap_net_admin` wrapper, group `users`.
   Creates `eth0` in the sandbox's netns.
9. **Call units**: `perm[-<launcher>]_call-<id>`, one transient user
   unit per host command call (`systemd-run --pipe`), `BindsTo=` the
   daemon's unit, `RuntimeMaxSec=` the command's timeout; runs the
   command the config declares with the call on stdin. The instances
   globs are read by the daemon itself.
10. **Host targets**: what host commands and host sockets reach (a VM, a
    host socket's server), reached only through a call unit or a
    connection the daemon splices.

Sandbox side, the attacker (see Attacker). Uid 1000 (kuid) unless noted.

11. **bwrap's init and the FHS env script**: in U1, N, M1, P, without
    capabilities. The script runs `bwrap-subid.sh` with `SUBID_MAP=parent`
    and sends `share`.
12. **udhcpc** and its event script: in U1, N, P with `net_admin` and
    `net_raw` only (inheritable, ambient and bounding sets), in MU: a
    mount namespace made from the host's and pivoted to a tmpfs with its
    closure read-only, P's `/proc` and the sandbox's home
    (`dhcp-root.sh`). Parses DHCP packets from the LAN, so counts as the
    attacker's.
13. **The app** (Claude Desktop): in U2, N, M2, P2 at pid `APP_PID`.
14. **Claude Code sessions** and what they spawn: shells, the local MCP
    servers, `permissions-broker mcp` (the `permissions` MCP server, a
    client of `request.sock`), anything Claude runs.
15. **Nested**: anything the above start in user, mount, pid or network
    namespaces of their own (`unshare -Urm`, bwrap, rootless containers),
    with maps from subid-broker.
16. **Re-entries**: `claude://` (`/init`) and `--shell`, both under
    `setpriv --no-new-privs` set on the host, joined into the app's
    namespaces by `nsenter` from the host. Inside once joined, but their
    parent is a host process.

## Namespaces

| ns | kind | owner userns | created by | who has capabilities over it |
|---|---|---|---|---|
| init | all | - | kernel | host root; the host user over nothing of the init namespaces |
| U1 | user | init, owner uid 1000 | nixpak's bwrap (`--unshare-user`, maps by subid) | every host process of uid 1000 (owner rule); bwrap's setup before it drops them; udhcpc (net_admin, net_raw); the broker's helpers after `nsenter --user` |
| N | net | U1 | nixpak's bwrap | as U1; netns-macvlan adds `eth0` from init with `cap_net_admin` there |
| M1 | mnt | U1 | nixpak's bwrap | as U1 |
| MU | mnt | U1 | net-setup's `unshare --mount`, from the host's mounts | as U1 |
| P | pid | U1 | nixpak's bwrap | as U1; bwrap's init is pid 1 here, the broker's `sandbox.pid` |
| ipc, uts, cgroup | | U1 | nixpak's bwrap | as U1 |
| U2 | user | U1, owner uid 1000 | the FHS env's bwrap (identity map of U1's ids) | every process of uid 1000 in U1 or init (owner rule); app-pid.sh with CAP_CHECKPOINT_RESTORE until it drops it |
| M2 | mnt | U2 | the FHS env's bwrap; copy of M1, `/run/permissions` a slave of M1's | as U2 |
| P2 | pid | U2 | the FHS env's bwrap | as U2 |
| U3... | user | U2 or below, owner the creator's euid | the sandbox (`unshare`, bwrap, podman) | the sandbox, fully: it is their owner |

U1 maps inner 0-999 and 1001-65535 to the user's `/etc/subuid` range and
1000 to 1000; gids likewise with 100. U2 maps all of U1's ids as
themselves. The time namespace stays the host's (the re-entries skip it:
joining needs CAP_SYS_ADMIN in init).

## Crossings and peer checks

| crossing | listener / actor | reachable from | checks |
|---|---|---|---|
| `request.sock` (`/run/permissions`, ro bind of `$XDG_RUNTIME_DIR/claude-desktop/permissions[-<name>]`) | broker | M1, M2 and copies; the host | `SO_PEERPIDFD`, pid from fdinfo, peer alive after the read; 64 connections, 10 s, 1 MiB; `share` only from M1 (`sameNsAs` by pid); a call's arguments against the command's schema before asking |
| `control.sock` (`$XDG_RUNTIME_DIR/claude-desktop/permissions[-<name>]-control.sock`, 0600, not bound) | broker | host only, unless a bind or ceiling exposes it | `SO_PEERPIDFD`; same user namespace as the daemon, except `watch`, which both sockets serve before the op dispatch |
| host socket addresses (`/run/permissions/sockets/<capability>[/<instance>]`) | broker, from its start or the instance's appearance | M1, M2 and copies | none of the peer: a grant is the sandbox's. Spliced to the host socket only while a live grant of that capability and instance covers it, closed at once otherwise and when the grant ends; bytes only, no fds; 64 connections per address |
| `/run/subid-broker.sock` | subid-broker | M1, M2 and copies | `SO_PEERCRED` uid and `SO_PEERPIDFD`; client's and target's `/proc` entries owned by that uid, checked against their pidfds; client not in the broker's userns; target's parent userns the client's or below; the kernel then checks the map against the parent |
| netns-macvlan `<pid>` | netns-macvlan | the host (setcap; under bwrap's no_new_privs file caps don't apply) | `/proc/<pid>` owned by the caller, by pidfd; netns not the caller's; its owner userns below the caller's, and the one right below the caller's on the way up owned by the caller's uid |
| `nixpak-bus` | xdg-dbus-proxy | M1, M2 | the proxy's fixed rules |
| notifications | notification daemon; the broker talks to it over godbus | host and sandbox (through the proxy) | each button's action key is random per notification, so a look-alike's or a replaced notification's buttons aren't the broker's (a click there denies); `ActionInvoked` and `NotificationClosed` count only from the current owner of `org.freedesktop.Notifications`; an action within 1 s of the notification appearing is ignored and the question asked again. The sandbox posts look-alikes through the portal, which keys them by app ID: it can't replace or close the broker's |
| `bwrapinfo.json`, `info` under `$XDG_RUNTIME_DIR/.flatpak/` | read by broker and launcher | host only (not bound) | child-pid's mount ns differs from the reader's; pidfd taken, file re-read |
| grant directory entries | broker creates on the host | sandbox reads through the ro bind | `O_NOFOLLOW` dirfd, random names; daemon refuses a grant dir that isn't its own directory; in M1 the helpers open it with `RESOLVE_NO_SYMLINKS`, check it's the host's directory (device and inode) and a mount root, and act on single entries beneath it |
| attach mounts | broker's helpers | appear in M1, propagate to M2 and slaves | source ceiling and denied directories (lexical, then `openat2` without links or mount crossings beneath the root), no submounts, ro/nodev/nosuid |
| the daemon's config (ceilings, standing grants) | the Home Manager module, a read-only path in the host's Nix store | host only (the host's store isn't bound) | nothing writes it at runtime; what the user ends lives in the daemon's memory |
| helper binaries | nsenter, setpriv, the launcher's scripts | resolved on the host's mounts, or in MU's closure binds | never in M1 or M2, where the sandbox can swap a directory (S12) |
| the app's pid (`app-pid.sh`) | FHS env's init with CAP_CHECKPOINT_RESTORE | P2 | dropped before the app's fork, or before its exec when the pid can't be set |
| the sandbox's home, store and the binds of `~/.claude` and `~/.config/Claude` | the launcher writes (config merge, `user-dirs.dirs`, `resolv.conf`, the GTK keyfile while it runs, the store sync) | the sandbox writes them, links included | `state.sh` in a bwrap holding only its closure and those directories; files replaced by rename; a store dir that's a link stops the launch |
| `/nix/store` where the sandbox runs | a mount of its own, the closure's ro binds on it | the sandbox writes beside the binds, and can rename it from a nested namespace | nothing host-side resolves a path there; a store dir other than the one the launch recorded (`store-sync.sh`, by device and inode), or no record, and `nix/` is deleted and the closure synced into a fresh one |

## Trust boundaries

- B1: host processes | everything in U1 and below. Crossed by the sockets
  above, binds, D-Bus through the proxy, the macvlan, and the host's own
  `nsenter`s (net-setup, the broker's helpers, re-entries).
- B2: U1 | U2. U1 holds the capabilities over N, M1, P; nothing in U2 has
  any there. Crossed by the FHS env's start and the propagation of
  `/run/permissions`.
- B3: one launcher's sandbox | another's. Separate namespaces, MAC, state
  dir, broker; shared lock files for exclusive instances and the user's
  runtime dir on the host.
- B4: consent: what the user sees and clicks | what the sandbox can draw.
  The broker's notification and the window against look-alike
  notifications. The sandbox reaches notifications through the portal
  only, not the notification server or the rest of what its process
  exports (plasmashell's on-screen display, clipboard, scripting, quit).

## Attacker

Anything a process in the sandbox can do, with every principal of 11 to
16 under its control (udhcpc through a malicious DHCP server on the LAN).
The models give the attacker these moves:

1. Run any code as uid 1000 in U1 (no capabilities), U2, or a namespace of
   its own; exec any binary it can write, including one named `claude`.
2. Set any environment variable on its processes, and run the real
   Claude Code binary.
3. Create nested user, mount, pid and network namespaces, with maps
   through subid-broker, and gain every capability there.
4. Fork, exit, double-fork to reparent, kill its own processes at any
   moment (a request's or call's client mid-request), and so
   recycle pids.
5. Pass fds over Unix sockets: a connection made by one process used by
   another, so the peer the listener sees is the connecting process.
6. Plant symlinks, rename and swap directories in its rw binds, which may
   lie under a ceiling root; race these against the broker's checks. That
   includes a directory that is a mountpoint in M1 (`/nix/store`,
   `/run/permissions`, a file bind's parent) on a filesystem it can
   write: from a nested user and mount namespace, after `pivot_root` and
   a lazy unmount of the old root, the kernel doesn't refuse the rename,
   as it checks only for mounts in the caller's own namespace.
7. Re-bind a granted mount in a nested mount namespace, keep files and
   cwds open on it, map it.
8. Connect to every socket it can reach, host socket addresses included,
   as often as it likes; hold connections, send nothing, send oversized or
   malformed requests, ask for `watch` streams and never read them.
9. Post notifications with any app name, icon and buttons, timed to the
   broker's; send anything as a request's or call's `reason`,
   parameters and arguments.
10. Request, call, release and status any grant by id; ask for any lease.
11. Write its own Nix store (`/nix` is a rw bind with the closure bound
    read-only over it), persistent across launches.
12. Act through udhcpc's `net_admin` and `net_raw` over N.

It can't: write the grant directory, reach `control.sock` or the
`.flatpak` instance dirs (not bound), change the proxy's rules, see host
processes (pid namespaces), or use setuid or file capabilities
(no_new_privs).

## Properties

Each is phrased so an assertion can state it. "Sandbox process": any
process whose principal is in the Sandbox domain, at any time.

### Structure (`structure.als`)

- S1. No sandbox process has a capability in the init user namespace or
  over any namespace it owns.
- S2. No sandbox process other than udhcpc has a capability over N, M1, P
  or anything else U1 owns; udhcpc has only `net_admin` and `net_raw`, and
  only over N.
- S3. No sandbox process can join (setns) U1, N, M1, P, or any host
  namespace.
- S4. Every user namespace a sandbox process creates is strictly below
  U1, and maps only ids U1 maps (the subuid range and the user's own
  uid).
- S5. Every mount a nested mount namespace copies from M2 is locked: no
  sandbox process can unmount or move a bind to reveal what lies under it,
  `/run/permissions` included. Accepted: a grant propagated into a nested
  namespace after it was made isn't locked there and unmounts, revealing
  only the empty mountpoint in the grant directory; made private there, it
  keeps the grant's access past its end until its holders end, as any
  open file does (no `revoke()` in Linux, `docs/permissions.md`).
- S6. `control.sock` answers no request from a sandbox process, however it
  reaches the socket (a watch stream aside, which carries what
  `request.sock`'s does).
- S7. subid-broker writes a map only into a user namespace whose parent is
  the client's or below, for a client and target of the user's uid in a
  user namespace other than init; the map lands in that namespace even if
  the target moves on (unshare, exit and pid reuse) between check and
  write.
- S8. netns-macvlan attaches `eth0` only to a network namespace that isn't
  the caller's and over which the caller's uid holds every capability by
  the owner rule: the user namespace right below the caller's, on the way
  up from the one owning it, is the caller's uid's.
- S9. `share` takes effect only for a client in M1.
- S10. No sandbox process can create, rename or remove an entry of the
  grant directory, in any mount namespace.
- S11. An attach source is beneath a ceiling root reached without links or
  mount crossings, and its path is not a denied directory, beneath one, or
  above one; it carries no submounts; a read-only grant is mounted
  read-only, a directory nodev and nosuid.
- S12. No binary a host-side process execs with capabilities in a sandbox
  namespace (the broker's helpers, `setpriv`, udhcpc and its script) is
  resolved in a mount tree the sandbox can swap a directory in (M1, M2
  and their copies): the broker's helpers are exec'd on the host's mounts
  and join M1 after, udhcpc runs in MU, built from the host's. A mount of
  its own at `/nix/store` didn't do it: the sandbox renames it from a
  nested namespace (Attacker 6).
- S13. Every peer check that reads `/proc/<pid>` is about the process the
  pidfd names: no answer is based on a recycled pid.
- S14. Nothing a sandbox process can write is read by a host process as
  the sandbox's identity (`bwrapinfo.json`, `info`, the daemon's
  config). The module's assertion refuses a bind holding a state dir or
  `$XDG_RUNTIME_DIR`, or in either's identity parts.

### Protocol (`protocol.als`)

- P1. No grant without consent: every live grant was preceded by an Allow
  for its capability and parameters, from the notification or the window,
  or comes from the config as a standing grant with exactly its
  parameters that the user hasn't ended in this daemon's life. One the
  user revoked or released isn't granted again without asking until the
  daemon restarts.
- P2. A standing grant comes only from the config: no request, answer or
  event adds one, none is of type attach, and lease `standing` is never a
  request's or an answer's.
- P3. Never above the ceiling: a grant's parameters validate, match an
  instance the instances glob finds (host commands, host sockets), and
  its source passes S11 (attach), at grant time and again after a window
  narrows it.
- P4. A grant that ended is dead: no further delivery (its calls' units
  stopped and no call started under it, its host socket connections
  closed, attach detached in M1 and everywhere it propagated, before
  anything else, the holders' scan included).
- P5. After an attach grant ends, every sandbox process that still holds it
  where `/proc` shows it is listed as a holder: a thread's cwd, root or
  open file on the grant's mount or one propagated from it, known by the
  mount id and peer group read at attach (not by path, which the sandbox
  can rename, Attacker 6); a thread's cwd, root or open file on a detached
  mount of the grant's filesystem (an `open_tree` clone, a lazy unmount),
  a holder when its path names the grant's inode beneath the grant's tree
  and a possible holder otherwise; a mount namespace with a mount of the
  same filesystem and root; a mapping of one of the grant's files, from
  `/proc/<pid>/maps` by device, inode and path (`map_files` takes
  capabilities in the initial user namespace). Best effort: an fd queued in
  an `SCM_RIGHTS` message or registered with io_uring, a detached mount
  attached in a namespace no process is in, a mapping whose path can't be
  looked up beneath the grant, and what the 10 s scan doesn't reach hold it
  unseen, until the sandbox ends. Linux has no general `revoke()` and an
  open file keeps its mount alive, so ending the holders, at worst the
  sandbox, is the only way to take access back (`docs/permissions.md`).
- P6. Only host principals answer: a pending request is decided by the
  notification's own action (not within 1 s of it appearing) or by a
  `control.sock` client.
- P7. Consent text is the daemon's: the summary comes from the validated
  parameters and the resolved source; the reason and string parameters
  appear only quoted, without markup or control characters, and opaque
  ones only as a digest.
- P8. Retired with session leases (acbceda): a grant is the sandbox's,
  and no lease ends with a process.
- P9. A lock lease ends on Lock, LockedHint or PrepareForSleep, and none is
  granted while the lock isn't watched.
- P10. The validity a call is given is at most the command's
  `maxValidity` and at most what's left of a duration lease.
- P11. Every grant ends with the daemon (call units by `BindsTo=`,
  connections with its process, attach by `ExecStopPost` or the next
  start's cleanup), with the sandbox, and with its instance (on the
  instance check's timer; no call starts on an instance that's gone).
- P12. After the daemon starts, the live grants are exactly the
  configured standing grants that pass P3 and the exclusive lock: a
  restart brings back the ones the user ended, and nothing else survives.
- P13. An exclusive instance is granted to at most one launcher at a time.
- P14. The sandbox can't keep the user from answering: one pending request
  per capability, three refusals in a row block it for 2 minutes, and a
  full `request.sock` leaves `control.sock` its own budget.
- P15. Retired with session leases (acbceda): a release from inside ends
  the grant.
- P16. A host command call runs only under a grant that covers it: one of
  its capability with exactly its bounding values, never one whose
  bounding values an answer changed. A `once` grant covers only the call
  it was made for, no request gets one, and it ends when that call is
  answered. A call's arguments are checked before the user is asked.
- P17. A connection to a host socket's address is spliced to the host
  socket only while a live grant of that capability and instance covers
  it; otherwise it is closed at once, and a grant's end closes what was
  spliced under it.

### Launch (`launch.als`)

- L1. No process of the sandbox runs before U1's maps are written: a
  failed map write kills bwrap's child, so nothing runs as the overflow
  id. U1 maps exactly the subuid range plus the user's own ids; U2 maps
  exactly U1's.
- L2. net-setup acts on the sandbox's pid only once its root is final, and
  netns-macvlan only on N (S8).
- L3. udhcpc and its script run in N, MU, P with `net_admin` and
  `net_raw` alone, so a compromise of it gains nothing beyond S2's, and
  nothing in the sandbox can swap what they exec.
- L4. The app and everything it starts hold no capability in U2:
  CAP_CHECKPOINT_RESTORE is dropped before the app runs, whether or not
  the pid could be set.
- L5. A re-entry joins U2, M2, P2, N, ipc, uts and cgroup of the app's pid,
  never U1 or M1, and holds no capability after its exec; both run with
  no_new_privs, set on the host before nsenter. The app's pid is the only process at `APP_PID`
  in a pid ns one below the sandbox's.
- L6. `--permissions` never enters the sandbox.
- L7. The broker's and the launcher's handle on the sandbox names the
  outer bwrap's child, in a mount namespace other than the host's, by
  pidfd taken and re-checked against `bwrapinfo.json`; it can't be
  redirected to a host process or a nested one.
- L8. The broker exits when the sandbox's pidfd turns readable, and stops
  restarting when it never finds one; subid-broker when bwrap exits, or at
  once when its parent is gone already; call units when the broker's
  unit stops.
- L9. `share` runs before the FHS env's bwrap copies M1, or the launcher
  goes on without attach (which the broker then refuses, P3).
- L10. No host-side step reads a host file into the sandbox, or writes
  one, through a path the sandbox can write: its home, its store, the
  binds of `~/.claude` and `~/.config/Claude` (`launch-host.als`).

### D-Bus proxy (`proxy.als`)

The proxy (`cmd/dbus-proxy`) between the sandbox's clients and the bus,
with the broker's live rule sets. Its state: each client's calls awaiting
replies (`awaitBus`) and the calls to it awaiting its replies
(`awaitPeer`), the names' owners and what the proxy saw each unique name
own, the static rules and the live sets, the clients held while their
proxy looks up a set's owners, the rules each client's last message was
judged by, and the sets each client used. The attacker is every client
(any destination, any serial, any reply, eavesdropping match rules);
peers own names, call clients and reply, asked or forged.

- D1. Nothing reaches a name or method outside the rules in force: a call
  reaches its destination, and a NameOwnerChanged a client, only when
  the static rules and the live sets in force when the proxy reads it
  allow it. Owners looked up for a set that went meanwhile give nothing.
- D2. A reply only answers a call let through: no two calls let through
  await replies on one serial, a reply reaches a client only for a serial
  awaiting one and, for a call to the bus, only from the bus, and a
  client's reply reaches only a peer whose call to it awaits one.
- D3. A removed set's clients are closed: every client a message it sent
  or got was judged under the set (a rule for its destination, sender or
  name, whatever the verdict) loses its connection with the set's removal,
  alone or with the broker's connection.
- D4. No eavesdropping: no client gets a call addressed to another.

## Not modelled

To confirm with Anders (plan Open 2):

1. Kernel bugs: in user namespace, mount, pidfd and KVM code; the models
   take the man pages as the kernel's behaviour.
2. The host compositor, the portals, and the notification daemon beyond
   what the proxy's rules let through, and Wayland itself.
3. A compromised host user, host Claude Code included: it owns U1 and
   everything below it by the owner rule.

Also left out: host commands' and host sockets' own code (trusted host
code the config declares; a host command's description reaches Claude
as text), what a host socket's server does with the bytes spliced to it, the network beyond the macvlan
(LAN peers, DHCP spoofing other than through udhcpc), side channels,
timing beyond the fake clock (plan decision 2026-10-31), and resource
exhaustion of the host other than the broker's budgets. Taking back
access a holder already has after a grant ends: Linux has no general
`revoke()`, so the models ask only that holders are listed (P5) and
that ending them ends it. The window's
overview of static access (binds, ceilings, standing grants) is
read-only and carries no consent, and the recent-decisions log, in the
daemon's memory only, decides nothing. A ceiling root
on a host mount that aliases a denied directory (a ceiling on `/mnt/home`
where that's a bind of `/home`) gets a denied directory past the path
check: that's the user's own mount and ceiling configuration.

## Model files

| file | step | properties |
|---|---|---|
| `sandbox.als` | 1 | shared base: signatures and kernel facts, no sandbox claims |
| `structure.als` | 2 | S1-S14 (S7's race and S13 need two states) |
| `protocol.als` | 3 | P1-P17 (P8 and P15 retired; `protocol-consent.als`, `protocol-life.als`, `protocol-calls.als`, `protocol-tree.als`, `protocol-window.als`) |
| `launch.als` | 4 | L1-L10 (with `launch-fhs.als`, `launch-reentry.als`, `launch-host.als`), and S12 for the launch's `nsenter`s |
| `proxy.als` | | the D-Bus proxy's system; `proxy-checks.als` checks D1-D4, each with a run for its premise and a revert check per guard enforcing it |

The proxy's Go tests run `proxy.als`'s actions as a `rapid` state machine
against the proxy between a real `dbus-daemon` and clients speaking the
wire (`cmd/dbus-proxy/machine*_test.go`): clients connect, say Hello and
hang up, call names allowed and hidden with fresh, reused and forged
serials, call the bus (owners, names listed, owned, released and started,
match rules eavesdropping or not, `BecomeMonitor`, a second Hello) and
reply, asked or not; services take and release names, call clients,
reply, forge replies (to a start the bus holds pending too) and
broadcast; the broker adds and removes sets, alone or right before a
client's message, and drops its connection. After every step what
arrived at each end, the connections closed and every name's owner match
a reference model. Each step settles there, so a set removed while a
client's lookups for it are in flight (`D1inflight`) is left to a second
machine, `cmd/dbus-proxy/internal/judge/machine_test.go`, which drives one
connection's judge without sockets, the bus a queue answered in order:
the client says Hello and calls names and peers, the broker adds and
removes sets (the rules swapped before the judge hears of it, as the
registry does), names change hands, and the bus answers one message at a
time or forges replies. It checks D1 (calls and NameOwnerChanged, and
D3's close for a set a call relied on) and D2 after every step. The
end-to-end machine has calls and replies between clients, which
`proxy.als` has between a client and a peer only.

The broker's Go tests run the protocol model's actions as `rapid` state
machines against the broker (`cmd/permissions-broker/machine*_test.go`,
and live against the work launcher's daemon in the VM test,
`live*_test.go`), and compare it with a reference model
(`machine_model_test.go`) after every step. They check P1, P2, P3, P4,
P6, P7, P9, P10, P11 (the daemon's restart), P12, P13, P14, P16 and P17,
and S6 and S9. Model actions without a machine action: `startCall` and
`answerCall` apart (a machine's call runs to its answer in one step, so
a call waiting for its slot or running across a revoke is left to
`TestCallEndedBeforeStart`, `TestNoOutputAfterEnd` and `TestCallUnit`),
`instanceGone` (the machines set `instanceEvery` to 1000 h;
`TestInstanceGone`), `mature` and `forge` (`cmd/permissions-broker/internal/notify/notify_test.go`), `env`'s
renames (`attach_test.go`, `swap_test.go`), `stopPost` on its own
(`Restart` runs the start's cleanup instead) and `sandboxEnd`. The live
machine also has no `Advance` (`tick`, `expire`, `unblock`), `Instances`
or `OtherLauncher`.

`sandbox.als` has principals, processes (`var`: namespaces, ids,
capabilities, parent and pid change), user namespaces with parent, owner
and map, the other kinds with their owning user namespace, capabilities,
files, mounts with flags, and sockets with the peer checks their listener
does. Its facts are the kernel's: the user namespace tree and map rules,
`cap_capable()`'s walk (a process has every capability in a namespace
whose parent it is in with the owner's euid, and in all below), setns'
requirements, pid namespace visibility, kill's rule, MNT_LOCKED. Its
checks only test that encoding, and fail when the walk is broken (tried
by dropping the owner rule's parent condition).

## Leads for steps 2 to 4

Found while reading the code for this inventory; each should come out of
a model as a counterexample (`expect 1` until triaged in step 5).

1. Re-entries are not descendants of the sandbox's pid. `--shell` (and
   anything it starts) runs below a host `nsenter`, so `grantMounts`,
   `holdersAfter`, `descendants` and `sandbox.isDescendant`
   (`mounts.go:457-617`) don't see it: a revoke lists no holder for a
   `--shell` process with its cwd on the grant or with a re-bind in a
   nested mount namespace, and the window can't end it. Against P5.
2. Gone with session leases (acbceda): `sessionOf` walked past the
   sandbox into the host for a re-entry. Fixed before that by stopping
   at the first process outside the sandbox's user namespaces.
3. `watch` is served before `handleControl`'s user-namespace check
   (`broker.go:292`), on both sockets. Harmless today (the events carry
   only kinds and ids, which `request.sock`'s `watch` gives too), but S6
   holds only because of that.
4. `share` is accepted from any process in M1. Harmless (idempotent),
   noted for S9. udhcpc no longer runs there (L3).
5. S12 holds because each host-side exec resolves its binary on the
   host's mounts. Nothing asserts that; a helper added later that execs
   after joining M1 runs the sandbox's code with full capabilities in U1.
