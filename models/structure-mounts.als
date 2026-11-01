/*
 * S5, S10, S11 and S14: mounts, their locks, the binds and the attach
 * grants, in one state. The sandbox's processes are wherever
 * structure-attacker shows they can get (structure.als's `reach`).
 *
 * The kernel's mount facts, from fs/namespace.c and fs/pnode.c (Linux
 * 6.18), checked inside this sandbox with unshare on 2026-10-31:
 * - a mount namespace's copy keeps each mount's flags and MNT_LOCKED,
 *   and when the new namespace is owned by another user namespace
 *   lock_mnt_tree() locks every mount but the root (MNT_LOCKED) and the
 *   flags each has (MNT_LOCK_READONLY, _NODEV, _NOSUID);
 * - a mount propagated into a namespace owned by another user
 *   namespace gets the flag locks, not MNT_LOCKED (tried: a grant
 *   propagated after the nested namespace was made unmounts there; a
 *   read-only one can't be remounted read-write);
 * - a bind (open_tree, mount --bind) keeps the flag locks and drops
 *   MNT_LOCKED on its top;
 * - a mount made or attached by a process that holds CAP_SYS_ADMIN over
 *   its namespace has no locks there (tried: a read-only bind moved into
 *   a namespace remounts read-write in it).
 */
open structure

// HIDE: Pid StorePath Exec Socket Op

abstract sig How {}
// A namespace's root mount; a copy made with the namespace; a later
// propagation from a peer or master; a bind of another mount; a new
// mount (a filesystem, or a detached tree moved in).
one sig IsRoot, Copied, Propagated, Bound, Fresh extends How {}
one sig LockRO, LockNoDev, LockNoSuid extends MountFlag {}

sig SMount extends Mount { from: lone SMount, how: one How }
fact { Mount = SMount }

fun lockOf: MountFlag -> MountFlag {
  ReadOnly -> LockRO + NoDev -> LockNoDev + NoSuid -> LockNoSuid
}
fun lockable: set MountFlag { ReadOnly + NoDev + NoSuid }
fun locks: set MountFlag { LockRO + LockNoDev + LockNoSuid }

fact kernelMounts {
  all m: SMount {
    some m.from iff m.how in Copied + Propagated + Bound
    m not in m.^from
    m.how in Copied + Propagated implies {
      m.root = m.from.root and m.ns != m.from.ns
      m.ns.ownedBy in m.from.ns.ownedBy.*~parent
    }
    m.how = Copied implies m.from.flags in m.flags
    m.how = Propagated implies (m.from.flags & (lockable + locks)) in m.flags
    m.how = Bound implies {
      m.root in m.from.root.*~up and (m.from.flags - Locked) in m.flags
      Locked not in m.flags
    }
    m.how = Fresh implies no m.flags & (locks + Locked)
    m.how = Propagated implies Locked not in m.flags
    m.how = IsRoot implies no m.flags & (locks + Locked)
    // a namespace's copy of the old root is its own root
    m.how = Copied implies m.from.how != IsRoot
    // lock_mnt_tree() across user namespaces
    (m.how in Copied + Propagated and m.ns.ownedBy != m.from.ns.ownedBy) implies {
      all f: lockable & m.flags | lockOf[f] in m.flags
      m.how = Copied implies Locked in m.flags
    }
    // otherwise nothing sets a lock
    (m.how = Copied and m.ns.ownedBy = m.from.ns.ownedBy) implies m.flags = m.from.flags
    (m.how = Propagated and m.ns.ownedBy = m.from.ns.ownedBy) implies
      no m.flags & (locks - m.from.flags)
    all f: lockable | lockOf[f] in m.flags implies f in m.flags
  }
}

// mount_setattr(2) or remount clearing f: CAP_SYS_ADMIN over the
// namespace, from inside it, and f not locked.
pred canClear[p: Process, m: SMount, f: MountFlag] {
  p.mnt = m.ns and hasCapOver[p, m.ns, SysAdmin]
  f in m.flags and lockOf[f] not in m.flags
}

// umount2(2) or a move revealing what lies beneath: not a root.
pred canReveal[p: Process, m: SMount] { canUnmount[p, m] and m.how != IsRoot }

// p writes f, or an entry of directory f: a mount in its namespace
// shows f, and is read-write or can be made so.
pred writes[p: Process, f: File] {
  some m: SMount | m.ns = p.mnt and f in m.root.*~up
    and (ReadOnly not in m.flags or canClear[p, m, ReadOnly])
}

// ---------------------------------------------------------------------
// Host files. The grant directory, control.sock and the .flatpak
// instance dirs (bwrapinfo.json, info) are in $XDG_RUNTIME_DIR; the
// sandbox's home, store and scratchpad in the launcher's state dir (hm/default.nix:90, 535-547, 855-857).

one sig FsRoot, RuntimeDir, GrantDir, FlatpakDir, StateDir,
  SandboxHome, SandboxNix, Scratch extends File {}
// tmpfs and other filesystems made in a namespace: no host file in them
sig Anon extends File {}
// The host directories a launcher's `binds` name, and those an attach
// ceiling allows
sig UserBind in File {}
sig CeilingRoot in File {}
// Files the attacker can plant a symlink at: those under its rw binds
sig Link in File { target: one File }

fact hostFiles {
  no FsRoot.up
  all f: File - Anon - FsRoot | some f.up and f.up not in Anon
  all a: Anon | a.up in Anon
  (GrantDir + FlatpakDir).up = RuntimeDir
  (SandboxHome + SandboxNix + Scratch).up = StateDir
  RuntimeDir not in StateDir.*up and StateDir not in RuntimeDir.*up
  no (UserBind + CeilingRoot) & Anon
}

// What may lie beneath a rw bind of the sandbox's: its home, store,
// scratchpad and the user's rw binds.
fun rwRoots: set File { SandboxHome + SandboxNix + Scratch + UserBind }
fact links { Link in rwRoots.*~up - rwRoots }

// The host's mount namespace: its mounts carry no locks (the host made
// them). M1: bwrap's binds of host mounts, the home, store and
// scratchpad rw, the store's closure and the grant directory read-only
// (hm/default.nix:532-548, 806-825), the user's binds, and the grants.
fact m1 {
  all m: SMount | m.ns = HostMnt implies (m.how in IsRoot + Fresh and m.root not in Anon)
  all m: SMount | m.ns = M1 implies {
    m.how = IsRoot implies m.root in Anon
    m.how = Bound implies {
      m.from.ns = HostMnt
      m.root in SandboxHome + SandboxNix + Scratch + GrantDir + UserBind
      (m.root = GrantDir) iff ReadOnly in m.flags
    }
    m.how = Fresh implies m in Grant.mnt
    m.how not in Copied + Propagated
  }
  // Only bwrap makes a mount namespace owned by U1 or init: nothing in
  // the sandbox holds CAP_SYS_ADMIN in either (S2). (clone-tree's
  // private one never shows the sandbox anything.)
  all n: MountNS - M1 - HostMnt | n.ownedBy not in U1 + InitUserNS
  // A bind from another namespace is bwrap's, in M1 only
  all m: SMount | (m.how = Bound and m.from.ns != m.ns) implies m.ns = M1
  // M2 and the namespaces below are copies, and the attacker's own
  all m: SMount | m.ns not in HostMnt + M1 implies {
    // bwrap's tmpfs root in M2, or a copy of it (as IsRoot)
    m.how = IsRoot implies m.root in Anon
    m.how in Copied + Propagated implies m.from.ns.ownedBy in U1.*~parent
    m.how = Fresh implies (m.root in Anon or m in Grant.mnt)
  }
}

// The module's assertion on `binds` (hm/default.nix stateBinds): no bind
// holds the runtime dir or a state dir, or lies in the grant or .flatpak
// dirs, or in a state dir outside the sandbox's home, store and
// scratchpad.
pred defaultBinds {
  no UserBind & (RuntimeDir + StateDir).*up
  no UserBind & (GrantDir + FlatpakDir).*~up
  no UserBind & (StateDir.^~up - (SandboxHome + SandboxNix + Scratch).*~up)
}
fact { BindsAsserted in Guards.on implies defaultBinds }

// ---------------------------------------------------------------------
// Attach grants (permissions-broker). The daemon checks the source
// lexically against the ceiling and the denied list (ceiling.go
// checkSource), clone-tree opens the root and the source without links
// and the source beneath the root without crossing mounts (ceiling.go
// openSource), clones without submounts and sets ro, nodev and nosuid
// (tree.go cloneTree); move-tree attaches it in sb's mount namespace.
// The model's paths are its files: beneath the root, RESOLVE_NO_XDEV
// keeps it so. A ceiling root on a host mount that aliases a denied
// directory isn't modelled (README, Not modelled).

// The denied list: every launcher's state dir and $XDG_RUNTIME_DIR
// (hm/default.nix:866).
one sig Denied { dirs: set File }
fact { Denied.dirs = StateDir + RuntimeDir }

sig Grant {
  ceiling: one CeilingRoot,
  // what the request names, and what the open resolves it to
  asked, source: one File,
  ro: lone Grant,
  mnt: one SMount
}

// Flags are as each mount was made; canClear is what can change them.

// Guards, so the revert checks can drop each.
one sig Guards { on: set Guard }
abstract sig Guard {}
one sig NoLinks, Beneath, NoSubmounts, BindsAsserted, PinnedNS extends Guard {}

fact grants {
  all g: Grant {
    g.ro in g
    // resolution: through the tree, and through planted links unless
    // RESOLVE_NO_SYMLINKS
    g.source in g.asked + (NoLinks in Guards.on => none else g.asked.^(target + ~up))
    g.asked in g.ceiling.*~up
    // the denied list on the path: at, beneath or above a denied
    // directory (above the root too, as the path holds it)
    no (g.asked.*up + g.asked.*~up) & Denied.dirs
    // RESOLVE_BENEATH: refuses a resolution that leaves the root
    Beneath in Guards.on implies g.source in g.ceiling.*~up
    // open_tree without AT_RECURSIVE in a locked copy: no mount below
    NoSubmounts in Guards.on implies no m: SMount - g.mnt |
      m.ns = HostMnt and m.how = Fresh and m.root in g.source.^~up
    g.mnt.how = Fresh and g.mnt.root = g.source
    // attached in the mount namespace pinned when the daemon found the
    // sandbox (pinSandbox: owned by a child of the init user namespace,
    // with the pid in it, so M1); without the pin, wherever the
    // sandbox's pid is when the grant is made
    g.mnt.ns = (PinnedNS in Guards.on => M1 else sb.mnt)
    some g.ro iff ReadOnly in g.mnt.flags
    // nodev and nosuid for a directory; the model's files all may be
    NoDev + NoSuid in g.mnt.flags
  }
  Grant.mnt in SMount
  all disj g, h: Grant | g.mnt != h.mnt
}

pred guarded { Guards.on = Guard }

// ---------------------------------------------------------------------
// S5: every mount a nested mount namespace (owned below U2) copies from
// what M2 had when it was made is locked: the attacker, though it holds
// CAP_SYS_ADMIN over the namespace, can't unmount or move one to reveal
// what's beneath. Holds. Revert: without lock_mnt_tree()'s MNT_LOCKED on
// copies across user namespaces, counterexample found. Not covered: a
// U1 attacker that took U2's capabilities (structure-attacker,
// u1AttackerOwnsU2) can copy M2 into a namespace U2 owns, where the FHS
// env's own top binds aren't locked; beneath them are the FHS root's
// empty mountpoints.
assert S5copiesLocked {
  world implies no p: sandboxProcs, m: SMount |
    m.how = Copied and m.from.ns = M2 and m.from.how != Propagated
      and m.ns.ownedBy in U2.^~parent and canReveal[p, m]
}
check S5copiesLocked for 3 but 5 UserNS, 11 OwnedNS, 8 File, 6 Mount, 8 StorePath, 0 LaterExec, 1 steps expect 0

run S5nestedWithCaps {
  world and some p: sandboxProcs, m: SMount |
    m.how = Copied and m.from.ns = M2 and p.mnt = m.ns and hasCapOver[p, m.ns, SysAdmin]
} for 3 but 5 UserNS, 11 OwnedNS, 8 File, 6 Mount, 8 StorePath, 0 LaterExec, 1 steps expect 1

// S5 for mounts that reach a nested namespace later: a grant propagated
// into the attacker's namespace after it was made is not MNT_LOCKED
// there and unmounts (tried, see the header). What it reveals is the
// empty mountpoint the broker made in the grant directory, in the
// attacker's own namespace. Made private there, the propagated grant
// also keeps its access after the grant ends, until the processes
// holding it end, as any open file does: Linux has no general revoke()
// (docs/permissions.md). Known, accepted (README S5).
assert S5propagatedLocked {
  world implies no p: sandboxProcs, m: SMount |
    m.from.ns = M2 and m.how in Copied + Propagated and canReveal[p, m]
}
check S5propagatedLocked for 3 but 5 UserNS, 11 OwnedNS, 8 File, 6 Mount, 8 StorePath, 0 LaterExec, 1 steps expect 1

// S10: no sandbox process creates, renames or removes an entry of the
// grant directory, in any mount namespace. Holds with the default binds:
// M1's bind is read-only and nothing in the sandbox has CAP_SYS_ADMIN
// over M1 (S2); every copy and propagation of it is LOCK_READONLY; a
// grant can't hold it ($XDG_RUNTIME_DIR is denied). Revert: without the
// flag locks on copies, the attacker remounts its copy read-write
// (counterexample found); without RuntimeDir in the denied list, a grant
// of it does (found).
assert S10grantDirReadOnly {
  (world and guarded and defaultBinds) implies no p: sandboxProcs | writes[p, GrantDir]
}
check S10grantDirReadOnly for 3 but 5 UserNS, 11 OwnedNS, 10 File, 5 Mount, 2 Grant, 8 StorePath, 0 LaterExec, 1 steps expect 0

// S14: nothing the sandbox writes is what the host reads as its
// identity: bwrapinfo.json and info (under the .flatpak dir). The
// daemon's config is a path in the host's Nix store, which no bind
// reaches. Holds with the default binds, as S10.
assert S14identityNotWritable {
  (world and guarded and defaultBinds) implies
    no p: sandboxProcs | writes[p, FlatpakDir]
}
check S14identityNotWritable for 3 but 5 UserNS, 11 OwnedNS, 10 File, 5 Mount, 2 Grant, 8 StorePath, 0 LaterExec, 1 steps expect 0

// S10 and S14 with any `binds` the module accepts: its assertion refuses
// the paths the ceiling's denied list refuses as grant sources. Holds.
assert S14anyBinds {
  (world and guarded) implies
    no p: sandboxProcs | writes[p, GrantDir] or writes[p, FlatpakDir]
}
check S14anyBinds for 3 but 5 UserNS, 11 OwnedNS, 10 File, 5 Mount, 2 Grant, 8 StorePath, 0 LaterExec, 1 steps expect 0

// S14, revert: without the assertion a bind holding a state dir or
// $XDG_RUNTIME_DIR passes (a rw bind of $XDG_RUNTIME_DIR exposes
// bwrapinfo.json and the grant directory).
assert S14anyBindsRevert {
  (world and Guards.on = Guard - BindsAsserted) implies
    no p: sandboxProcs | writes[p, GrantDir] or writes[p, FlatpakDir]
}
check S14anyBindsRevert for 3 but 5 UserNS, 11 OwnedNS, 10 File, 5 Mount, 2 Grant, 8 StorePath, 0 LaterExec, 1 steps expect 1

// S11: a granted source is beneath its ceiling root, is no denied
// directory, beneath or above one, and brings no submount. Holds: with
// no link followed and no mount crossed, the source is the path the
// lexical check saw. Revert: dropping Beneath alone still holds;
// dropping NoLinks alone lets a link beneath the root reach a state dir
// there (counterexample found), and dropping both lets one lead out of
// the ceiling. A ceiling root on a host mount that aliases a denied
// directory isn't modelled: that's the user's configuration.
assert S11sourceInCeiling {
  (world and guarded) implies all g: Grant {
    g.source in g.ceiling.*~up
    no (g.source.*up + g.source.*~up) & Denied.dirs
    no m: SMount - g.mnt | m.ns = HostMnt and m.how = Fresh and m.root in g.source.^~up
  }
}
check S11sourceInCeiling for 3 but 5 UserNS, 11 OwnedNS, 13 File, 5 Mount, 2 Grant, 8 StorePath, 0 LaterExec, 1 steps expect 0

run S11grantVisibleToApp {
  world and guarded and sbPinned and some g: Grant, m: SMount |
    some g.ro and m.from = g.mnt and m.ns = M2 and m.how = Propagated
} for 3 but 5 UserNS, 11 OwnedNS, 10 File, 5 Mount, 2 Grant, 8 StorePath, 0 LaterExec, 1 steps expect 1

// S11's flags: a read-only grant stays read-only, and every grant
// nodev and nosuid, wherever the sandbox sees it. Holds with the
// sandbox's pid in M1: there nothing in the sandbox has CAP_SYS_ADMIN,
// and the copies in M2 and below are flag-locked. Revert: without
// lock_mnt_tree()'s flag locks, counterexample found.
assert S11flagsStay {
  (world and guarded and sbPinned) implies no p: sandboxProcs, g: Grant, m: SMount |
    g.mnt in m.*from and (canClear[p, m, NoDev] or canClear[p, m, NoSuid]
      or (some g.ro and canClear[p, m, ReadOnly]))
}
check S11flagsStay for 3 but 5 UserNS, 11 OwnedNS, 10 File, 5 Mount, 2 Grant, 8 StorePath, 0 LaterExec, 1 steps expect 0

// The same under the README's attacker, which counts bwrap's init in.
// Run as the sandbox's pid, it unshares a user and mount namespace of
// its own. Holds: the daemon pins the sandbox's mount and user
// namespaces when it finds it (pinSandbox, cmd/permissions-broker/
// sandbox.go), refusing a mount namespace whose owner isn't a child of
// its own user namespace or doesn't hold the pid, and its helpers join
// the pinned M1 by fd (inM1, helpers.go) after check() refuses once the
// pid has left the pinned namespaces. The grant is attached in M1 and
// reaches the attacker's namespace only as a flag-locked copy or
// propagation. Revert: without the pin (the namespaces read afresh from
// /proc/<pid>/ns for every grant, as before the fix), move-tree attaches
// the tree in the attacker's namespace, unlocked, and the attacker
// remounts a read-only grant read-write (counterexample found).
assert S11flagsUnderHijack {
  (world and guarded) implies no p: sandboxProcs, g: Grant, m: SMount |
    g.mnt in m.*from and some g.ro and canClear[p, m, ReadOnly]
}
check S11flagsUnderHijack for 3 but 5 UserNS, 11 OwnedNS, 10 File, 5 Mount, 2 Grant, 8 StorePath, 0 LaterExec, 1 steps expect 0

assert S11flagsUnderHijackRevert {
  (world and Guards.on = Guard - PinnedNS) implies no p: sandboxProcs, g: Grant, m: SMount |
    g.mnt in m.*from and some g.ro and canClear[p, m, ReadOnly]
}
check S11flagsUnderHijackRevert for 3 but 5 UserNS, 11 OwnedNS, 10 File, 5 Mount, 2 Grant, 8 StorePath, 0 LaterExec, 1 steps expect 1
