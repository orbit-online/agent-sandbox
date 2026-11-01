# shellcheck shell=bash
# udhcpc's mount namespace, run by net-setup.sh through unshare --mount in the sandbox's user, net and pid namespaces
# with every capability in its user namespace. udhcpc parses packets from the LAN, so it gets no more of the host than
# it needs, and nothing of M1: there the sandbox can swap /nix/store for a directory of its own (models/README.md,
# S12), and udhcpc execs its script on every lease. Its root: a tmpfs holding its closure read-only from the host's
# store, /proc of the sandbox's pid namespace, /dev/null, and the sandbox's home, where the script writes resolv.conf.
# A link the sandbox planted there resolves in this view, to its own files or to nothing
: "${CLOSURE:?}" "${HOME_SRC:?}" "${SANDBOX_HOME:?}" "${BUSYBOX:?}" "${SETPRIV:?}" "${UDHCPC:?}" "${UDHCPC_SCRIPT:?}"
# busybox's mount: util-linux's treats a caller that isn't uid 0 as an unprivileged user, capabilities or not
mount() { "$BUSYBOX" mount "$@"; }
mapfile -t closure <"$CLOSURE"
# The new root, on the host's /tmp, which this namespace no longer needs
r=/tmp
mount -t tmpfs -o mode=0755 tmpfs "$r"
for p in "${closure[@]}"; do
  if [[ -d $p ]]; then
    mkdir -p "$r$p"
  else
    mkdir -p "$r${p%/*}"
    touch "$r$p"
  fi
  # Read-only as the host's /nix/store mount is, which a bind keeps
  mount -o bind "$p" "$r$p"
done
mkdir -p "$r$SANDBOX_HOME" "$r/proc" "$r/dev" "$r/old"
mount -o bind "$HOME_SRC" "$r$SANDBOX_HOME"
mount -t proc proc "$r/proc"
touch "$r/dev/null"
mount -o bind /dev/null "$r/dev/null"
cd "$r" || exit 1
"$BUSYBOX" pivot_root . old
cd / || exit 1
"$BUSYBOX" umount -l /old
rmdir /old
# Forks to the background once it has a lease or gives up (~10s)
exec "$SETPRIV" --inh-caps=-all,+net_admin,+net_raw --ambient-caps=-all,+net_admin,+net_raw \
  --bounding-set=-all,+net_admin,+net_raw \
  "$UDHCPC" -i eth0 -s "$UDHCPC_SCRIPT" -b -t 5 -T 2
