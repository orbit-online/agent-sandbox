# shellcheck shell=bash
# Runs in nixpak's pasta slot: the launcher calls it with `-- <pid>` once the sandbox exists and before the app starts
: "${NETNS_MACVLAN:?}" "${SETPRIV:?}" "${UDHCPC:?}" "${UDHCPC_SCRIPT:?}"
pid=${!#}
# bwrap's parent reports the pid while the child is still building the mount tree; nixpak binds
# /.flatpak-info last, so once it shows up the sandbox's root is final
for _ in {1..50}; do
  [[ -e /proc/$pid/root/.flatpak-info ]] && break
  sleep 0.1
done
[[ -e /proc/$pid/root/.flatpak-info ]] || {
  echo "claude-desktop: Sandbox root not ready after 5s" >&2
  exit 1
}
"$NETNS_MACVLAN" "$pid"
# By now the sandbox runs in a second userns (bwrap needs uid 0 in the first to mount devpts for --dev);
# the first owns the netns. nsenter 2.42 can't combine --user-parent with other namespaces, so two steps.
# --keep-caps: exec would otherwise drop the caps setns granted
ns() {
  nsenter -t "$pid" --user-parent --preserve-credentials --keep-caps \
    nsenter -t "$pid" -n --preserve-credentials --keep-caps "$@"
}
ns ip link set lo up
ns ip link set eth0 up
# In the sandbox's pid ns so it dies with it, and its mount ns: it parses packets from the LAN, so it gets
# no more of the host than the app does. -r: the sandbox process's root, as for the claude:// re-entry.
# Forks to the background once it has a lease or gives up (~10s)
ns -m -r -p "$SETPRIV" --inh-caps=-all,+net_admin,+net_raw --ambient-caps=-all,+net_admin,+net_raw \
  --bounding-set=-all,+net_admin,+net_raw \
  "$UDHCPC" -i eth0 -s "$UDHCPC_SCRIPT" -b -t 5 -T 2
