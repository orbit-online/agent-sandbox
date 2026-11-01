# shellcheck shell=bash
# Runs in nixpak's pasta slot: the launcher calls it with `-- <pid>` once the sandbox exists and before the app starts.
# $NAME: the launcher's name, empty for the default one
: "${NETNS_MACVLAN:?}" "${DHCP_ROOT:?}"
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
"$NETNS_MACVLAN" "$pid" ${NAME:+"$NAME"}
# The sandbox's userns owns its netns. --keep-caps: exec would otherwise drop the caps setns granted
ns() {
  nsenter -t "$pid" -U -n --preserve-credentials --keep-caps "$@"
}
ns ip link set lo up
ns ip link set eth0 up
# udhcpc in a mount namespace of its own, made from the host's (see dhcp-root.sh), in the sandbox's pid ns so it dies
# with it
ns -p unshare --mount --propagation private "$DHCP_ROOT"
