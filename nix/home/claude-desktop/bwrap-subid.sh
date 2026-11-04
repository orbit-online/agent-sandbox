# shellcheck shell=bash
# bwrap for the sandbox: maps a range of ids into bwrap's userns through newuidmap and newgidmap, which bwrap
# can't do itself (unprivileged, it only writes one-id maps).
# SUBID_MAP=subid, nixpak's bwrap on the host: the user's /etc/subuid and /etc/subgid range, inner id x is host
#   start+x except the user's own uid and gid, which stay themselves. Starts subid-broker, whose socket the sandbox
#   gets at /run/subid-broker.sock.
# SUBID_MAP=parent, the FHS env's bwrap inside: every id of the parent userns as itself, through the broker's shims,
#   and /etc/subuid and /etc/subgid listing those ids minus the user's own for rootless tools (on fds 22 and 23).
: "${BWRAP:?}" "${SUBID_MAP:?}" "${NEWUIDMAP:?}" "${NEWGIDMAP:?}"

uid=$(id -u) gid=$(id -g)
args=()
info_out=
cg_root=
case $SUBID_MAP in
subid)
  : "${SUBID_BROKER:?}"
  # nixpak's launcher puts --info-fd first for the app; its D-Bus proxy runs in a plain bwrap
  [[ ${1:-} == --info-fd ]] || exec "$BWRAP" "$@"
  user=$(id -un)
  IFS=: read -r _ ustart ucount < <(grep -m1 "^$user:" /etc/subuid) || true
  IFS=: read -r _ gstart gcount < <(grep -m1 "^$user:" /etc/subgid) || true
  if ((${ucount:-0} <= uid || ${gcount:-0} <= gid)); then
    echo "claude-desktop: $user needs a range of at least $((uid + 1)) ids in /etc/subuid and $((gid + 1)) in /etc/subgid" >&2
    exit 1
  fi
  umap=(0 "$ustart" "$uid" "$uid" "$uid" 1 $((uid + 1)) $((ustart + uid + 1)) $((ucount - uid - 1)))
  gmap=(0 "$gstart" "$gid" "$gid" "$gid" 1 $((gid + 1)) $((gstart + gid + 1)) $((gcount - gid - 1)))
  # nixpak's options, up to the --: its --info-fd is ours to forward, --unshare-user-try becomes --unshare-user
  while (($#)) && [[ $1 != -- ]]; do
    case $1 in
    --unshare-user-try) ;;
    --info-fd)
      info_out=$2
      shift
      ;;
    *) args+=("$1") ;;
    esac
    shift
  done
  sock=$XDG_RUNTIME_DIR/claude-desktop/subid-broker-$$.sock
  mkdir -p "${sock%/*}"
  # Its parent death signal fires when bwrap, which this shell execs into, exits; it ends at once if this shell is
  # gone by then. Without the info fd, which the launcher reads to EOF
  "$SUBID_BROKER" "$sock" $$ {info_out}>&- &
  for _ in {1..50}; do
    [[ -S $sock ]] && break
    sleep 0.1
  done
  [[ -S $sock ]] || {
    echo "claude-desktop: subid-broker didn't start" >&2
    exit 1
  }
  # The sandbox's cgroups, below the app's unit's (Delegate=yes), which systemd started in supervisor/
  # (DelegateSubgroup=), where this shell and nixpak's launcher stay. The sandbox gets sandbox/, the root of its
  # cgroup namespace, with its processes in sandbox/app/: bwrap's parent sits in sandbox/ while it clones the child,
  # whose new cgroup namespace is rooted where its parent is, then the info fd's reader below moves the parent back
  # here and the child, still blocked, into app/. sandbox/ holds no process, so controllers can be enabled for its
  # children (cgrun), and the kernel's nsdelegate keeps the sandbox from writing its root's files (memory.max,
  # cgroup.max.*) or moving a process out of it. It sees sandbox/ alone at /sys/fs/cgroup.
  # nsdelegate guards only the root of the writer's own cgroup namespace: from a nested one, rooted at app/, the
  # sandbox writes sandbox/'s files. So the caps on its cgroups go on the unit's cgroup, which it has no path to
  # cgroup v2 alone: one line, 0::PATH
  cg_self=$(</proc/self/cgroup)
  cg_self=${cg_self#0::}
  [[ $cg_self == */supervisor ]] || {
    echo "claude-desktop: Not in the app's unit's supervisor cgroup but in $cg_self" >&2
    exit 1
  }
  cg_root=/sys/fs/cgroup${cg_self%/supervisor}
  # Without end, the sandbox's cgroups would cost the kernel memory without end: 64 below sandbox/, app/ included, 4
  # deep, which are 66 and 5 from the unit's cgroup (supervisor/ and sandbox/ besides)
  echo 66 >"$cg_root/cgroup.max.descendants"
  echo 5 >"$cg_root/cgroup.max.depth"
  mkdir "$cg_root/sandbox" "$cg_root/sandbox/app"
  # Without nsdelegate, the kernel neither keeps the sandbox from its root's files nor checks moves against its
  # namespace (any cgroup2 mount in the host's cgroup namespace without the option clears it for all, as cilium's
  # does): the sandbox gets its cgroup read-only, and no cgrun. systemd mounts it with nsdelegate
  cg_bind=--bind
  # The superblock's options, last on a cgroup2 mount's line: the same on every one
  cg_flags=
  while read -r line; do
    [[ $line == *" - cgroup2 "* ]] || continue
    cg_flags=${line##* }
    break
  done </proc/self/mountinfo
  if [[ ,$cg_flags, != *,nsdelegate,* ]]; then
    cg_bind=--ro-bind
    echo "claude-desktop: cgroup2 is mounted without nsdelegate (options: ${cg_flags:-none}), so the sandbox's" \
      "cgroup is read-only and cgrun won't work in it. A cgroup2 mount in the host's cgroup namespace without the" \
      "option clears it (cilium's at /run/cilium/cgroupv2 does). As root, 'mount -o" \
      "remount,nsdelegate,memory_recursiveprot,memory_hugetlb_accounting /sys/fs/cgroup' restores systemd's" \
      "options; then start the app again" >&2
  fi
  # The controllers the unit got, for sandbox/ and below
  ctl=()
  for c in memory pids; do grep -qw "$c" "$cg_root/cgroup.controllers" && ctl+=("+$c"); done
  ((${#ctl[@]} == 0)) || echo "${ctl[*]}" >"$cg_root/cgroup.subtree_control"
  args+=(--bind "$sock" /run/subid-broker.sock "$cg_bind" "$cg_root/sandbox" /sys/fs/cgroup "$@")
  ;;
parent)
  user=$(id -un)
  umap=() gmap=()
  # The ids around own in an inner range of the parent's map, as subuid lines
  around() {
    local start=$1 count=$2 own=$3
    if ((own < start || own >= start + count)); then
      echo "$user:$start:$count"
      return
    fi
    ((own == start)) || echo "$user:$start:$((own - start))"
    ((own == start + count - 1)) || echo "$user:$((own + 1)):$((start + count - own - 1))"
  }
  while read -r inner _ count; do umap+=("$inner" "$inner" "$count"); done </proc/self/uid_map
  while read -r inner _ count; do gmap+=("$inner" "$inner" "$count"); done </proc/self/gid_map
  subuid=$(while read -r inner _ count; do around "$inner" "$count" "$uid"; done </proc/self/uid_map)
  subgid=$(while read -r inner _ count; do around "$inner" "$count" "$gid"; done </proc/self/gid_map)
  # The FHS env's /etc comes from its rootfs and a fixed list of host entries, so these go in as data: the module's
  # extraBwrapArgs bind fds 22 and 23, which have to come after the FHS env's /etc tmpfs
  args=("$@")
  exec 22< <(printf '%s\n' "$subuid") 23< <(printf '%s\n' "$subgid")
  # With the permissions broker, its grant directory turns shared here, before this bwrap copies the mount
  # namespace, so grants mounted there later reach the app (docs/permissions.md)
  if [[ -d /run/permissions ]]; then
    : "${PERMISSIONS_BROKER:?}"
    "$PERMISSIONS_BROKER" share ||
      echo "claude-desktop: No folder grants: the permissions broker didn't share /run/permissions" >&2
  fi
  ;;
*)
  echo "bwrap-subid: Unknown SUBID_MAP $SUBID_MAP" >&2
  exit 2
  ;;
esac

d=$(mktemp -d)
mkfifo "$d/info" "$d/userns"
# Fds from 20 up: nixpak's launcher passes 3 and 4
(
  exec 20<"$d/info" 21>"$d/userns"
  rm -r "$d"
  read -r -d '' info <&20 || true
  [[ $info =~ \"child-pid\":\ *([0-9]+) ]] || {
    kill -KILL $$
    exit 1
  }
  pid=${BASH_REMATCH[1]}
  if [[ -n $cg_root ]]; then
    if ! echo $$ >"$cg_root/supervisor/cgroup.procs" || ! echo "$pid" >"$cg_root/sandbox/app/cgroup.procs" ||
      { ((${#ctl[@]})) && ! echo "${ctl[*]}" >"$cg_root/sandbox/cgroup.subtree_control"; }; then
      kill -KILL "$pid" $$
      exit 1
    fi
  fi
  # Unblocked without maps, the child would run as the overflow uid: take bwrap down instead
  if ! "$NEWUIDMAP" "$pid" "${umap[@]}" || ! "$NEWGIDMAP" "$pid" "${gmap[@]}"; then
    kill -KILL "$pid" $$
    exit 1
  fi
  [[ -z $info_out ]] || printf '%s' "$info" >&"$info_out"
  echo >&21
) &
# The caller reads its info fd to EOF, so bwrap mustn't hold it
[[ -z $info_out ]] || exec {info_out}>&-
# Where the child's cgroup namespace is rooted, see above
[[ -z $cg_root ]] || echo $$ >"$cg_root/sandbox/cgroup.procs"
exec "$BWRAP" --unshare-user --info-fd 20 --userns-block-fd 21 "${args[@]}" 20>"$d/info" 21<"$d/userns"
