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
case $SUBID_MAP in
subid)
  : "${SUBID_BROKER:?}"
  # nixpak's launcher puts --info-fd first for the app; its xdg-dbus-proxy runs in a plain bwrap
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
  # Its parent death signal fires when bwrap, which this shell execs into, exits. Without the info fd, which the
  # launcher reads to EOF
  "$SUBID_BROKER" "$sock" {info_out}>&- &
  for _ in {1..50}; do
    [[ -S $sock ]] && break
    sleep 0.1
  done
  [[ -S $sock ]] || {
    echo "claude-desktop: subid-broker didn't start" >&2
    exit 1
  }
  args+=(--bind "$sock" /run/subid-broker.sock "$@")
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
exec "$BWRAP" --unshare-user --info-fd 20 --userns-block-fd 21 "${args[@]}" 20>"$d/info" 21<"$d/userns"
