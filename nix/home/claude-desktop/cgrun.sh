# shellcheck shell=bash
# cgrun: runs a command in a cgroup of its own under the sandbox's, with a memory limit, so the kernel's OOM killer
# ends that command (all of it: memory.oom.group) when it goes past the limit, not the app, and a CPU weight below
# the app's, so the app stays responsive while it runs.
#
# Usage: cgrun --memory=SIZE [--cpu-weight=WEIGHT] [--] CMD [ARG...]
#
#   SIZE    memory.max, in bytes or with a K, M, G or T suffix (the kernel's syntax). No swap: memory.swap.max is 0.
#   WEIGHT  cpu.weight, 1 to 10000 against the app's 100 [default: 50]. Without the cpu controller (a host whose
#           user@.service doesn't delegate it) the command runs at the sandbox's weight, with a warning.
#
# The sandbox's cgroup is mounted at /sys/fs/cgroup, its processes in app/ beneath it. The command's cgroup is
# cgrun-<pid> next to app/, removed once the command and whatever it left running have ended. Exits with the
# command's status.
root=/sys/fs/cgroup

usage() {
  echo "Usage: cgrun --memory=SIZE [--cpu-weight=WEIGHT] [--] CMD [ARG...]" >&2
  exit 2
}

memory=
cpu_weight=50
while (($#)); do
  case $1 in
  --memory=*) memory=${1#--memory=} ;;
  --cpu-weight=*) cpu_weight=${1#--cpu-weight=} ;;
  --) shift; break ;;
  -h | --help) usage ;;
  -*) echo "cgrun: Unknown option $1" >&2; usage ;;
  *) break ;;
  esac
  shift
done
[[ -n $memory && $# -gt 0 ]] || usage

# The launcher binds the sandbox's cgroup read-only when the host's cgroup2 lacks nsdelegate (cmd/launcher bwrap.go), which
# is also gone from the mount's options here then, unless the host's mount changed since
flags=
while read -r line; do
  [[ $line == *" - cgroup2 "* ]] || continue
  flags=${line##* }
done </proc/self/mountinfo
if [[ ,$flags, != *,nsdelegate,* || ! -w $root ]]; then
  echo "cgrun: $root is read-only: the host mounted cgroup2 without nsdelegate (its options: ${flags:-none})" \
    "when the app started, so the launcher kept the sandbox's cgroup read-only. The user can remount it with" \
    "nsdelegate on the host (the launcher's journal says how) and start the app again" >&2
  exit 1
fi
grep -qw memory "$root/cgroup.subtree_control" 2>/dev/null || {
  echo "cgrun: The memory controller isn't enabled in $root: not the sandbox's cgroup" >&2
  exit 1
}
cg=$root/cgrun-$$
mkdir "$cg" || exit 1
# shellcheck disable=SC2329 # The EXIT trap runs it
cleanup() {
  # The command's leftovers end with it
  [[ ! -e $cg/cgroup.kill ]] || echo 1 >"$cg/cgroup.kill" 2>/dev/null || true
  for _ in {1..50}; do
    rmdir "$cg" 2>/dev/null && return
    sleep 0.1
  done
  echo "cgrun: Couldn't remove $cg" >&2
}
trap cleanup EXIT
if ! echo "$memory" >"$cg/memory.max"; then
  echo "cgrun: Bad --memory=$memory" >&2
  exit 2
fi
[[ ! -e $cg/memory.swap.max ]] || echo 0 >"$cg/memory.swap.max"
if [[ ! -e $cg/cpu.weight ]]; then
  echo "cgrun: The cpu controller isn't enabled in $root, so the command runs without a CPU weight of its own" >&2
elif ! echo "$cpu_weight" >"$cg/cpu.weight"; then
  echo "cgrun: Bad --cpu-weight=$cpu_weight" >&2
  exit 2
fi
echo 1 >"$cg/memory.oom.group"

# Handlers, not ignored signals: the command gets them as usual, and this shell waits for it, then cleans up
trap : INT TERM HUP QUIT
status=0
(
  echo 0 >"$cg/cgroup.procs"
  exec "$@"
) || status=$?
exit "$status"
