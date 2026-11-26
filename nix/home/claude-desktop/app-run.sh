# shellcheck shell=bash
# What app-pid.sh execs into once it set the pid cursor and dropped its capability: the app as this shell's first
# fork, so at that pid, then the sandbox's systemd --user, in the cgroup user/ beside app/: after the app's fork, so
# neither it nor what it starts at once (timers catching up, units in the home) can take the app's pid
# (models/launch-pid.als, L11). Nothing here may fork ahead of the app: builtins only until then
: "${SETSID:?}" "${SYSTEMD:?}" "${USER_UNITS:?}"
# Without capabilities, or not at all: everything from here on is the sandbox's (models/README.md, L4)
while read -r key value; do
  case $key in
  CapInh: | CapPrm: | CapEff: | CapAmb:)
    [[ $value =~ ^0+$ ]] || { echo "claude-desktop: app-run.sh started with capabilities ($key $value)" >&2; exit 1; }
    ;;
  esac
done </proc/self/status
# A background job isn't its process group's leader, so setsid doesn't fork again: the job's pid is the app's
"$SETSID" "$@" &
app=$!
# user/ is writable only with the host's nsdelegate (cmd/launcher bwrap.go). No bus for the manager, which talks on
# $XDG_RUNTIME_DIR/systemd/private; its units get the session bus
cg=/sys/fs/cgroup/user
if mkdir "$cg" 2>/dev/null && mkdir -p /run/systemd/system /run/systemd/user.conf.d; then
  printf '[Manager]\nDefaultEnvironment=DBUS_SESSION_BUS_ADDRESS=%s\n' "${DBUS_SESSION_BUS_ADDRESS:-}" \
    >/run/systemd/user.conf.d/bus.conf
  (
    echo "$BASHPID" >"$cg/cgroup.procs" || exit
    unset DBUS_SESSION_BUS_ADDRESS
    SYSTEMD_UNIT_PATH=$USER_UNITS: SYSTEMD_LOG_TARGET=journal exec "$SYSTEMD" --user
  ) &
else
  echo "claude-desktop: No systemd --user: the sandbox's cgroup is read-only" >&2
fi
wait "$app"
