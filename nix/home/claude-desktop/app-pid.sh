# shellcheck shell=bash
# The FHS env's runScript, ahead of the app's: starts the app at pid $APP_PID in the FHS env's pid ns, so Chromium's
# tray item takes the D-Bus name the module's policy names (StatusNotifierItem-<pid>-1). The FHS env's bwrap grants
# CAP_CHECKPOINT_RESTORE in its userns, which owns that pid ns; nothing else runs there yet but bwrap's init, so the
# next fork gets the pid. claude:// re-entries come in through nsenter without the capability and start the app as is.
# Either way the capability goes (bwrap raised it as ambient) before the app runs: the pid cursor survives the execs.
# Then the sandbox's systemd --user, in the cgroup user/ beside app/: after the app's fork, so neither it nor what it
# starts at once (timers catching up, units in the home) can take the app's pid (models/launch-pid.als, L11)
: "${APP_PID:?}" "${SETPRIV:?}" "${SETSID:?}" "${SYSTEMD:?}" "${USER_UNITS:?}"
drop=("$SETPRIV" --inh-caps=-all --ambient-caps=-all --)
echo $((APP_PID - 1)) 2>/dev/null >/proc/sys/kernel/ns_last_pid || exec "${drop[@]}" "$@"
# A background job isn't its process group's leader, so setsid doesn't fork again: the job's pid is the app's
"${drop[@]}" "$SETSID" "$@" &
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
    SYSTEMD_UNIT_PATH=$USER_UNITS: SYSTEMD_LOG_TARGET=journal exec "${drop[@]}" "$SYSTEMD" --user
  ) &
else
  echo "claude-desktop: No systemd --user: the sandbox's cgroup is read-only" >&2
fi
wait "$app"
