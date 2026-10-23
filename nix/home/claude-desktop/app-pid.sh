# shellcheck shell=bash
# The FHS env's runScript, ahead of the app's: starts the app at pid $APP_PID in the FHS env's pid ns, so Chromium's
# tray item takes the D-Bus name the module's policy names (StatusNotifierItem-<pid>-1). The FHS env's bwrap grants
# CAP_CHECKPOINT_RESTORE in its userns, which owns that pid ns; nothing else runs there yet but bwrap's init, so the
# next fork gets the pid. claude:// re-entries come in through nsenter without the capability and start the app as is
: "${APP_PID:?}" "${SETPRIV:?}" "${SETSID:?}"
if echo $((APP_PID - 1)) 2>/dev/null >/proc/sys/kernel/ns_last_pid; then
  # Drops the capability (bwrap raised it as ambient) before the fork; the pid cursor survives the execs
  exec "$SETPRIV" --inh-caps=-all --ambient-caps=-all -- "$SETSID" --fork --wait "$@"
fi
exec "$@"
