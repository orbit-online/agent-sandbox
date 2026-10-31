# shellcheck shell=bash
# The FHS env's runScript, ahead of the app's: starts the app at pid $APP_PID in the FHS env's pid ns, so Chromium's
# tray item takes the D-Bus name the module's policy names (StatusNotifierItem-<pid>-1). The FHS env's bwrap grants
# CAP_CHECKPOINT_RESTORE in its userns, which owns that pid ns; nothing else runs there yet but bwrap's init, so the
# next fork gets the pid. claude:// re-entries come in through nsenter without the capability and start the app as is.
# Either way the capability goes (bwrap raised it as ambient) before the app runs: the pid cursor survives the execs
: "${APP_PID:?}" "${SETPRIV:?}" "${SETSID:?}"
drop=("$SETPRIV" --inh-caps=-all --ambient-caps=-all --)
if echo $((APP_PID - 1)) 2>/dev/null >/proc/sys/kernel/ns_last_pid; then
  exec "${drop[@]}" "$SETSID" --fork --wait "$@"
fi
exec "${drop[@]}" "$@"
