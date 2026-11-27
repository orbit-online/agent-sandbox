# shellcheck shell=bash
# The FHS env's runScript, ahead of the app's: sets the pid the app starts at, $APP_PID in the FHS env's pid ns, so
# Chromium's tray item takes the D-Bus name the module's policy names (StatusNotifierItem-<pid>-1). The FHS env's bwrap
# grants CAP_CHECKPOINT_RESTORE in its userns, which owns that pid ns; nothing else runs there yet but bwrap's init, so
# the next fork gets the pid. That fork is app-run.sh's, which this execs into without the capability (bwrap raised it
# as ambient): an exec forks nothing and keeps the pid cursor, and nothing of the sandbox's holds the capability by
# the time anything but this script runs, not this shell either, which would wait on the app with it for as long as
# the app runs. bash -p: no BASH_ENV file, whose commands would fork ahead of the app. URL handler re-entries
# (claude://) come in through nsenter without the capability and start the app as is, through the same drop
: "${APP_PID:?}" "${SETPRIV:?}" "${RUN:?}"
drop=("$SETPRIV" --inh-caps=-all --ambient-caps=-all --)
echo $((APP_PID - 1)) 2>/dev/null >/proc/sys/kernel/ns_last_pid || exec "${drop[@]}" "$@"
exec "${drop[@]}" "$BASH" -p "$RUN" "$@"
