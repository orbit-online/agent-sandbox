# shellcheck shell=bash
# Runs gtk-theme.sh on every change of the portal's color-scheme until process $1 exits
: "${GTK_THEME:?}"
gdbus monitor --session --dest org.freedesktop.portal.Desktop --object-path /org/freedesktop/portal/desktop |
  while read -r line; do
    if [[ $line =~ SettingChanged\ \(\'org\.freedesktop\.appearance\',\ \'color-scheme\',\ \<uint32\ ([0-9]+)\>\) ]]; then
      "$GTK_THEME" "${BASH_REMATCH[1]}" || true
    fi
  done &
tail --pid="$1" -f /dev/null
pkill -P "$BASHPID"
