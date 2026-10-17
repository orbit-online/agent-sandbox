# shellcheck shell=bash
# The launcher on the host's PATH. $VARS: the sandbox's environment, filtered (see `vars` in default.nix).
# $REQUIRED_BINDS: the sources of the binds that aren't optional
: "${SANDBOX_HOME:?}" "${SCRATCHPAD:?}" "${RESOLV_CONF:?}" "${APP_ID:?}" "${FHS_ENV:?}" "${DOT_CLAUDE:?}" "${CONFIG:?}" "${MCP_SERVERS:?}" "${TRAY:?}"
: "${STORE_SYNC:?}" "${GTK_THEME:?}" "${GTK_THEME_WATCH:?}" "${NIXPAK_LAUNCHER:?}"
mkdir -p "$SANDBOX_HOME/.config" "$DOT_CLAUDE"
# Bind source for Claude Code's temp dir, which it wants private. Its parent exists from SANDBOX_HOME's mkdir
[[ -d $SCRATCHPAD ]] || mkdir -m 700 "$SCRATCHPAD"
# Bind source for the sandbox's /etc/resolv.conf, filled in by the DHCP client
touch "$RESOLV_CONF"
# Without user-dirs.dirs, Chromium saves downloads to $HOME
# shellcheck disable=SC2016
echo 'XDG_DOWNLOAD_DIR="$HOME/Downloads"' >"$SANDBOX_HOME/.config/user-dirs.dirs"
args=(--password-store=basic "$@")

# The running sandbox's pid 1. The mount ns check stops a stale info file with a recycled pid from pointing at a
# host process
sandbox_pid() {
  local d pid
  for d in "$XDG_RUNTIME_DIR"/.flatpak/nixpak-app-*; do
    grep -qxF "name=$APP_ID" "$d/info" 2>/dev/null || continue
    pid=$(grep -oP '"child-pid":\s*\K\d+' "$d/bwrapinfo.json" 2>/dev/null) || continue
    if [[ -e /proc/$pid/ns/mnt && ! /proc/$pid/ns/mnt -ef /proc/self/ns/mnt ]]; then
      echo "$pid"
      return
    fi
  done
  return 1
}

# The app's main process: pid 1's grandchild in a user ns its parent isn't in, which only the FHS env's bwrap makes.
# Re-entries come in through nsenter, so they aren't pid 1's descendants
app_pid() {
  local child children grandchild grandchildren
  read -ra children <"/proc/$1/task/$1/children" || true
  for child in "${children[@]}"; do
    read -ra grandchildren <"/proc/$child/task/$child/children" 2>/dev/null || true
    for grandchild in "${grandchildren[@]}"; do
      if [[ ! /proc/$grandchild/ns/user -ef /proc/$child/ns/user ]]; then
        echo "$grandchild"
        return
      fi
    done
  done
  return 1
}

env=(env -i "${VARS[@]}" DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/nixpak-bus")
# Not -a: that also joins the time ns, still the host's, which needs CAP_SYS_ADMIN in the init userns
nsenter=(nsenter -U -m -p -n -i -u -C -r -w --preserve-credentials)

# --shell (the .desktop file's terminal action): a login shell where the app runs, so it gets the Code tab's environment
if [[ ${1:-} == --shell ]]; then
  if ! { pid=$(sandbox_pid) && app=$(app_pid "$pid"); }; then
    echo "Starting Claude"
    # As a unit of its own: run from the terminal, the app would stop with the terminal's unit
    systemd-run --user --collect --quiet -- "$(readlink -f "$0")"
    for ((i = 0; i < 300; i++)); do
      pid=$(sandbox_pid) && app=$(app_pid "$pid") && break
      sleep 1
    done
  fi
  [[ -n ${app:-} ]] || { echo "claude-desktop: The app didn't start, see journalctl --user" >&2; exit 1; }
  # The terminal's. Ghostty points TERMINFO at its own entry, which the sandbox's store lacks: xterm-256color then
  term=()
  for v in TERM TERMINFO COLORTERM; do [[ -z ${!v:-} ]] || term+=("$v=${!v}"); done
  # shellcheck disable=SC2016
  exec "${env[@]}" "${term[@]}" "${nsenter[@]}" -t "$app" /bin/sh -c \
    '[ -z "${TERMINFO-}" ] || [ -d "$TERMINFO" ] || { TERM=xterm-256color; unset TERMINFO; }; exec "$SHELL" -l'
fi

# Further launches (claude:// URLs) join the running sandbox, so Electron's single-instance lock finds the first instance
if pid=$(sandbox_pid); then
  exec "${env[@]}" "${nsenter[@]}" -t "$pid" "$FHS_ENV" "${args[@]}"
fi

# The app writes to this file too, so merge instead of symlinking a read-only store path
mkdir -p "$(dirname "$CONFIG")"
[[ -s $CONFIG ]] || echo '{}' >"$CONFIG"
jq --slurpfile m "$MCP_SERVERS" --argjson tray "$TRAY" \
  '.mcpServers = $m[0] | .preferences.menuBarEnabled = $tray' "$CONFIG" >"$CONFIG.tmp"
mv "$CONFIG.tmp" "$CONFIG"

"$STORE_SYNC"
# nixpak only passes bwrap the --*-bind-try variants, which skip a missing source
for src in "${REQUIRED_BINDS[@]}"; do
  [[ -e $src ]] || { echo "claude-desktop: Bind source $src is missing" >&2; exit 1; }
done

"$GTK_THEME" || true
# Double fork: the launcher this script execs into must not wait for it. It stops once that pid ($$) exits
("$GTK_THEME_WATCH" $$ </dev/null >/dev/null 2>&1 &)

exec env -i "${VARS[@]}" "$NIXPAK_LAUNCHER" "${args[@]}"
