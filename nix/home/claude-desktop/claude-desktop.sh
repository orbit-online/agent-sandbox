# shellcheck shell=bash
# The launcher on the host's PATH. $VARS: the sandbox's environment, filtered (see `vars` in default.nix).
# $REQUIRED_BINDS: the sources of the binds that aren't optional. $HOME_DIRS: where the sandbox's home, ~/.claude and
# ~/.config/Claude are on the host, the directories claude-desktop-state ($STATE) works in
: "${SCRATCHPAD:?}" "${APP_ID:?}" "${APP_PID:?}" "${SETPRIV:?}" "${STATE:?}"
: "${PERMISSIONS_CONFIG?}" "${PERMISSIONS_DIR?}" "${PERMISSIONS_UNIT?}" "${PERMISSIONS_BROKER:?}" "${PERMISSIONS_WINDOW:?}" "${PERMISSIONS_TITLE:?}"
: "${STORE_SYNC:?}" "${STORE_ROOTS:?}" "${STORE_ROOTS_LINK:?}" "${GTK_THEME:?}" "${GTK_THEME_WATCH:?}" "${NIXPAK_LAUNCHER:?}"
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

# The app's main process: the one at $APP_PID in the FHS env's pid ns, one level below the sandbox's (see app-pid.sh).
# The level counts: the sandbox can put a process at $APP_PID in a pid ns of its own further down, nearer to pid 1 in
# the tree than the app. Two at that level (a pid ns it made next to the FHS env's) leave the app unknown: status 2.
# Re-entries come in through nsenter, so they aren't pid 1's descendants
app_pid() {
  local queue=("$1") p children nspid found=() level
  read -ra nspid < <(grep -m1 '^NSpid:' "/proc/$1/status") || return 1
  level=$((${#nspid[@]} + 1))
  while ((${#queue[@]})); do
    p=${queue[0]} queue=("${queue[@]:1}")
    read -ra nspid < <(grep -m1 '^NSpid:' "/proc/$p/status" 2>/dev/null) || continue
    ((${#nspid[@]} != level)) || [[ ${nspid[-1]} != "$APP_PID" ]] || found+=("$p")
    read -ra children <"/proc/$p/task/$p/children" 2>/dev/null || true
    queue+=("${children[@]}")
  done
  if ((${#found[@]} > 1)); then
    echo "claude-desktop: Several processes in the sandbox sit at the app's pid $APP_PID: ${found[*]}" >&2
    return 2
  fi
  ((${#found[@]} == 1)) && echo "${found[0]}"
}

env=(env -i "${VARS[@]}" DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/nixpak-bus")
# Not -a: that also joins the time ns, still the host's, which needs CAP_SYS_ADMIN in the init userns. no_new_privs
# first, on the host, as bwrap sets it for everything inside: nsenter holds every capability in U2 until it execs a
# path the sandbox controls, whose file capabilities would otherwise count
nsenter=("$SETPRIV" --no-new-privs nsenter -U -m -p -n -i -u -C -r -w --preserve-credentials)

# --permissions (the .desktop file's action with the broker): the Permissions window, on the host. Ahead of the
# running sandbox's lookup, which would hand the flag to the app
if [[ ${1:-} == --permissions ]]; then
  [[ -n $PERMISSIONS_CONFIG ]] || { echo "claude-desktop: This launcher has no permissions broker" >&2; exit 1; }
  exec "$PERMISSIONS_WINDOW" "$XDG_RUNTIME_DIR/claude-desktop/$PERMISSIONS_DIR-control.sock" "$PERMISSIONS_TITLE"
fi

# --shell (the .desktop file's terminal action): a login shell where the app runs, so it gets the Code tab's environment
if [[ ${1:-} == --shell ]]; then
  if pid=$(sandbox_pid); then
    app=$(app_pid "$pid") || { (($? != 2)) || exit 1; }
  fi
  if [[ -z ${app:-} ]]; then
    echo "Starting Claude"
    # As a unit of its own: run from the terminal, the app would stop with the terminal's unit
    systemd-run --user --collect --quiet -- "$(readlink -f "$0")"
    for ((i = 0; i < 300; i++)); do
      if pid=$(sandbox_pid); then
        app=$(app_pid "$pid") && break
        (($? != 2)) || exit 1
      fi
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

# Further launches (claude:// URLs) join the running app's namespaces, its pid ns included, so Electron's
# single-instance lock finds the first instance and checks its pid where it lives. /init is the FHS env's, which the
# FHS env's bwrap would otherwise run
if pid=$(sandbox_pid); then
  for ((i = 0; i < 30; i++)); do
    app=$(app_pid "$pid") && break
    (($? != 2)) || exit 1
    sleep 1
  done
  [[ -n ${app:-} ]] || { echo "claude-desktop: The running sandbox has no app" >&2; exit 1; }
  exec "${env[@]}" "${nsenter[@]}" -t "$app" /init "${args[@]}"
fi

# The sandbox can write its home and plant links there, so the files it expects (resolv.conf, user-dirs.dirs, the app's
# config) are written confined, see confine.sh. The directories themselves are bind sources, on paths it can't write
mkdir -p "${HOME_DIRS[@]}"
# Bind source for Claude Code's temp dir, which it wants private. Its parent, the state dir, exists from the home's mkdir
[[ -d $SCRATCHPAD ]] || mkdir -m 700 "$SCRATCHPAD"
"$STATE" "${HOME_DIRS[@]}" -- home

"$STORE_SYNC"
# nixpak binds the closure from the host store, where a GC would empty it under the running sandbox once a rebuild
# dropped its generation. The runtime dir goes at logout, the next launch replaces the root
mkdir -p "$XDG_RUNTIME_DIR/claude-desktop"
nix-store --add-root "$XDG_RUNTIME_DIR/claude-desktop/$STORE_ROOTS_LINK" --realise "$STORE_ROOTS" >/dev/null
# nixpak only passes bwrap the --*-bind-try variants, which skip a missing source
for src in "${REQUIRED_BINDS[@]}"; do
  [[ -e $src ]] || { echo "claude-desktop: Bind source $src is missing" >&2; exit 1; }
done

# The permissions broker, a unit of its own that finds the sandbox once it runs (docs/permissions.md)
if [[ -n $PERMISSIONS_CONFIG ]]; then
  mkdir -p "$XDG_RUNTIME_DIR/claude-desktop/$PERMISSIONS_DIR"
  systemctl --user -q is-active "$PERMISSIONS_UNIT" ||
    # ExecStopPost ends its grants when it stops, a crash included: service units are bound to it, folder grants
    # are detached. It fails when it finds no sandbox within a minute: the start limit ends the restarts then
    systemd-run --user --quiet --collect --unit="$PERMISSIONS_UNIT" -p Restart=on-failure \
      -p StartLimitIntervalSec=10min -p StartLimitBurst=3 \
      -p ExecStopPost="$PERMISSIONS_BROKER cleanup $PERMISSIONS_CONFIG" -- \
      "$PERMISSIONS_BROKER" serve "$PERMISSIONS_CONFIG"
fi

"$GTK_THEME" || true
# Double fork: the launcher this script execs into must not wait for it. It stops once that pid ($$) exits
("$GTK_THEME_WATCH" $$ </dev/null >/dev/null 2>&1 &)

exec env -i "${VARS[@]}" "$NIXPAK_LAUNCHER" "${args[@]}"
