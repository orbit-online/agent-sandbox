# shellcheck shell=bash
# The launcher on the host's PATH. $VARS: the sandbox's environment, filtered (see `vars` in default.nix)
: "${SANDBOX_HOME:?}" "${RESOLV_CONF:?}" "${APP_ID:?}" "${FHS_ENV:?}" "${CONFIG:?}" "${MCP_SERVERS:?}" "${TRAY:?}"
: "${STORE_SYNC:?}" "${GTK_THEME:?}" "${GTK_THEME_WATCH:?}" "${NIXPAK_LAUNCHER:?}"
mkdir -p "$SANDBOX_HOME/.config"
# Bind source for the sandbox's /etc/resolv.conf, filled in by the DHCP client
touch "$RESOLV_CONF"
# Without user-dirs.dirs, Chromium saves downloads to $HOME
# shellcheck disable=SC2016
echo 'XDG_DOWNLOAD_DIR="$HOME/Downloads"' >"$SANDBOX_HOME/.config/user-dirs.dirs"
args=(--password-store=basic "$@")

# Further launches (claude:// URLs) join the running sandbox, so Electron's single-instance lock finds
# the first instance. The mount ns check stops a stale info file with a recycled pid from pointing at a host process.
for d in "$XDG_RUNTIME_DIR"/.flatpak/nixpak-app-*; do
  grep -qxF "name=$APP_ID" "$d/info" 2>/dev/null || continue
  pid=$(grep -oP '"child-pid":\s*\K\d+' "$d/bwrapinfo.json" 2>/dev/null) || continue
  if [[ -e /proc/$pid/ns/mnt && ! /proc/$pid/ns/mnt -ef /proc/self/ns/mnt ]]; then
    # Not -a: that also joins the time ns, still the host's, which needs CAP_SYS_ADMIN in the init userns
    exec env -i "${VARS[@]}" DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/nixpak-bus" \
      nsenter -t "$pid" -U -m -p -n -i -u -C -r -w --preserve-credentials "$FHS_ENV" "${args[@]}"
  fi
done

# The app writes to this file too, so merge instead of symlinking a read-only store path
mkdir -p "$(dirname "$CONFIG")"
[[ -s $CONFIG ]] || echo '{}' >"$CONFIG"
jq --slurpfile m "$MCP_SERVERS" --argjson tray "$TRAY" \
  '.mcpServers = $m[0] | .preferences.menuBarEnabled = $tray' "$CONFIG" >"$CONFIG.tmp"
mv "$CONFIG.tmp" "$CONFIG"

"$STORE_SYNC"

"$GTK_THEME" || true
# Double fork: the launcher this script execs into must not wait for it. It stops once that pid ($$) exits
("$GTK_THEME_WATCH" $$ </dev/null >/dev/null 2>&1 &)

exec env -i "${VARS[@]}" "$NIXPAK_LAUNCHER" "${args[@]}"
