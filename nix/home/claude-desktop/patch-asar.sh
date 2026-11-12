# shellcheck shell=bash
# The app only persists its sign-in when safeStorage.isEncryptionAvailable(), which is false under
# --password-store=basic. Opting into Chromium's fixed v10 key makes it true.
# On Linux the app picks its white tray icon in dark mode, and before 5.1231 on GNOME always. Without the GNOME case it
# follows the colour scheme the sandbox's GTK theme tracks (gtk-theme.sh), live, so it suits a panel that changes with
# it. Apps from 5.1231 have no GNOME case (the picker's argument is a retry flag), so nothing to patch, as long as one
# file picks the icon by the colour scheme.
# The app's own notification backend (a native module, behind a gate that's on by default) talks to
# org.freedesktop.Notifications on the session bus, which the proxy doesn't let through: there the sandbox could replace
# or close any notification, the permissions broker's included. With its gate-and-probe condition false, the app keeps
# Electron's, libnotify, which NOTIFY_FORCE_PORTAL sends through the portal.
# Electron takes the windows' Wayland app ID and X11 WM_CLASS from package.json's desktopName alone (it sets
# CHROME_DESKTOP from it at startup), so the launcher's DESKTOP_NAME, its .desktop file, gives its windows that file's
# taskbar entry.
# The first time one of its windows is visible once its page loaded or when it's shown, the app prints $READY on
# stdout, where the launcher waits for it to end its splash and tell systemd the app is up. Not ready-to-show: that
# only fires for a window not shown yet, and the app shows its main window at creation. Not gated on isLoading(): a
# frame still loading inside the page keeps that true at did-finish-load, and nothing asks again. Written through
# stdout's write as it is at startup, whatever the app does to console later.
# With servers in $CHANNELS (JSON), channels.js delivers their notifications/claude/channel into Code sessions
: "${ASAR:?}" "${out:?}" "${DESKTOP_NAME:?}" "${READY:?}" "${CHANNELS:?}" "${CHANNELS_JS:?}"
asar extract "$ASAR" app
jq --arg d "$DESKTOP_NAME" '.desktopName = $d' app/package.json >package.json
mv package.json app/package.json
main=app/$(jq -er .main app/package.json)
sed -i '1s/^"use strict";/&require("electron").safeStorage.setUsePlainTextEncryption(true);/' "$main"
grep -q setUsePlainTextEncryption "$main"
ready="(()=>{let d=!1;const o=process.stdout.write.bind(process.stdout),r=w=>{d||w.isDestroyed()||!w.isVisible()||(d=!0,o($(jq -n --arg r "$READY" '$r')+String.fromCharCode(10)))};require(\"electron\").app.on(\"browser-window-created\",(e,w)=>{w.webContents.once(\"did-finish-load\",()=>r(w));w.on(\"show\",()=>r(w))})})();"
# Its JS holds no # or &, which sed would take as the delimiter or the match
sed -i "1s#^\"use strict\";#&$ready#" "$main"
grep -qF "$ready" "$main"
gnome='\|\|[A-Za-z0-9_$]+\(\)==="gnome"(\|\|[A-Za-z0-9_$.]+\.nativeTheme\.shouldUseDarkColors\?"TrayIconLinux-Dark\.png")'
mapfile -t files < <(grep -rlE --include='*.js' "$gnome" app)
if ((${#files[@]} > 0)); then
  ((${#files[@]} == 1)) || { echo "patch-asar: ${#files[@]} files pick the tray icon by GNOME, want 1" >&2; exit 1; }
  sed -i -E "s/$gnome/\1/" "${files[0]}"
  ! grep -qE "$gnome" "${files[0]}" || exit 1
else
  dark='[A-Za-z0-9_$.]+\.nativeTheme\.shouldUseDarkColors\?"TrayIconLinux-Dark\.png"'
  mapfile -t files < <(grep -rlE --include='*.js' "$dark" app)
  ((${#files[@]} == 1)) || { echo "patch-asar: ${#files[@]} files pick the tray icon by colour scheme, want 1" >&2; exit 1; }
fi
# Apps before that backend (by its telemetry name or its gate) have nothing to patch; one that has it must have exactly
# one such place
native='([A-Za-z0-9_$]+\([A-Za-z0-9_$]+,!0\)&&await ([A-Za-z0-9_$]+)\.probe\(\)&&\(this\.backend=\2\))'
if grep -rqE --include='*.js' 'telemetryName="freedesktop"|"1358149550"' app; then
  mapfile -t files < <(grep -rlE --include='*.js' "$native" app)
  ((${#files[@]} == 1)) || { echo "patch-asar: ${#files[@]} files pick a notification backend by probe, want 1" >&2; exit 1; }
  found=$(grep -oE "$native" "${files[0]}" | wc -l)
  ((found == 1)) || { echo "patch-asar: $found places pick a notification backend by probe, want 1" >&2; exit 1; }
  sed -i -E "s/$native/!1\&\&\1/" "${files[0]}"
  [[ $(grep -oE "!1&&$native" "${files[0]}" | wc -l) == 1 ]] || exit 1
fi
if [[ $CHANNELS != '[]' ]]; then
  # The session-side host's client for server \2 (clientInfo local-agent-mode-<name>), right before its roots handler
  # shellcheck disable=SC2016 # the JS template literal's ${...}
  hook='(name:`local-agent-mode-\$\{([A-Za-z0-9_$]+)\}`[^;]*\)),(([A-Za-z0-9_$]+)&&([A-Za-z0-9_$]+)\.setRequestHandler\("roots/list",)'
  mapfile -t files < <(grep -rlE --include='*.js' "$hook" app)
  ((${#files[@]} == 1)) || { echo "patch-asar: ${#files[@]} files make the sessions' MCP clients, want 1" >&2; exit 1; }
  found=$(grep -oE "$hook" "${files[0]}" | wc -l)
  ((found == 1)) || { echo "patch-asar: $found places make the sessions' MCP clients, want 1" >&2; exit 1; }
  # Where the app's tools get the session manager: its chunk and export
  manager='\{claudeCodeSessionManager:[A-Za-z0-9_$]+\}=await Promise\.resolve\(\)\.then\(\(\(\)=>require\("\./([A-Za-z0-9_.-]+\.js)"\)\)\)\.then\(\(([A-Za-z0-9_$]+)=>\2\.([A-Za-z0-9_$]+)\)\)'
  mapfile -t found < <(grep -rhoE --include='*.js' "$manager" app | sed -E "s#$manager#\1 \3#" | sort -u)
  ((${#found[@]} == 1)) || { echo "patch-asar: ${#found[@]} ways to the session manager, want 1" >&2; exit 1; }
  read -r chunk export <<<"${found[0]}"
  dir=$(dirname "${files[0]}")
  [[ -f $dir/$chunk ]] || { echo "patch-asar: the session manager's chunk isn't next to the MCP clients'" >&2; exit 1; }
  sed -e "s|@servers@|$CHANNELS|" -e "s|@chunk@|$chunk|g" -e "s|@export@|$export|" "$CHANNELS_JS" \
    >"$dir/agent-sandbox-channels.js"
  sed -i -E "s#$hook#\1,require(\"./agent-sandbox-channels.js\")(\5,\2),\3#" "${files[0]}"
  grep -qF 'require("./agent-sandbox-channels.js")(' "${files[0]}" || exit 1
fi
asar pack app app.asar --unpack '{*.node,github-mcp-server}'
# Bound at the original path, the patched asar reads the original app.asar.unpacked, so the lists must match
diff <(cd "$ASAR.unpacked" && find . -type f | sort) <(cd app.asar.unpacked && find . -type f | sort)
cp app.asar "$out"
