# shellcheck shell=bash
# The app only persists its sign-in when safeStorage.isEncryptionAvailable(), which is false under
# --password-store=basic. Opting into Chromium's fixed v10 key makes it true.
# On Linux the app picks its white tray icon in dark mode, and on GNOME always. Without the GNOME case it follows the
# colour scheme the sandbox's GTK theme tracks (gtk-theme.sh), live, so it suits a panel that changes with it.
# The app's own notification backend (a native module, behind a gate that's on by default) talks to
# org.freedesktop.Notifications on the session bus, which the proxy doesn't let through: there the sandbox could replace
# or close any notification, the permissions broker's included. With its gate-and-probe condition false, the app keeps
# Electron's, libnotify, which NOTIFY_FORCE_PORTAL sends through the portal.
# Electron takes the windows' Wayland app ID and X11 WM_CLASS from package.json's desktopName alone (it sets
# CHROME_DESKTOP from it at startup), so the launcher's DESKTOP_NAME, its .desktop file, gives its windows that file's
# taskbar entry.
# Once its first window is ready to show, the app prints $READY on stdout, where the launcher waits for it to end its
# splash and tell systemd the app is up
: "${ASAR:?}" "${out:?}" "${DESKTOP_NAME:?}" "${READY:?}"
asar extract "$ASAR" app
jq --arg d "$DESKTOP_NAME" '.desktopName = $d' app/package.json >package.json
mv package.json app/package.json
main=app/$(jq -er .main app/package.json)
sed -i '1s/^"use strict";/&require("electron").safeStorage.setUsePlainTextEncryption(true);/' "$main"
grep -q setUsePlainTextEncryption "$main"
ready="require(\"electron\").app.once(\"browser-window-created\",(e,w)=>w.once(\"ready-to-show\",()=>console.log($(jq -n --arg r "$READY" '$r'))));"
sed -i "1s|^\"use strict\";|&$ready|" "$main"
grep -qF "$ready" "$main"
gnome='\|\|[A-Za-z0-9_$]+\(\)==="gnome"(\|\|[A-Za-z0-9_$.]+\.nativeTheme\.shouldUseDarkColors\?"TrayIconLinux-Dark\.png")'
mapfile -t files < <(grep -rlE --include='*.js' "$gnome" app)
((${#files[@]} == 1)) || { echo "patch-asar: ${#files[@]} files pick the tray icon by GNOME, want 1" >&2; exit 1; }
sed -i -E "s/$gnome/\1/" "${files[0]}"
! grep -qE "$gnome" "${files[0]}" || exit 1
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
asar pack app app.asar --unpack '{*.node,github-mcp-server}'
# Bound at the original path, the patched asar reads the original app.asar.unpacked, so the lists must match
diff <(cd "$ASAR.unpacked" && find . -type f | sort) <(cd app.asar.unpacked && find . -type f | sort)
cp app.asar "$out"
