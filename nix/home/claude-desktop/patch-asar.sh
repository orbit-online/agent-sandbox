# shellcheck shell=bash
# The app only persists its sign-in when safeStorage.isEncryptionAvailable(), which is false under
# --password-store=basic. Opting into Chromium's fixed v10 key makes it true.
# On Linux the app picks its white tray icon in dark mode, and on GNOME always. Without the GNOME case it follows the
# colour scheme the sandbox's GTK theme tracks (gtk-theme.sh), live, so it suits a panel that changes with it
: "${ASAR:?}" "${out:?}"
asar extract "$ASAR" app
main=app/$(jq -er .main app/package.json)
sed -i '1s/^"use strict";/&require("electron").safeStorage.setUsePlainTextEncryption(true);/' "$main"
grep -q setUsePlainTextEncryption "$main"
gnome='\|\|[A-Za-z0-9_$]+\(\)==="gnome"(\|\|[A-Za-z0-9_$.]+\.nativeTheme\.shouldUseDarkColors\?"TrayIconLinux-Dark\.png")'
mapfile -t files < <(grep -rlE --include='*.js' "$gnome" app)
((${#files[@]} == 1)) || { echo "patch-asar: ${#files[@]} files pick the tray icon by GNOME, want 1" >&2; exit 1; }
sed -i -E "s/$gnome/\1/" "${files[0]}"
! grep -qE "$gnome" "${files[0]}" || exit 1
asar pack app app.asar --unpack '{*.node,github-mcp-server}'
# Bound at the original path, the patched asar reads the original app.asar.unpacked, so the lists must match
diff <(cd "$ASAR.unpacked" && find . -type f | sort) <(cd app.asar.unpacked && find . -type f | sort)
cp app.asar "$out"
