# shellcheck shell=bash
# The app only persists its sign-in when safeStorage.isEncryptionAvailable(), which is false under
# --password-store=basic. Opting into Chromium's fixed v10 key makes it true
: "${ASAR:?}" "${out:?}"
asar extract "$ASAR" app
main=app/$(jq -er .main app/package.json)
sed -i '1s/^"use strict";/&require("electron").safeStorage.setUsePlainTextEncryption(true);/' "$main"
grep -q setUsePlainTextEncryption "$main"
asar pack app app.asar --unpack '{*.node,github-mcp-server}'
# Bound at the original path, the patched asar reads the original app.asar.unpacked, so the lists must match
diff <(cd "$ASAR.unpacked" && find . -type f | sort) <(cd app.asar.unpacked && find . -type f | sort)
cp app.asar "$out"
