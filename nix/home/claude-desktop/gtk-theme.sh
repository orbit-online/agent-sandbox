# shellcheck shell=bash
# Electron takes light/dark from GTK, not the portal (electron/electron#25925), and GTK only follows GSettings live.
# Mirrors the portal's color-scheme into the sandbox's GSettings keyfile as the GTK theme. The keyfile only works
# because buildFHSEnv's inner bwrap keeps nixpak's /.flatpak-info out of the FHS root; GTK3 would otherwise read the
# theme from the portal's org.gnome.* settings, which KDE leaves empty. The keyfile is in the sandbox's home, written
# through claude-desktop-state ($STATE) while the sandbox runs.
# $1: the portal's color-scheme (1 = dark), read from the portal when omitted
: "${STATE:?}" "${SANDBOX_HOME:?}"
scheme=${1:-}
if [[ -z $scheme && $(gdbus call --session --dest org.freedesktop.portal.Desktop \
  --object-path /org/freedesktop/portal/desktop --method org.freedesktop.portal.Settings.ReadOne \
  org.freedesktop.appearance color-scheme) =~ uint32\ ([0-9]+) ]]; then
  scheme=${BASH_REMATCH[1]}
fi
"$STATE" "$SANDBOX_HOME" -- theme "$scheme"
