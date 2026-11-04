# shellcheck shell=bash
# The app's unit, claude-desktop[-<name>]-app.service in the launcher's slice, which claude-desktop.sh starts with
# its caller's environment and its cgroup delegated. This runs in its supervisor/ cgroup, see bwrap-subid.sh. $VARS: the sandbox's environment, filtered from that (see `vars` in default.nix). nixpak's
# launcher runs in this process, so the unit's main pid is the sandbox's and the unit ends with it
: "${GTK_THEME_WATCH:?}" "${NIXPAK_LAUNCHER:?}"

# Double fork: the launcher this script execs into must not wait for it. It stops once that pid ($$) exits
("$GTK_THEME_WATCH" $$ </dev/null >/dev/null 2>&1 &)

exec env -i "${VARS[@]}" "$NIXPAK_LAUNCHER" --password-store=basic "$@"
