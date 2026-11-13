# shellcheck shell=bash
# What the host does in the sandbox's state dir and home, always confined by confine.sh (claude-desktop-state), so a
# link the sandbox planted there resolves to its own files or to nothing. Files are replaced through a temp file and a
# rename, which replaces a link rather than writing through it.
# $1: the command
#   home: the dirs, files and app config the sandbox expects, before a launch
#   store-missing ROOTS: reads the closure of ROOTS, one path a line; prints "current" if the store's GC root names
#     ROOTS already, else "stale" and the paths the store lacks
#   store-import ROOTS [none]: imports a nix-store --export stream from stdin (none: nothing to import) and roots ROOTS
#   theme SCHEME: the GTK theme for the portal's color-scheme (1 = dark)
: "${STATE_DIR:?}" "${SANDBOX_HOME:?}" "${RESOLV_CONF:?}" "${NAMESERVERS?}" "${DOT_CLAUDE:?}" "${CONFIG:?}" "${MCP_SERVERS:?}" "${TRAY:?}"
: "${SCHEMA_DIR:?}"

# Stdin to file $1, replacing whatever is there
replace() {
  local tmp
  tmp=$(mktemp "$1.XXXXXX")
  cat >"$tmp"
  mv -fT "$tmp" "$1"
}

store="local?root=$STATE_DIR"
root=$STATE_DIR/nix/var/nix/gcroots/claude-desktop
case ${1:?} in
home)
  mkdir -p "$SANDBOX_HOME/.config" "$DOT_CLAUDE" "${CONFIG%/*}"
  # Target of the sandbox's /etc/resolv.conf, written in place: Nix binds the file into fixed-output builds, a rename
  # would leave them on the old inode
  [[ -f $RESOLV_CONF && ! -L $RESOLV_CONF ]] || { rm -f "$RESOLV_CONF" && : >"$RESOLV_CONF"; }
  for ns in $NAMESERVERS; do echo "nameserver $ns"; done >"$RESOLV_CONF"
  # Without user-dirs.dirs, Chromium saves downloads to $HOME
  # shellcheck disable=SC2016
  echo 'XDG_DOWNLOAD_DIR="$HOME/Downloads"' | replace "$SANDBOX_HOME/.config/user-dirs.dirs"
  # The app writes to this file too, so merge instead of symlinking a read-only store path
  config='{}'
  [[ ! -s $CONFIG ]] || config=$(<"$CONFIG")
  jq --slurpfile m "$MCP_SERVERS" --argjson tray "$TRAY" \
    '.mcpServers = $m[0] | .preferences.menuBarEnabled = $tray' <<<"$config" | replace "$CONFIG"
  ;;
store-missing)
  [[ $(readlink "$root" 2>/dev/null) != "${2:?}" ]] || { echo current; exit 0; }
  echo stale
  mapfile -t paths
  nix-store --store "$store" --check-validity --print-invalid "${paths[@]}"
  ;;
store-import)
  # Unsigned local builds (the app, the patched asar) are fine: the stream comes from the host's own store
  [[ ${3:-} == none ]] || nix-store --store "$store" --import >/dev/null
  mkdir -p "${root%/*}" "$STATE_DIR/nix/var/claude-desktop"
  ln -sfn "${2:?}" "$root"
  # The old closure is garbage now; store-gc.sh collects it from inside the sandbox
  rm -f "$STATE_DIR/nix/var/claude-desktop/gc-pending"
  : >"$STATE_DIR/nix/var/claude-desktop/gc-pending"
  ;;
theme)
  GSETTINGS_BACKEND=keyfile XDG_CONFIG_HOME=$SANDBOX_HOME/.config GSETTINGS_SCHEMA_DIR=$SCHEMA_DIR \
    gsettings set org.gnome.desktop.interface gtk-theme "Adwaita$([[ ${2:-} == 1 ]] && echo -dark)"
  ;;
*)
  echo "claude-desktop-state: Unknown command $1" >&2
  exit 2
  ;;
esac
