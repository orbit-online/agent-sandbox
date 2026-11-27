# shellcheck shell=bash
# What the host does in the sandbox's state dir and home, always confined by confine.sh (<sandbox>-state), so a
# link the sandbox planted there resolves to its own files or to nothing. Files are replaced through a temp file and a
# rename, which replaces a link rather than writing through it.
# $1: the command
#   home: the dirs, files and app config the sandbox expects, before a launch: the core's, then the app's (app_home,
#     which the module puts ahead of the script, with the app's variables)
#   store-missing ROOTS: reads the closure of ROOTS, one path a line; prints "current" if the store's GC root names
#     ROOTS already, else "stale" and the paths the store lacks
#   store-import ROOTS [none]: imports a nix-store --export stream from stdin (none: nothing to import) and roots ROOTS
#   theme SCHEME: the GTK theme for the portal's color-scheme (1 = dark)
#   resolv: stdin as the sandbox's resolv.conf (the launcher's dns.go)
: "${APP:?}" "${STATE_DIR:?}" "${SANDBOX_HOME:?}" "${RESOLV_CONF:?}" "${SCHEMA_DIR:?}"

# Stdin to file $1, replacing whatever is there
replace() {
  local tmp
  tmp=$(mktemp "$1.XXXXXX")
  cat >"$tmp"
  mv -fT "$tmp" "$1"
}

# File $1 through a command, for an app's config the app and the sandbox write too: the command ($3...) reads the
# file's content on stdin, or $2 where the file is missing or empty, and its output replaces the file only when it
# succeeded and wrote something. Otherwise (the file truncated, not the JSON the command takes) the file stays as it
# was, a warning goes to stderr, which the launcher logs, and merge returns 1 for the caller to skip what depends on it
merge() {
  local file=$1 default=$2 tmp
  shift 2
  tmp=$(mktemp "$file.XXXXXX")
  if if [[ -s $file ]]; then "$@" <"$file"; else "$@" <<<"$default"; fi >"$tmp" && [[ -s $tmp ]]; then
    mv -fT "$tmp" "$file"
  else
    rm -f "$tmp"
    echo "$APP-state: Left $file as it was: merging the sandbox's settings into it failed" >&2
    return 1
  fi
}

store="local?root=$STATE_DIR"
root=$STATE_DIR/nix/var/nix/gcroots/$APP
case ${1:?} in
home)
  mkdir -p "$SANDBOX_HOME/.config"
  # Without user-dirs.dirs, Chromium saves downloads to $HOME
  # shellcheck disable=SC2016
  echo 'XDG_DOWNLOAD_DIR="$HOME/Downloads"' | replace "$SANDBOX_HOME/.config/user-dirs.dirs"
  app_home
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
  mkdir -p "${root%/*}" "$STATE_DIR/nix/var/$APP"
  ln -sfn "${2:?}" "$root"
  # The old closure is garbage now; store-gc.sh collects it from inside the sandbox
  rm -f "$STATE_DIR/nix/var/$APP/gc-pending"
  : >"$STATE_DIR/nix/var/$APP/gc-pending"
  ;;
theme)
  GSETTINGS_BACKEND=keyfile XDG_CONFIG_HOME=$SANDBOX_HOME/.config GSETTINGS_SCHEMA_DIR=$SCHEMA_DIR \
    gsettings set org.gnome.desktop.interface gtk-theme "Adwaita$([[ ${2:-} == 1 ]] && echo -dark)"
  ;;
resolv)
  # Target of the sandbox's /etc/resolv.conf, written in place: Nix binds the file into fixed-output builds, a rename
  # would leave them on the old inode
  [[ -f $RESOLV_CONF && ! -L $RESOLV_CONF ]] || { rm -f "$RESOLV_CONF" && : >"$RESOLV_CONF"; }
  cat >"$RESOLV_CONF"
  ;;
*)
  echo "$APP-state: Unknown command $1" >&2
  exit 2
  ;;
esac
