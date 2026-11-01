# shellcheck shell=bash
# Copies the sandbox closure into its own store and roots it, when the root doesn't point at it yet. The store is the
# sandbox's to write, so Nix works on it only through claude-desktop-state ($STATE), confined to $STATE_DIR/nix; the
# stream it imports comes from the host's store
: "${STATE_DIR:?}" "${STORE_ROOTS:?}" "${STATE:?}" "${UNSHARE:?}"
# nixpak binds the store directory on its own, following a link there on the host. Nothing runs in the sandbox now
store=$STATE_DIR/nix/store
if [[ -L $store ]]; then
  echo "claude-desktop: $store is a link, which only the sandbox could have put there. Remove it" >&2
  exit 1
fi
# The store directory the sync made, by device and inode, kept where the sandbox can't write. The sandbox can rename a
# directory that is a mountpoint where it runs from a namespace of its own (models/README.md, S12) and put a directory
# of its own in its place, which a check for a link misses
id_file=$STATE_DIR/nix-store.id
if [[ -e $id_file ]]; then
  if [[ $(stat -c %d:%i "$store" 2>/dev/null) != "$(<"$id_file")" ]]; then
    echo "claude-desktop: $store isn't the store directory this launcher made: the sandbox replaced it (see" \
      "$STATE_DIR/nix for the original). Remove $id_file to have the next launch delete $STATE_DIR/nix and start" \
      "afresh" >&2
    exit 1
  fi
else
  # No record: an install from before the launcher kept one. Whatever store directory is there may be the sandbox's
  # own by now, so nix/ goes whole and the closure is copied into a fresh one: nothing else in it is the host's. As root
  # of a userns holding the user's subuids and subgids, so files a container in the sandbox made go too. Outside
  # confine.sh, whose userns maps the user alone; rm doesn't follow links, and the sandbox isn't running
  if [[ -e $STATE_DIR/nix || -L $STATE_DIR/nix ]]; then
    echo "claude-desktop: No record of the store directory this launcher made, so $STATE_DIR/nix is deleted and" \
      "the closure copied afresh" >&2
    "$UNSHARE" --map-auto --map-root-user rm -rf "$STATE_DIR/nix"
  fi
  # The record goes in before the first copy, so a sync that doesn't finish goes on in the same directory next time
  mkdir -p "$store"
  stat -c %d:%i "$store" >"$id_file.tmp"
  mv -f "$id_file.tmp" "$id_file"
fi
# Dependencies first, as the import needs them
paths=$(nix-store -qR "$STORE_ROOTS")
mapfile -t closure <<<"$paths"
out=$(printf '%s\n' "${closure[@]}" | "$STATE" "$STATE_DIR/nix" -- store-missing "$STORE_ROOTS")
[[ $out != current ]] || exit 0
# Only paths of the closure, in its order, whatever the sandbox's store answered
declare -A invalid=()
while read -r p; do [[ -z $p ]] || invalid[$p]=1; done <<<"${out#*$'\n'}"
missing=()
for p in "${closure[@]}"; do [[ -z ${invalid[$p]:-} ]] || missing+=("$p"); done
if ((${#missing[@]})); then
  echo "claude-desktop: Copying the sandbox closure to $STATE_DIR/nix" >&2
  nix-store --export "${missing[@]}" | "$STATE" "$STATE_DIR/nix" -- store-import "$STORE_ROOTS"
else
  "$STATE" "$STATE_DIR/nix" -- store-import "$STORE_ROOTS" none </dev/null
fi
