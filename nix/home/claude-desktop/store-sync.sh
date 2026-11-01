# shellcheck shell=bash
# Copies the sandbox closure into its own store and roots it, when the root doesn't point at it yet. The store is the
# sandbox's to write, so Nix works on it only through claude-desktop-state ($STATE), confined to $STATE_DIR/nix; the
# stream it imports comes from the host's store
: "${STATE_DIR:?}" "${STORE_ROOTS:?}" "${STATE:?}"
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
      "$STATE_DIR/nix for the original). Remove $STATE_DIR/nix and $id_file to start it afresh" >&2
    exit 1
  fi
elif [[ -e $STATE_DIR/nix ]]; then
  # No record: an install from before the launcher kept one, or a sync that didn't finish. Whatever store directory
  # is there may be the sandbox's own by now, so it isn't trusted: nix/ goes aside whole (its database describes that
  # store), and the closure is copied into a fresh one
  aside=$("$STATE" "$STATE_DIR" -- store-quarantine)
  if [[ -n $aside ]]; then
    echo "claude-desktop: No record of the store directory this launcher made, so $STATE_DIR/nix is set aside as" \
      "$aside and the closure copied afresh. Remove $aside once you've looked" >&2
  fi
fi
mkdir -p "$STATE_DIR/nix"
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
[[ -e $id_file ]] || stat -c %d:%i "$store" >"$id_file"
