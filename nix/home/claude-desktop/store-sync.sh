# shellcheck shell=bash
# Copies the sandbox closure into its own store and roots it, when the root doesn't point at it yet. The store is the
# sandbox's to write, so Nix works on it only through claude-desktop-state ($STATE), confined to $STATE_DIR/nix; the
# stream it imports comes from the host's store
: "${STATE_DIR:?}" "${STORE_ROOTS:?}" "${STATE:?}"
mkdir -p "$STATE_DIR/nix"
# nixpak binds the store directory on its own, following a link there on the host. Nothing runs in the sandbox now
if [[ -L $STATE_DIR/nix/store ]]; then
  echo "claude-desktop: $STATE_DIR/nix/store is a link, which only the sandbox could have put there. Remove it" >&2
  exit 1
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
