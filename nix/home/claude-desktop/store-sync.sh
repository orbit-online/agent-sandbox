# shellcheck shell=bash
# Copies the sandbox closure into its own store and roots it, when the root doesn't point at it yet
: "${STATE_DIR:?}" "${STORE_ROOTS:?}"
root=$STATE_DIR/nix/var/nix/gcroots/claude-desktop
[[ $(readlink "$root" 2>/dev/null) == "$STORE_ROOTS" ]] && exit 0
echo "claude-desktop: Copying the sandbox closure to $STATE_DIR/nix" >&2
# Unsigned local builds (the app, the patched asar) are fine: the source is the host's own store
nix --extra-experimental-features nix-command copy --no-check-sigs \
  --to "local?root=$STATE_DIR" "$STORE_ROOTS"
ln -sfn "$STORE_ROOTS" "$root"
# The old closure is garbage now; ~/.claude/libexec/store-gc collects it from inside the sandbox
mkdir -p "$STATE_DIR/nix/var/claude-desktop"
touch "$STATE_DIR/nix/var/claude-desktop/gc-pending"
