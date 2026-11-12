# shellcheck shell=bash
# Collects the sandbox's Nix store, run by the sandbox's systemd --user weekly and when the launcher left gc-pending
# (it moved the GC root), which it removes. Only inside the sandbox, whose store has the launcher's root: on the host,
# nix-store --gc would collect the host's store. Another run holding the lock makes it a no-op (Nix would queue it on
# gc.lock instead)
dir=/nix/var/claude-desktop
[[ -L /nix/var/nix/gcroots/claude-desktop ]] ||
  { echo "claude-desktop-store-gc: Only runs inside the claude-desktop sandbox" >&2; exit 1; }
mkdir -p "$dir"
exec {fd}>"$dir/gc.lock"
flock -n "$fd" || exit 0
echo "$(date -Is): nix-store --gc"
nix-store --gc 2>&1 | { grep -v "^deleting '" || true; }
rm -f "$dir/gc-pending"
