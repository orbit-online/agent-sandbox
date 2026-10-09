# shellcheck shell=bash
# Collects the sandbox's Nix store when store-sync.sh left gc-pending (it moved the GC root) or the last run is a week
# old. Only inside the sandbox, whose store has store-sync.sh's root: on the host, nix-store --gc would collect the
# host's store. Another run holding the lock makes it a no-op (Nix would queue it on gc.lock instead)
dir=/nix/var/claude-desktop
[[ -L /nix/var/nix/gcroots/claude-desktop ]] ||
  { echo "claude-desktop-store-gc: Only runs inside the claude-desktop sandbox" >&2; exit 1; }
[[ -e $dir/gc-pending || -z $(find "$dir/gc-last" -mtime -7 2>/dev/null) ]] || exit 0
mkdir -p "$dir"
exec {fd}>"$dir/gc.lock"
flock -n "$fd" || exit 0
echo "$(date -Is): nix-store --gc"
nix-store --gc 2>&1 | { grep -v "^deleting '" || true; }
rm -f "$dir/gc-pending"
touch "$dir/gc-last"
