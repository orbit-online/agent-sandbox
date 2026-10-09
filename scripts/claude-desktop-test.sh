#!/usr/bin/env bash
# Starts a second claude-desktop sandbox built from this checkout next to the running one. Run on the host.
# Usage: claude-desktop-test.sh [NIXOS_CONFIG]
#   NIXOS_CONFIG: a flake attribute holding a NixOS config's `config`, from a flake with an
#   agent-sandbox input. Defaults to the agent-sandbox specialisation of this host in nixos-workstation:
#   ~/Workspace/ops/nixos-workstation#nixosConfigurations.<hostname>.config.specialisation.agent-sandbox.configuration
set -euo pipefail

repo=$(git -C "$(dirname "$(readlink -f "$0")")" rev-parse --show-toplevel)
config=${1:-$HOME/Workspace/ops/nixos-workstation#nixosConfigurations.$(hostname).config.specialisation.agent-sandbox.configuration}

# The Home Manager profile, built with agent-sandbox overridden to this checkout
home_path=$(nix build --no-link --print-out-paths --override-input agent-sandbox "path:$repo" \
  "$config.home-manager.users.$USER.home.path")

# bin/claude-desktop is the module's wrapper. It would nsenter into the running sandbox,
# so take the nixpak launcher it calls instead, and do the wrapper's setup here
wrapper=$(readlink -f "$home_path/bin/claude-desktop")
launcher=$(grep -o '/nix/store/[^ ]*nixpak-claude-desktop[^/ ]*/bin/claude-desktop' "$wrapper" | head -1)
sync=$(grep -o '/nix/store/[^ ]*/bin/claude-desktop-store-sync' "$wrapper" | head -1)
[[ -n $launcher && -n $sync ]] || {
  echo "No nixpak launcher or store sync in $wrapper" >&2
  exit 1
}
echo "launcher: $launcher" >&2

# Bind source for the sandbox's /etc/resolv.conf
touch "$HOME/.local/share/claude-desktop/home/.config/resolv.conf"
# Shared with the running instance's store: this moves the GC root to the test closure until the next normal launch
"$sync"

# --password-store=basic: as the wrapper passes it.
# --user-data-dir: keeps Chromium's singleton socket away from the running instance's
# ~/.config/Claude; /tmp is the sandbox's own tmpfs, so this instance needs a fresh sign-in
exec "$launcher" --password-store=basic --user-data-dir=/tmp/claude-test
