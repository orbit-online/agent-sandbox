# The sandbox's own single-user Nix store (lib.nix, nixConf): stateDir/nix bound at /nix, the store roots' closure
# copied in before every launch (cmd/launcher/store.go), and the maintenance the sandbox's systemd --user runs
{
  lib,
  pkgs,
  osConfig,
  config,
  sl,
  launcherName,
  ...
}:
let
  ids = sl.idsOf launcherName;
  sys = {
    mcp = false;
  };
  # Run by the sandbox's systemd --user (userUnits below), see environment.md
  storeGc = sl.script "store-gc.sh" {
    name = "claude-desktop-store-gc";
    runtimeInputs = [
      osConfig.nix.package
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.util-linux
    ];
  };
  scratchpadPrune = sl.script "scratchpad-prune.sh" {
    name = "claude-desktop-scratchpad-prune";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.findutils
    ];
  };
  # nixpak --ro-binds every closure path, and bwrap won't mount onto the symlink a symlink store path already is in the
  # store, so those fail the build here
  storeRoots =
    let
      roots = config.build.storeRoots;
    in
    pkgs.runCommand "claude-desktop-store-roots" { closure = pkgs.closureInfo { rootPaths = roots; }; }
      ''
        while read -r p; do
          [[ ! -L $p ]] || { echo "$p is a symlink, nixpak can't bind it over the sandbox store's copy" >&2; exit 1; }
        done <"$closure/store-paths"
        printf '%s\n' ${lib.escapeShellArgs roots} >$out
      '';
in
{
  env.NIX_CONF_DIR = "${sl.nixConf}";
  binds = {
    "/nix" = sys // {
      src = "${ids.stateDir}/nix";
      rw = true;
    };
    # On its own, so the sandbox can't rename it: host-side processes that join its mount namespace run binaries
    # from the closure's binds in it
    "/nix/store" = sys // {
      src = "${ids.stateDir}/nix/store";
      rw = true;
    };
  };
  build.storeRoots = [ sl.nixConf ];
  build.sw = [
    storeGc
    scratchpadPrune
  ];
  build.nixpak = [ { bubblewrap.extraStorePaths = [ storeRoots ]; } ];
  # Weekly and when the launcher moved the GC root (gc-pending, which the script removes), and the prune daily, each
  # caught up at the next start when the sandbox wasn't running
  build.userUnits = {
    "claude-desktop-store-gc.service" = ''
      [Unit]
      Description=Collect the sandbox's Nix store
      [Service]
      Type=oneshot
      ExecStart=${lib.getExe storeGc}
    '';
    "claude-desktop-store-gc.timer" = ''
      [Timer]
      OnCalendar=weekly
      Persistent=true
    '';
    "claude-desktop-store-gc.path" = ''
      [Path]
      PathExists=/nix/var/claude-desktop/gc-pending
    '';
    "claude-desktop-scratchpad-prune.service" = ''
      [Unit]
      Description=Prune Claude Code's session scratchpads
      [Service]
      Type=oneshot
      ExecStart=${lib.getExe scratchpadPrune}
    '';
    "claude-desktop-scratchpad-prune.timer" = ''
      [Timer]
      OnCalendar=daily
      Persistent=true
    '';
  };
  build.launcherConfig = {
    storeRoots = "${storeRoots}";
    storeRootsLink = "store-roots${ids.suffix}";
  };
}
