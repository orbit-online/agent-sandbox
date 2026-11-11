# The sandbox's own single-user Nix store (lib.nix, nixConf): stateDir/nix bound at /nix, the store roots' closure
# copied in before every launch (store-sync.sh), and the maintenance scripts the user's hooks run
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
  # Run by the user's own hooks, see environment.md
  storeGc = sl.script "store-gc.sh" {
    name = "claude-desktop-store-gc";
    runtimeInputs = [
      osConfig.nix.package
      pkgs.coreutils
      pkgs.findutils
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
  storeSync = sl.script "store-sync.sh" {
    name = "claude-desktop-store-sync";
    runtimeInputs = [
      pkgs.coreutils
      osConfig.nix.package
    ];
    vars = {
      STATE_DIR = ids.stateDir;
      STORE_ROOTS = "${storeRoots}";
      STATE = lib.getExe config.build.state;
      UNSHARE = lib.getExe' pkgs.util-linux "unshare";
    };
    # unshare runs newuidmap and newgidmap from PATH
    prelude = "PATH=$PATH:${osConfig.security.wrapperDir}\n";
  };
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
  build.launcherVars = {
    STORE_SYNC = lib.getExe storeSync;
    STORE_ROOTS = "${storeRoots}";
    STORE_ROOTS_LINK = "store-roots${ids.suffix}";
  };
}
