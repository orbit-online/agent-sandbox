# Where a launcher's feature modules meet: what each adds to the store roots, nixpak's config, the FHS env, the
# launcher's variables and its .desktop file, and the assertions. Internal: core.nix and launch.nix read them
{ lib, ... }:
let
  inherit (lib) mkOption types;
  internal =
    type:
    mkOption {
      inherit type;
      internal = true;
      visible = false;
    };
  list = type: internal (types.listOf type) // { default = [ ]; };
in
{
  options.build = {
    # Everything the sandbox runs from the store. nixpak's closure only covers the app and extraStorePaths, not env
    # values or bind sources, so they all go in here
    storeRoots = list types.package;
    # nixpak's config, beside core.nix's
    nixpak = list types.deferredModule;
    # Arguments of the FHS env's bwrap, before the files option's
    fhsBwrapArgs = list types.str;
    # Packages on the sandbox's /run/current-system/sw besides PATH's
    sw = list types.package;
    # The launcher's config (cmd/launcher/main.go), as JSON
    launcherConfig = internal (types.attrsOf types.anything) // {
      default = { };
    };
    # The .desktop file's actions after Shell, each the argument it runs the launcher with
    desktopActions = internal (types.attrsOf types.str) // {
      default = { };
    };
    assertions = list types.attrs;
    # Units of the sandbox's systemd --user (fhs.nix, app-pid.sh) by file name, each its text; a timer or path unit is
    # wanted by timers.target or paths.target
    userUnits = internal (types.attrsOf types.lines) // {
      default = { };
    };
    # Set by core.nix, fhs.nix and launch.nix: the devices bound (/dev/kvm with kvm, each once), the app in its FHS
    # env, nixpak's build, the confined state script and the launcher's package
    devices = internal (types.listOf types.str);
    # Where claude-desktop-state works (see core.nix)
    homeDirs = internal (types.listOf types.str);
    # What the sandbox's /etc takes from the host's
    etcEntries = internal (types.listOf types.str);
    app = internal types.package;
    sandboxed = internal types.raw;
    package = internal types.package;
    state = internal types.package;
  };
}
