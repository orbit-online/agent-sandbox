# Where a launcher's feature modules and its app's meet: what each adds to the store roots, nixpak's config, the FHS env,
# the launcher's variables and its .desktop file, and the assertions. Internal: core.nix and launch.nix read them
{
  lib,
  pkgs,
  config,
  ...
}:
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
    # The app's packages on the sandbox's PATH after the launcher's `path` (sl.sandboxPackagesOf)
    pathPackages = list types.package;
    # The app's part of the state script's home step (state.sh), bash run confined after the core's, with stateVars as
    # readonly variables and stateInputs on PATH
    stateHome = internal types.lines // {
      default = "";
    };
    stateVars = internal (types.attrsOf types.str) // {
      default = { };
    };
    stateInputs = list types.package;
    # Set by fhs.nix: what the core adds to the arguments of the app's buildFHSEnv, a function of them. The app builds
    # build.app with it, through sl.fhsAppOf or sl.fhsEnvOf
    fhsEnvArgs = internal (types.functionTo types.attrs);
    # The launcher's config (cmd/launcher/main.go), as JSON
    launcherConfig = internal (types.attrsOf types.anything) // {
      default = { };
    };
    # The .desktop file's actions after Shell, each the argument it runs the launcher with
    desktopActions = internal (types.attrsOf types.str) // {
      default = { };
    };
    assertions = list types.attrs;
    # The paths of the binds the core adds for itself (core.nix, store.nix)
    coreBinds = list types.str;
    # How the environment doc lists a bind (environment.nix), the bind with its path: whether at all, and what it says
    # besides rw or ro. By default the read-write ones and the user's read-only ones; the app may say more (Claude
    # Desktop: MCP)
    environmentBind = internal (types.functionTo (types.attrsOf types.anything)) // {
      default = b: {
        listed = b.rw || !lib.elem b.path config.build.coreBinds;
        tags = [ ];
      };
    };
    # Arguments the launcher puts ahead of the caller's on every start and re-entry of the app (Claude Desktop:
    # --password-store=basic, Chromium's)
    appArgs = list types.str;
    # Local MCP servers, by name, each a command, its args and env: the features' (the permissions broker's `permissions`
    # server) and the app's own. Every app hands them to the agents it runs, in whatever form they take them (Claude
    # Desktop: mcp.nix, its config's mcpServers); an app that doesn't leaves the broker's tools out of reach
    mcpServers = internal (types.attrsOf (pkgs.formats.json { }).type) // {
      default = { };
    };
    # Units of the sandbox's systemd --user (fhs.nix, app-pid.sh) by file name, each its text; a timer or path unit is
    # wanted by timers.target or paths.target
    userUnits = internal (types.attrsOf types.lines) // {
      default = { };
    };
    # Set by fhs.nix: those units as the directory the sandbox's systemd --user loads them from
    userUnitsDir = internal types.package;
    # Set by core.nix, the app and launch.nix: the devices bound (permissions.devices), the app in its FHS env (the
    # app's modules), nixpak's build, the confined state script and the launcher's package
    devices = internal (types.listOf types.str);
    # Where <sandbox>-state works (see core.nix), the sandbox's home and the app's
    homeDirs = list types.str;
    # What the sandbox's /etc takes from the host's
    etcEntries = internal (types.listOf types.str);
    app = internal types.package;
    sandboxed = internal types.raw;
    package = internal types.package;
    state = internal types.package;
  };
}
