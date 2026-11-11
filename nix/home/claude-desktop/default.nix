# Namespaces of the sandbox. U1 maps the user's /etc/subuid and /etc/subgid range, inner id x as host start+x, except
# the user's own uid and gid (1000 and 100 below), which stay themselves: everything the app writes to host paths is
# the user's. U2 maps all of U1's ids as themselves. bwrap-subid.sh writes both maps.
#
# init userns (host)
# │  runs: nixpak launcher, dbus-proxy (in a bwrap of nixpak's), the pasta-slot script (netSetup), bwrap's parent,
# │        netns-macvlan (cap_net_admin, creates eth0 in N), subid-broker (writes maps below U1 on request)
# │
# └─ U1  bwrap's userns (0-999 → start+0-999, 1000 → 1000, 1001-65535 → start+1001-65535)
#    │  owns: N (netns: lo + eth0 macvlan), M1 (sandbox mount tree), MU (udhcpc's mount tree, made from the
#    │        host's: its closure, /proc and the sandbox's home), P (pid ns), ipc, uts, cgroup (rooted at sandbox/ in
#    │        the app's unit's delegated cgroup, see bwrap-subid.sh)
#    │  runs (in N, M1, P): bwrap's init and the FHS env script as uid 1000 without capabilities
#    │       (in N, MU, P): udhcpc + dhcpScript (net_admin and net_raw only)
#    │       (in N and the host's mount ns): netSetup's ip calls; the permissions broker's helpers, which join M1
#    │        only after their exec
#    │
#    └─ U2  buildFHSEnv's bwrap (all of U1's ids)
#          owns: M2 (tmpfs /etc with the rootfs' resolv.conf and hosts links, subuid and subgid, patched app.asar),
#                P2 (pid ns, where app-pid.sh starts the app at a pid of the launcher's, with CAP_CHECKPOINT_RESTORE)
#          runs (in N, M2, P2): Claude Desktop, Code tab shells, the local MCP servers, `claude-desktop --shell`,
#                claude:// re-entry, and the user namespaces they create, whose maps the newuidmap and newgidmap
#                shims ask subid-broker for
#
# Each launcher, the default one (agent-sandbox.claude-desktop) and each of launchers.<name>, is a submodule of the
# feature modules below, which meet in its internal `build` options (build.nix). A module in launcherModules joins
# them on every launcher
{ inputs }:
{
  pkgs,
  lib,
  config,
  options,
  osConfig,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.agent-sandbox.claude-desktop;
  sl = import ./lib.nix {
    inherit
      inputs
      pkgs
      lib
      osConfig
      ;
    hm = config;
  };
  launcherModules = [
    ./build.nix
    ./options.nix
    ./core.nix
    ./fhs.nix
    ./environment.nix
    ./network.nix
    ./store.nix
    ./theme.nix
    ./mcp.nix
    ./dbus.nix
    ./permissions.nix
    ./request-send.nix
    ./launch.nix
  ]
  ++ config.agent-sandbox.launcherModules;
  specialArgs = {
    inherit
      inputs
      pkgs
      osConfig
      sl
      ;
    hm = config;
    hmOptions = options;
  };
  # The launchers, the default one first
  launchers = [ cfg ] ++ lib.attrValues cfg.launchers;
in
{
  options.agent-sandbox = {
    launcherModules = mkOption {
      type = types.listOf types.deferredModule;
      default = [ ];
      description = ''
        Modules added to every launcher, the default one and each of `agent-sandbox.claude-desktop.launchers`, for
        options of their own next to the launcher's: `permissions.commands` from a plugin's settings, for one.
        Their arguments: the launcher's `config`, `launcherName` (null for the default launcher), Home Manager's
        config as `hm`, `pkgs` and `osConfig`.
      '';
    };
    claude-desktop = mkOption {
      type = types.submoduleWith {
        inherit specialArgs;
        modules = launcherModules ++ [
          {
            config._module.args.launcherName = null;
            options = {
              enable = lib.mkEnableOption "Claude Desktop, sandboxed with nixpak";
              launchers = mkOption {
                type = types.attrsOf (
                  types.submoduleWith {
                    inherit specialArgs;
                    modules = launcherModules ++ [ ({ name, ... }: { _module.args.launcherName = name; }) ];
                  }
                );
                default = { };
                example = lib.literalExpression ''{ work.binds."''${config.home.homeDirectory}/Workspace/work".rw = true; }'';
                description = ''
                  More sandboxes next to the default one, which is always there. Each has the same options, starts from the
                  module's defaults rather than the default launcher's settings, and keeps its state in
                  `~/.local/share/claude-desktop-<name>`: its own home (`~/.claude` and `~/.config/Claude` included, unless bound),
                  Nix store and scratchpads. It runs as `claude-desktop-<name>`, shows as "Claude (<name>)", and leaves the
                  `claude://` handler to the default launcher.
                '';
              };
            };
          }
        ];
      };
      default = { };
      description = "Claude Desktop, sandboxed: the default launcher's settings, and more launchers in `launchers`.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = osConfig.hardware.graphics.enable;
        message = "agent-sandbox.claude-desktop: the sandbox uses the host's graphics drivers, but hardware.graphics.enable is off on this machine. Enable it there if this is a desktop; the module doesn't, so it never pulls a graphics stack onto a server.";
      }
    ]
    ++ lib.mapAttrsToList (name: s: {
      assertion =
        s.command or null != null
        && !lib.elem name [
          "filesystem"
          "claude-code"
        ];
      message = "agent-sandbox.claude-desktop: programs.mcp.servers.${name} must be a local server (command) and not named filesystem or claude-code, which are the sandbox's own";
    }) sl.hmMcpServers
    ++ lib.concatMap (l: l.build.assertions) launchers;
    home.packages = map (l: l.build.package) launchers;
    # The sandbox's store right after memo's embedded ones (mkOrder 550, ahead of the default), by its store path, so
    # memo on the host answers as it does inside
    programs = lib.optionalAttrs (options ? programs.agent-memos) {
      agent-memos.settings.stores = lib.mkIf (lib.any (l: l.memo.enable) launchers) (
        lib.mkOrder 550 [ "${sl.environment}/environment.memo" ]
      );
    };
  };
}
