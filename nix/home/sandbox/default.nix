# Namespaces of the sandbox. U1 maps the user's /etc/subuid and /etc/subgid range, inner id x as host start+x, except
# the user's own uid and gid (1000 and 100 below), which stay themselves: everything the app writes to host paths is
# the user's. U2 maps all of U1's ids as themselves. The launcher's bwrap (cmd/launcher bwrap.go) writes both maps.
#
# init userns (host)
# │  runs: the launcher's supervise (the app's unit), nixpak launcher, dbus-proxy (in a bwrap of nixpak's), bwrap's
# │        parent, the launcher's bwrap helper (U1's maps, the cgroups, the netns), netns-netkit (cap_net_admin and
# │        cap_bpf, setgid sandbox-uplink: creates the netkit pair, its primary here and eth0 in N, and attaches its
# │        programs), subid-broker (writes maps below U1 on request; a unit of its own); system services shared by
# │        every launcher: sandbox-einat (NAT on the uplinks) and sandbox-uplink (the programs around it,
# │        nix/nixos/network.nix)
# │
# └─ U1  bwrap's userns (0-999 → start+0-999, 1000 → 1000, 1001-65535 → start+1001-65535)
#    │  owns: N (netns: lo + eth0, the netkit peer; lo alone with permissions.network.enable off), M1 (sandbox mount
#    │        tree), P (pid ns), ipc, uts, cgroup (rooted at sandbox/ in the app's unit's delegated cgroup, see
#    │        cmd/launcher bwrap.go)
#    │  runs (in N, M1, P): bwrap's init and the FHS env script as uid 1000 without capabilities
#    │       (in N and the host's mount ns): the bwrap helper's ip call; the permissions broker's helpers, which join M1
#    │        only after their exec
#    │
#    └─ U2  buildFHSEnv's bwrap (all of U1's ids)
#          owns: M2 (tmpfs /etc with the rootfs' resolv.conf and hosts links, subuid and subgid, patched app.asar),
#                P2 (pid ns, where app-pid.sh sets the app's pid, one of the launcher's, with CAP_CHECKPOINT_RESTORE,
#                which it drops before app-run.sh starts the app there)
#          runs (in N, M2, P2): the app (Claude Desktop: its Code tab shells and local MCP servers too), `<app> --shell`,
#                the app's URL handler re-entry (claude://), and the user namespaces they create, whose maps the
#                newuidmap and newgidmap shims ask subid-broker for
#
# The core of every app's sandbox: a function of the app's descriptor (its fields below,
# nix/home/claude-desktop/default.nix for one) to the app's Home Manager module, `agent-sandbox.<app>`. Each launcher
# of the app, the default one (agent-sandbox.<app>) and each of launchers.<name>, is a submodule of the feature modules
# below and the app's own, which meet in its internal `build` options (build.nix). A module in launcherModules
# (shared.nix) joins them on every launcher of every app
#
# The descriptor:
#   name             the option's name and the base of every name of its sandboxes, <name>[-<launcher>] (lib.nix, idsOf)
#   appId            the D-Bus app ID of its default launcher; a named launcher's is <appId>.<launcher>
#   displayName      what the user sees it called: the splash, a named launcher's .desktop Name, the Permissions window
#   agent            what the broker calls the agent in its words ("<agent> wants to …")
#   description      the enable option's text and the environment memo store's
#   environmentPath  where the sandbox's doc is bound for the agent (environment.nix)
#   environment      the app's part of the doc, with `<!-- agent-sandbox: core -->` where the core's goes
#   modules          the app's launcher modules: they set build.app, the app in its FHS env (fhs.nix, build.fhsEnvArgs),
#                    which prints sl.readyLine on stdout once its first window shows
#   assertions       optional, a function of { lib, sl, config } to assertions on the app's Home Manager config beside
#                    its launchers' (config: Home Manager's)

{ inputs }:
app:
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
  cfg = config.agent-sandbox.${app.name};
  sl = import ./lib.nix {
    inherit
      inputs
      pkgs
      lib
      osConfig
      app
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
    ./dbus.nix
    ./permissions.nix
    ./features.nix
    ./request-send.nix
    ./launch.nix
  ]
  ++ app.modules
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
  imports = [ ./shared.nix ];
  options.agent-sandbox.${app.name} = mkOption {
    # shorthandOnlyDefinesConfig as types.submodule sets it, here and on launchers: consumers extend both options
    # with types.submodule, and the module system refuses to merge submodules that disagree on it
    type = types.submoduleWith {
      inherit specialArgs;
      shorthandOnlyDefinesConfig = true;
      modules = launcherModules ++ [
        {
          config._module.args.launcherName = null;
          options = {
            enable = lib.mkEnableOption "${app.description}, sandboxed with nixpak";
            launchers = mkOption {
              type = types.attrsOf (
                types.submoduleWith {
                  inherit specialArgs;
                  shorthandOnlyDefinesConfig = true;
                  modules = launcherModules ++ [ ({ name, ... }: { _module.args.launcherName = name; }) ];
                }
              );
              default = { };
              example = lib.literalExpression ''{ work.permissions.binds."''${config.home.homeDirectory}/Workspace/work".rw = true; }'';
              description = ''
                More sandboxes next to the default one, which is always there. Each has the same options, starts from the
                module's defaults rather than the default launcher's settings, and keeps its state in
                `~/.local/share/${app.name}-<name>`: its own home and what the app keeps there (unless bound), Nix store
                and scratchpads. It runs as `${app.name}-<name>`, shows as "${app.displayName} (<name>)", and leaves the
                app's URL handler to the default launcher.
              '';
            };
          };
        }
      ];
    };
    default = { };
    description = "${app.description}, sandboxed: the default launcher's settings, and more launchers in `launchers`.";
  };

  config = lib.mkMerge [
    {
      # Every sandbox of the app, enabled or not (shared.nix)
      agent-sandbox.sandboxes = lib.imap0 (index: name: {
        inherit index;
        inherit (sl.idsOf name)
          sandbox
          appId
          stateDir
          journal
          sandboxJournal
          ;
        app = app.name;
        inherit (cfg) enable;
      }) sl.names;
    }
    (lib.mkIf cfg.enable {
      assertions = [
        {
          # As a launcher name, and so its sandbox's name: what the helpers take (internal/caller)
          assertion = builtins.match "[a-z][a-z0-9-]*" app.name != null && lib.stringLength app.name <= sl.sandboxNameMax;
          message = "agent-sandbox: the app's name ${app.name} must match [a-z][a-z0-9-]* and be at most ${toString sl.sandboxNameMax} characters, as the names of its sandboxes start with it";
        }
        {
          # The gpu feature bundles them (core.nix)
          assertion = osConfig.hardware.graphics.enable || !lib.any (l: l.features.gpu.enable) launchers;
          message = "agent-sandbox.${app.name}: the gpu feature uses the host's graphics drivers, but hardware.graphics.enable is off on this machine. Enable it there if this is a desktop; the module doesn't, so it never pulls a graphics stack onto a server.";
        }
      ]
      ++ (app.assertions or (_: [ ])) { inherit lib sl config; }
      ++ lib.concatMap (l: l.build.assertions) launchers;
      home.packages = map (l: l.build.package) launchers;
      # Each launcher's slice weighted between app.slice and session.slice (100) and background.slice (30), so a busy
      # sandbox leaves the desktop two thirds of the CPU. A switch must not stop the slice, which would take the app with
      # it: sd-switch stops and starts a changed unit unless the new file says keep-old, and one whose file is new or gone
      # unless the running unit refuses a manual stop. daemon-reload applies a changed CPUWeight to the running slice
      systemd.user.slices = lib.listToAttrs (
        map (
          n:
          lib.nameValuePair (lib.removeSuffix ".slice" (sl.sliceOf n)) {
            Unit = {
              X-SwitchMethod = "keep-old";
              RefuseManualStop = true;
            };
            Slice.CPUWeight = 50;
          }
        ) sl.names
      );
      # The memo stores, which shared.nix puts in memo's config
      agent-sandbox.memoStores = lib.mkIf (lib.any (l: l.memo.enable) launchers) sl.memoStores;
    })
  ];
}
