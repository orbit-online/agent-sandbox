# The permissions broker with permissions.broker.enable: its config, the grant directory bound read-only at
# /run/permissions, the sandbox's `permissions` MCP server, and the Permissions window as a .desktop action
{
  lib,
  pkgs,
  config,
  osConfig,
  sl,
  launcherName,
  ...
}:
let
  ids = sl.idsOf launcherName;
  # A launcher's host commands as the broker's config has them; the MCP server's copy, in the sandbox, without run
  commandsOf =
    withRun:
    lib.mapAttrsToList (
      name: c:
      {
        inherit name;
        inherit (c) description bounding exclusive;
        commands = lib.mapAttrs (
          _: cmd:
          {
            inherit (cmd)
              description
              arguments
              result
              timeout
              ;
          }
          // lib.optionalAttrs (cmd.maxValidity != null) { inherit (cmd) maxValidity; }
          // lib.optionalAttrs withRun { inherit (cmd) run consent; }
        ) c.commands;
      }
      # The consent, in the user's words, is the broker's alone
      // lib.optionalAttrs withRun { inherit (c) consent; }
    ) config.permissions.commands;
  # The permissions broker's, under $XDG_RUNTIME_DIR/agent-sandbox: its grant directory, the sandbox's
  # /run/permissions, and its control socket next to it, which isn't bound
  permissionsDir = ids.permissions;
  runtime = "\${XDG_RUNTIME_DIR}/${sl.runtimeDir}";
  permissionsUnit = "${ids.sandbox}-permissions";
  permissionsTitle = "${sl.app.displayName} permissions${
    lib.optionalString (launcherName != null) " (${launcherName})"
  }";
  permissionsConfig = pkgs.writeText "permissions${ids.suffix}.json" (builtins.toJSON brokerConfig);
  brokerConfig = {
    # Who the notifications and the window say asks
    inherit (sl.app) agent;
    inherit (ids) appId sandbox;
    grantDir = "${runtime}/${permissionsDir}";
    controlSocket = "${runtime}/${permissionsDir}-control.sock";
    unit = "${permissionsUnit}.service";
    inherit (ids) slice;
    sandboxGrantDir = "/run/permissions";
    window = [
      (lib.getExe sl.packages.permissions-window)
      "--app-id=${ids.appId}"
      "${runtime}/${permissionsDir}-control.sock"
      permissionsTitle
    ];
    # Every launcher's state directory, of every app, and the runtime directory, and anything holding one
    denied = map (s: s.stateDir) sl.allSandboxes ++ [ "\${XDG_RUNTIME_DIR}" ];
    # The folders ceiling, by path
    folders = lib.mapAttrsToList (path: f: {
      inherit path;
      inherit (f) rw;
    }) (lib.filterAttrs (_: f: f.enable) config.permissions.folders);
    # The helper of the port capability, the wrapper of the NixOS module; none, and no port capability, without a
    # network
    netnsNetkit =
      if config.permissions.network.enable then "${osConfig.security.wrapperDir}/netns-netkit" else null;
    commands = commandsOf true;
    sockets = lib.mapAttrsToList (
      name: sock:
      {
        inherit name;
        inherit (sock) description bounding;
      }
      // lib.optionalAttrs (sock.path != null) { inherit (sock) path; }
      // lib.optionalAttrs (sock.grantedBy != null) { inherit (sock) grantedBy; }
    ) config.permissions.sockets;
    # The standing grants, in the order of their names
    grants = map (g: { inherit (g) capability params; }) (
      lib.filter (g: g.enable) (lib.attrValues config.permissions.grants)
    );
    # What the sandbox reaches from its start, for the window's read-only overview
    overview =
      let
        nixpak = config.build.sandboxed.config;
        sockets = {
          wayland = "Wayland";
          pipewire = "PipeWire";
          pulse = "PulseAudio";
          x11 = "X11";
        };
        socketsOn = lib.attrNames (lib.filterAttrs (_: on: on == true) nixpak.bubblewrap.sockets);
      in
      {
        binds =
          map
            (b: {
              inherit (b)
                path
                src
                rw
                optional
                ;
            })
            (
              lib.sortOn (b: b.path) (
                lib.mapAttrsToList (path: b: b // { inherit path; }) (
                  lib.filterAttrs (_: b: b.enable) config.permissions.binds
                )
              )
            );
        inherit (config.build) devices;
        # The features that are on, each with its description and note: what they add is among the rest
        inherit (config.build) features;
        dbus = config.build.dbusRules;
        network =
          if config.permissions.network.enable then
            "Its own network namespace, joined to the host by a netkit pair whose programs let it out only through the uplinks, NATed: no host-only services, routes or abstract sockets"
          else
            "Its own network namespace with lo alone: no network";
        implicit =
          lib.optional (socketsOn != [ ])
            "Sockets: ${lib.concatMapStringsSep ", " (s: sockets.${s} or s) socketsOn}"
          ++ lib.optional nixpak.gpu.enable "GPU: /dev/dri, with the host's graphics drivers (${nixpak.gpu.provider})"
          ++ [
            "From the Nix store, read-only: the app's closure, the PATH packages at /run/current-system/sw, /etc's ${
              lib.concatStringsSep ", " (lib.filter (e: !lib.elem e sl.hostEtc) config.build.etcEntries)
            }${
              lib.concatMapStrings (f: ", ${f}") (lib.attrNames (lib.filterAttrs (_: f: f.enable) config.files))
            }"
            "/tmp: a tmpfs, with /tmp/claude-<uid> from ${ids.scratchpad}"
            "/run/permissions: this broker's grant directory, read-only"
          ];
      };
  };
in
{
  # The broker's config as it goes to JSON, for the eval tests
  options.build.permissionsConfig = lib.mkOption {
    type = lib.types.raw;
    internal = true;
    visible = false;
    readOnly = true;
    default = brokerConfig;
  };
  config = {
    build.mcpServers = lib.mkIf config.permissions.broker.enable {
      permissions = {
        command = lib.getExe sl.packages.permissions-broker;
        args = [
          "mcp"
        ]
        ++ lib.optionals (config.permissions.commands != { }) [
          "--commands"
          "${pkgs.writeText "permissions-commands.json" (builtins.toJSON (commandsOf false))}"
        ];
      };
    };
    build.nixpak = lib.optional config.permissions.broker.enable (
      { sloth, ... }:
      {
        bubblewrap.bind.ro = [
          [
            (sloth.concat' (sloth.env "XDG_RUNTIME_DIR") "/${sl.runtimeDir}/${permissionsDir}")
            "/run/permissions"
          ]
        ];
      }
    );
    build.launcherConfig.permissions =
      if config.permissions.broker.enable then
        {
          config = "${permissionsConfig}";
          dir = permissionsDir;
          unit = permissionsUnit;
          broker = lib.getExe sl.packages.permissions-broker;
          window = [
            (lib.getExe sl.packages.permissions-window)
            "--app-id=${ids.appId}"
            "${runtime}/${permissionsDir}-control.sock"
            permissionsTitle
          ];
        }
      else
        null;

    build.desktopActions = lib.mkIf config.permissions.broker.enable { Permissions = "--permissions"; };
  };
}
