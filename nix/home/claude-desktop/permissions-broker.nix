# The permissions broker with permissions.enable: its config, the grant directory bound read-only at
# /run/permissions, the sandbox's `permissions` MCP server, and the Permissions window as a .desktop action
{
  lib,
  pkgs,
  config,
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
  # The permissions broker's, under $XDG_RUNTIME_DIR/claude-desktop: its grant directory, the sandbox's
  # /run/permissions, and its control socket next to it, which isn't bound
  permissionsDir = "permissions${ids.suffix}";
  permissionsUnit = "claude-desktop${ids.suffix}-permissions";
  permissionsTitle = "Claude permissions${
    lib.optionalString (launcherName != null) " (${launcherName})"
  }";
  permissionsConfig = pkgs.writeText "permissions${ids.suffix}.json" (
    builtins.toJSON {
      # Who the notifications and the window say asks
      agent = "Claude";
      inherit (ids) appId;
      # Empty for the default launcher: no named one can take that name
      launcher = if launcherName == null then "" else launcherName;
      grantDir = "\${XDG_RUNTIME_DIR}/claude-desktop/${permissionsDir}";
      controlSocket = "\${XDG_RUNTIME_DIR}/claude-desktop/${permissionsDir}-control.sock";
      unit = "${permissionsUnit}.service";
      inherit (ids) slice;
      sandboxGrantDir = "/run/permissions";
      window = [
        (lib.getExe sl.packages.permissions-window)
        "--app-id=${ids.appId}"
        "\${XDG_RUNTIME_DIR}/claude-desktop/${permissionsDir}-control.sock"
        permissionsTitle
      ];
      # Every launcher's state directory and runtime directory, and anything holding one
      denied = map sl.stateDirOf sl.names ++ [ "\${XDG_RUNTIME_DIR}" ];
      inherit (config.permissions) folders;
      commands = commandsOf true;
      sockets = lib.mapAttrsToList (
        name: sock:
        {
          inherit name;
          inherit (sock) description bounding;
        }
        // lib.optionalAttrs (sock.path != null) { inherit (sock) path; }
      ) config.permissions.sockets;
      grants = map (g: { inherit (g) capability params; }) config.permissions.grants;
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
                  lib.mapAttrsToList (path: b: b // { inherit path; }) (lib.filterAttrs (_: b: b.enable) config.binds)
                )
              );
          inherit (config.build) devices;
          dbus = config.build.dbusRules;
          network = "Its own network namespace, joined to the host by a netkit pair whose programs let it out only through the uplinks, NATed: no host-only services, routes or abstract sockets";
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
    }
  );
in
{
  build.mcpServers = lib.mkIf config.permissions.enable {
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
  build.nixpak = lib.optional config.permissions.enable (
    { sloth, ... }:
    {
      bubblewrap.bind.ro = [
        [
          (sloth.concat' (sloth.env "XDG_RUNTIME_DIR") "/claude-desktop/${permissionsDir}")
          "/run/permissions"
        ]
      ];
    }
  );
  build.launcherConfig.permissions =
    if config.permissions.enable then
      {
        config = "${permissionsConfig}";
        dir = permissionsDir;
        unit = permissionsUnit;
        broker = lib.getExe sl.packages.permissions-broker;
        window = [
          (lib.getExe sl.packages.permissions-window)
          "--app-id=${ids.appId}"
          "\${XDG_RUNTIME_DIR}/claude-desktop/${permissionsDir}-control.sock"
          permissionsTitle
        ];
      }
    else
      null;

  build.desktopActions = lib.mkIf config.permissions.enable { Permissions = "--permissions"; };
}
