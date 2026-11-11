# The sandbox itself: nixpak's config from the launcher's binds, devices and the features' additions, the binds every
# launcher starts with, and what the host does in the sandbox's home, confined
{
  lib,
  pkgs,
  config,
  hm,
  osConfig,
  inputs,
  sl,
  launcherName,
  ...
}:
let
  ids = sl.idsOf launcherName;
  sys = {
    mcp = false;
  };
  # nixpak's D-Bus proxy: its launcher runs pkgs.xdg-dbus-proxy in a wrapper whose path it sets at build time
  # (docs/permissions.md, D-Bus), so the proxy comes in through the pkgs it gets. And nixpak's launcher, which it builds
  # with this callPackage, with its reaper leaving alone the children it waits for (nix/patches/nixpak-launcher-reaper.patch).
  # Everything else nixpak calls or takes sees nixpkgs as is
  nixpakPkgs = pkgs // {
    xdg-dbus-proxy = sl.packages.dbus-proxy;
    callPackage =
      fn: args:
      let
        drv = pkgs.callPackage fn args;
      in
      if toString fn == "${inputs.nixpak}/launcher" then
        drv.overrideAttrs (o: {
          patches = (o.patches or [ ]) ++ [ ../../patches/nixpak-launcher-reaper.patch ];
          # The patch is against nixpak's repo, the package's source its launcher/
          patchFlags = [ "-p2" ];
        })
      else
        drv;
  };
  # The host's /run/opengl-driver, as NixOS builds it
  graphicsDrivers = pkgs.buildEnv {
    name = "graphics-drivers";
    paths = [ osConfig.hardware.graphics.package ] ++ osConfig.hardware.graphics.extraPackages;
  };
  # Where a path under the home directory is on the host: its bind's source, or the sandbox's home
  hostBind =
    rel:
    let
      b = config.binds."${hm.home.homeDirectory}/${rel}" or null;
    in
    if b != null && b.enable then b.src else null;
  hostPath = rel: if hostBind rel != null then hostBind rel else "${ids.home}/${rel}";
  # What the host does in the sandbox's state dir and home, confined: see confine.sh
  stateInner = sl.script "state.sh" {
    name = "claude-desktop${ids.suffix}-state-inner";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.jq
      pkgs.glib
      osConfig.nix.package
    ];
    vars = {
      STATE_DIR = ids.stateDir;
      SANDBOX_HOME = ids.home;
      RESOLV_CONF = "${ids.home}/.config/resolv.conf";
      DOT_CLAUDE = hostPath ".claude";
      CONFIG = "${hostPath ".config/Claude"}/claude_desktop_config.json";
      MCP_SERVERS = "${pkgs.writeText "mcp-servers.json" (builtins.toJSON config.mcpServers)}";
      TRAY = lib.boolToString config.tray;
      SCHEMA_DIR = pkgs.glib.getSchemaPath pkgs.gsettings-desktop-schemas;
    };
  };
  # Shallowest first, so nested binds override their parents. nixpak mounts all rw binds before the ro ones
  binds =
    rw:
    map (
      b:
      if b.src == b.path then
        b.src
      else
        [
          b.src
          b.path
        ]
    ) (sl.byDepth (lib.filterAttrs (_: b: b.rw == rw) config.binds));
  devices = lib.unique (lib.optional config.kvm "/dev/kvm" ++ config.devices);
  # The launcher's enabled binds whose source holds or lies in a launcher's state dir, holds $XDG_RUNTIME_DIR (any
  # /run/user/<uid>) or lies in its .flatpak or claude-desktop dirs: the sandbox would reach another sandbox's state,
  # the permissions broker's sockets, or the nixpak instance info the broker and the launcher read as the
  # sandbox's identity. Its own home, store and scratchpad aside, which it holds anyway. As the broker's attach
  # ceiling denies them
  stateBinds =
    let
      stateDirs = map sl.stateDirOf sl.names;
      ownParts = map (d: "${ids.stateDir}/${d}") [
        "home"
        "nix"
        "tmp-scratchpad"
      ];
      runtime =
        src:
        lib.elem src [
          "/"
          "/run"
          "/run/user"
        ]
        || builtins.match "/run/user/[^/]+(/(\\.flatpak|claude-desktop)(/.*)?)?" src != null;
      bad =
        src:
        runtime src
        || lib.any (
          d:
          sl.holds src d || (sl.holds d src && !(d == ids.stateDir && lib.any (r: sl.holds r src) ownParts))
        ) stateDirs;
    in
    lib.filterAttrs (
      _: b: b.enable && bad (if b.src == "/" then "/" else lib.removeSuffix "/" b.src)
    ) config.binds;
in
{
  config = {
    env =
      lib.genAttrs [
        "HOME"
        "USER"
        "LANG"
        "LC_ALL"
        "XDG_RUNTIME_DIR"
        "WAYLAND_DISPLAY"
        "XDG_SESSION_TYPE"
        "XDG_CONFIG_DIRS"
        "XCURSOR_THEME"
        "XCURSOR_SIZE"
        # The host bus, for nixpak's D-Bus proxy. The sandbox gets the proxy's address
        "DBUS_SESSION_BUS_ADDRESS"
      ] (_: { })
      // {
        # nixpak binds /etc/localtime as a file, so ICU can't read the zone name from the link target
        TZ.value = osConfig.time.timeZone;
        # Not the login shell from /etc/passwd
        SHELL = "/run/current-system/sw/bin/bash";
        NIXOS_OZONE_WL = "1";
        # Chromium takes the first desktop it knows. On GNOME it hands the tray its icon as a file in the sandbox's
        # /tmp, which the shell can't read; on COSMIC as pixmaps, with the same GTK theme and proxy settings. GLib and
        # the app's own checks still find GNOME in the list. Empty when the host's is unset
        XDG_CURRENT_DESKTOP = "\${XDG_CURRENT_DESKTOP:+\${XDG_CURRENT_DESKTOP/GNOME/COSMIC:GNOME}}";
      };
    binds = {
      "/sys" = sys;
      ${hm.home.homeDirectory} = sys // {
        src = ids.home;
        rw = true;
      };
    }
    # A named launcher keeps them in its own home
    // lib.optionalAttrs (launcherName == null) {
      "${hm.home.homeDirectory}/.claude".rw = true;
      "${hm.home.homeDirectory}/.config/Claude" = sys // {
        rw = true;
      };
    }
    // lib.genAttrs (map (e: "/etc/${e}") sl.hostEtc) (_: sys // { optional = true; });

    build.devices = devices;
    # The directories claude-desktop-state works in for the launcher: the sandbox's home, and the bind sources of
    # ~/.claude and ~/.config/Claude where they're bound
    build.homeDirs = lib.unique (
      [ ids.home ]
      ++ lib.filter (d: d != null) [
        (hostBind ".claude")
        (hostBind ".config/Claude")
      ]
    );
    build.storeRoots = [ graphicsDrivers ];
    build.state = sl.script "confine.sh" {
      name = "claude-desktop${ids.suffix}-state";
      vars = {
        BWRAP = lib.getExe' pkgs.bubblewrap "bwrap";
        CLOSURE = "${pkgs.closureInfo { rootPaths = [ stateInner ]; }}/store-paths";
        COMMAND = lib.getExe stateInner;
      };
    };
    build.assertions =
      lib.optionals (launcherName != null) [
        {
          # File names, the app ID and the .desktop file's Name take it as is
          assertion = builtins.match "[a-z][a-z0-9-]*" launcherName != null;
          message = "agent-sandbox.claude-desktop: launcher name ${launcherName} must match [a-z][a-z0-9-]*";
        }
        {
          # The tightest of what the name goes into: the broker's control socket and request.sock, 61 bytes besides
          # the name with a 10-digit uid, bound by path (at most 107 bytes and the NUL). The app ID (D-Bus's 255 bytes, 21
          # besides), the slice (systemd's 255 characters, 27 besides and 3 more for each - escaped) and the state
          # dir's file name (255, 15 besides) allow more; the macvlan is eth0 whatever the name
          assertion = lib.stringLength launcherName <= sl.launcherNameMax;
          message = "agent-sandbox.claude-desktop: launcher name ${launcherName} must be at most ${toString sl.launcherNameMax} characters, so its permissions broker's socket path, /run/user/<uid>/claude-desktop/permissions-<name>-control.sock, fits a socket's 107 bytes and its NUL";
        }
      ]
      ++ lib.mapAttrsToList (path: b: {
        assertion = false;
        message = "${ids.opt}binds.\"${path}\" binds ${b.src}, which holds or lies in a launcher's state dir, or holds $XDG_RUNTIME_DIR or lies in its .flatpak or claude-desktop dir; no sandbox may reach those";
      }) stateBinds;

    build.sandboxed =
      inputs.nixpak.lib.nixpak
        {
          inherit lib;
          pkgs = nixpakPkgs;
        }
        {
          config =
            { sloth, ... }:
            {
              imports = [ config.sandbox ] ++ config.build.nixpak;
              flatpak.appId = ids.appId;
              app.package = config.build.app;
              gpu = {
                enable = true;
                # Not "nixos": /run/opengl-driver links into the system closure
                provider = "bundle";
                bundlePackage = graphicsDrivers;
              };
              bubblewrap = {
                bindEntireStore = false;
                bind.rw = binds true;
                # Claude Code's temp dir, so the session scratchpads survive restarts (pruned by scratchpad-prune.sh).
                # A dev bind because nixpak mounts the /tmp tmpfs after the rw and ro binds and before the dev ones.
                # It still ends up nodev where the app runs: the FHS env's bwrap binds /tmp on with nodev
                bind.dev = [
                  [
                    ids.scratchpad
                    (sloth.concat' "/tmp/claude-" sloth.uid)
                  ]
                ]
                ++ devices;
                bind.ro = binds false;
                tmpfs = [ "/tmp" ];
                sockets = {
                  wayland = true;
                  pipewire = config.audio;
                  pulse = config.audio;
                };
                newSession = true;
                dieWithParent = true;
              };
            };
        };
  };
}
