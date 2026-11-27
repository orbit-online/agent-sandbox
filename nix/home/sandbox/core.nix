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
  # nixpak's D-Bus proxy: its launcher runs pkgs.xdg-dbus-proxy in a wrapper whose path it sets at build time
  # (docs/permissions.md, D-Bus), so the proxy comes in through the pkgs it gets. And nixpak's launcher, which it builds
  # with this callPackage, with its reaper leaving alone the children it waits for (nix/patches/nixpak-launcher-reaper.patch).
  # Everything else nixpak calls or takes sees nixpkgs as is
  nixpakPkgs = pkgs // {
    # Logging to the launcher's journal namespace: nixpak's wrapper binds /run into the proxy's bwrap
    xdg-dbus-proxy = pkgs.writeShellApplication {
      name = "xdg-dbus-proxy";
      text = ''exec ${lib.getExe' osConfig.systemd.package "systemd-cat"} --namespace=${ids.journal} --identifier=dbus-proxy -- ${lib.getExe sl.packages.dbus-proxy} "$@"'';
    };
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
  # What the host does in the sandbox's state dir and home, confined: see confine.sh. The app's own part of the home
  # step, its variables and tools come from build.stateHome, build.stateVars and build.stateInputs
  stateInner = sl.script "state.sh" {
    name = "${ids.sandbox}-state-inner";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.glib
      osConfig.nix.package
    ]
    ++ config.build.stateInputs;
    vars = config.build.stateVars // {
      APP = sl.app.name;
      STATE_DIR = ids.stateDir;
      SANDBOX_HOME = ids.home;
      RESOLV_CONF = "${ids.home}/.config/resolv.conf";
      SCHEMA_DIR = pkgs.glib.getSchemaPath pkgs.gsettings-desktop-schemas;
    };
    # The home step's app part, as a function the script calls, so the script's checks see the app's variables used
    prelude = "app_home() {\n:\n${config.build.stateHome}}\n";
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
    ) (sl.byDepth (lib.filterAttrs (_: b: b.rw == rw) config.permissions.binds));
  # By path: the entries of permissions.devices that are on, the features' among them
  devices = lib.attrNames (lib.filterAttrs (_: d: d.enable) config.permissions.devices);
  # What the checks below say about a bind's or a device's source on the host, null for nothing. They read the path as
  # written, so first it has to be the one spelling of itself: absolute and clean, one trailing slash aside
  # (/run/user//, /run/./user/1000 and <state dir>/home/.. are /run/user, the runtime dir and the state dir to bwrap).
  # Then it may not be /proc or /var/run or lie in them, where every path of the host has another name
  # (/proc/self/root/run/user/1000, /var/run/user/1000) and the host's /proc opens the root of each of the user's
  # processes; nor hold or lie in a launcher's state dir, hold $XDG_RUNTIME_DIR (any /run/user/<uid>) or lie in its
  # .flatpak or agent-sandbox dirs: the sandbox would reach another sandbox's state, the permissions broker's
  # sockets, or the nixpak instance info the broker and the launcher read as the sandbox's identity. Its own home,
  # store and scratchpad aside, which it holds anyway. As the broker's attach ceiling denies them. A source that is a
  # link on the host to one of these isn't seen here
  sourceRefusal =
    let
      stateDirs = map (s: s.stateDir) sl.allSandboxes;
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
        || builtins.match "/run/user/[^/]+(/(\\.flatpak|${sl.runtimeDir})(/.*)?)?" src != null;
      state =
        src:
        runtime src
        || lib.any (
          d:
          sl.holds src d || (sl.holds d src && !(d == ids.stateDir && lib.any (r: sl.holds r src) ownParts))
        ) stateDirs;
    in
    written:
    let
      src = if written == "/" then "/" else lib.removeSuffix "/" written;
    in
    if !sl.cleanPath src then
      "which isn't an absolute path in its clean form (no ., .. or empty segments); the checks on what no sandbox may reach read it as written"
    else if
      lib.any (alias: sl.holds alias src) [
        "/proc"
        "/var/run"
      ]
    then
      "which is /proc or /var/run or lies in one, where every path of the host has another name; no sandbox may reach those"
    else if state src then
      "which holds or lies in a launcher's state dir, or holds $XDG_RUNTIME_DIR or lies in its .flatpak or ${sl.runtimeDir} dir; no sandbox may reach those"
    else
      null;
  refusedBinds = lib.filterAttrs (
    _: b: b.enable && sourceRefusal b.src != null
  ) config.permissions.binds;
  refusedDevices = lib.filter (d: sourceRefusal d != null) devices;
  # The source of a read-write bind, the scratchpad's included, that holds a bind's or a device's source, null for
  # none: the sandbox writes the directory that holds the source, so it can put a link in its place, even while it is
  # a mountpoint (from a nested mount namespace, models/README.md, Attacker 6), and bwrap follows a link at a bind's
  # source: the next launch would mount what the link names, anything the user reaches (CVE-2024-42472 was this in
  # Flatpak). A read-only bind there protects nothing either: moved aside, its directory is the read-write bind's
  # under another name. Compared as written, so only of sources the checks above let through, which are clean. The
  # store beneath /nix aside, which the launcher checks itself before every launch (cmd/launcher store.go)
  holder =
    let
      clean = src: if src == "/" then "/" else lib.removeSuffix "/" src;
      writable =
        lib.mapAttrsToList (_: b: clean b.src) (
          lib.filterAttrs (_: b: b.enable && b.rw) config.permissions.binds
        )
        ++ [ ids.scratchpad ];
    in
    written:
    let
      src = clean written;
    in
    if sourceRefusal written != null || src == "${ids.stateDir}/nix/store" then
      null
    else
      lib.findFirst (w: w != src && sl.holds w src) null writable;
  nestedBinds = lib.mapAttrs (_: b: b // { holder = holder b.src; }) (
    lib.filterAttrs (_: b: b.enable && holder b.src != null) config.permissions.binds
  );
  nestedDevices = lib.filter (d: holder d != null) devices;
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
    permissions.binds = {
      "/sys" = { };
      ${hm.home.homeDirectory} = {
        src = ids.home;
        rw = true;
      };
    }
    // lib.genAttrs (map (e: "/etc/${e}") sl.hostEtc) (_: { optional = true; });
    # The binds above and store.nix's: the sandbox's own, which the environment doc lists only when read-write and an
    # app may treat apart (Claude Desktop keeps them from its filesystem MCP server)
    build.coreBinds = [
      "/sys"
      hm.home.homeDirectory
    ]
    ++ map (e: "/etc/${e}") sl.hostEtc;

    build.devices = devices;
    # The directories <sandbox>-state works in for the launcher: the sandbox's home, and those the app adds (the bind
    # sources of directories it keeps in the home)
    build.homeDirs = lib.mkBefore [ ids.home ];
    build.storeRoots = [ graphicsDrivers ];
    build.state = sl.script "confine.sh" {
      name = "${ids.sandbox}-state";
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
          message = "agent-sandbox.${sl.app.name}: launcher name ${launcherName} must match [a-z][a-z0-9-]*";
        }
        {
          # The tightest of what the sandbox's name, <app>-<name>, goes into: the broker's sockets, bound by path (at most
          # 107 bytes and the NUL), 60 bytes besides the sandbox's name with a 10-digit uid; see sl.sandboxSockets for the
          # others. The app ID (D-Bus's 255 bytes), the slice (systemd's 255 characters, 6 besides and 3 more for each -
          # escaped) and the state dir's file name (255) allow more; the netkit primary's name hashes it
          assertion = lib.stringLength launcherName <= sl.launcherNameMax;
          message = "agent-sandbox.${sl.app.name}: launcher name ${launcherName} must be at most ${toString sl.launcherNameMax} characters, so the socket paths its sandbox's name ${sl.app.name}-<name> goes into fit a socket's 107 bytes and its NUL; the longest is the broker's, /run/user/<uid>/${sl.runtimeDir}/${sl.app.name}-<name>-permissions/request.sock";
        }
      ]
      ++ lib.mapAttrsToList (path: b: {
        assertion = false;
        message = "${ids.opt}permissions.binds.\"${path}\" binds ${b.src}, ${sourceRefusal b.src}";
      }) refusedBinds
      # A device is bound read-write from its own path
      ++ map (d: {
        assertion = false;
        message = "${ids.opt}permissions.devices.\"${d}\", ${sourceRefusal d}";
      }) refusedDevices
      ++ lib.mapAttrsToList (path: b: {
        assertion = false;
        message = "${ids.opt}permissions.binds.\"${path}\" binds ${b.src}, which lies beneath ${b.holder}, a directory the sandbox writes: it can put a link in its place, which the next launch would follow to anything you reach. Bind it from somewhere the sandbox can't write, or leave it to the bind that holds it";
      }) nestedBinds
      ++ map (d: {
        assertion = false;
        message = "${ids.opt}permissions.devices.\"${d}\", which lies beneath ${holder d}, a directory the sandbox writes: it can put a link in its place, which the next launch would follow to anything you reach. Bind it from somewhere the sandbox can't write, or leave it to the bind that holds it";
      }) nestedDevices;

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
                  # The sandbox's journal namespace's syslog socket, after nixpak's /dev like the devices
                  [
                    "/run/systemd/journal.${ids.sandboxJournal}/dev-log"
                    "/dev/log"
                  ]
                ]
                ++ devices;
                # Its native and stream sockets, where sd-journal and systemd-cat look; the namespaces' files are bound
                # at launch (cmd/launcher bwrap.go), by the machine-id. None of the host side's sockets
                bind.ro = binds false ++ [
                  [
                    "/run/systemd/journal.${ids.sandboxJournal}/socket"
                    "/run/systemd/journal/socket"
                  ]
                  [
                    "/run/systemd/journal.${ids.sandboxJournal}/stdout"
                    "/run/systemd/journal/stdout"
                  ]
                ];
                tmpfs = [ "/tmp" ];
                sockets = {
                  wayland = true;
                  # The audio feature (features.nix), which has no body for them
                  pipewire = config.features.audio.enable;
                  pulse = config.features.audio.enable;
                };
                newSession = true;
                dieWithParent = true;
              };
            };
        };
  };
}
