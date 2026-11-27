# The launcher: <app>[-<name>] on the host's PATH (claude-desktop for Claude Desktop's default launcher), the Go
# launcher (cmd/launcher, `launcher --help`) with the launcher's config and the sandbox's environment, which runs the
# app's unit too; the splash it shows while the sandbox starts; and the .desktop file
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
  inherit (lib) mkOption types;
  ids = sl.idsOf launcherName;
  sandboxed = config.build.sandboxed;
  launcher = lib.getExe sl.packages.launcher;
  # nixpak's sloth.env panics on unset variables, so filter the environment before its launcher.
  # Unset passthrough variables expand to nothing
  vars = lib.concatStringsSep "\n  " (
    lib.mapAttrsToList (
      n: v: if v.value == null then "\${${n}+\"${n}=\$${n}\"}" else "\"${n}=${v.value}\""
    ) (lib.filterAttrs (_: v: v.enable) config.env)
  );
  # The launcher with the sandbox's environment, expanded here in bash from the caller's, NUL-separated on fd 3
  wrapper = pkgs.writeShellApplication {
    name = ids.sandbox;
    text = ''
      VARS=(
        ${vars}
      )
      exec ${launcher} start --config=${launcherConfig} --vars-fd=3 -- "$@" 3< <(printf '%s\0' "''${VARS[@]}")
    '';
  };
  launcherConfig = pkgs.writeText "launcher${ids.suffix}.json" (builtins.toJSON config.build.launcherConfig);
in
{
  # The app's .desktop file as the core writes it for each launcher (config.build.package below), set by the app's
  # modules. Name, Exec, StartupWMClass, Actions and MimeType are the core's
  options.build.desktop = {
    entries = mkOption {
      type = types.attrsOf types.str;
      default = { };
      internal = true;
      description = "Other keys of [Desktop Entry]: Icon, Categories, Comment, Keywords, ….";
    };
    execArgs = mkOption {
      type = types.str;
      default = "%U";
      internal = true;
      description = "What Exec passes the launcher after its name.";
    };
    mimeTypes = mkOption {
      type = types.listOf types.str;
      default = [ ];
      internal = true;
      description = "The MIME types the default launcher handles (x-scheme-handler/claude); a named launcher none.";
    };
    actions = mkOption {
      type = types.attrsOf (
        types.submodule {
          options.name = mkOption { type = types.str; };
          options.args = mkOption { type = types.str; };
        }
      );
      default = { };
      internal = true;
      description = "The app's actions, by id, ahead of the core's (Shell, Permissions): the launcher run with `args`.";
    };
    icons = mkOption {
      type = types.nullOr types.path;
      default = null;
      internal = true;
      description = "A share/icons tree the default launcher installs, which Icon names an icon in.";
    };
  };

  options.splash = {
    logo = mkOption {
      type = types.nullOr types.path;
      # A copy, see assets/README.md
      default = ./assets/orbit-landskab-farve.svg;
      defaultText = lib.literalMD "the Orbit logo, `assets/orbit-landskab-farve.svg`";
      description = "The main logo of the splash the launcher shows while the sandbox starts, for a light background.";
    };
    logoDark = mkOption {
      type = types.nullOr types.path;
      default = ./assets/orbit-landskab-farve-negativ.svg;
      defaultText = lib.literalMD "the Orbit logo for dark backgrounds, `assets/orbit-landskab-farve-negativ.svg`";
      description = "The splash's main logo for a dark background, when the desktop is dark. `logo` without it.";
    };
    agentLogo = mkOption {
      type = types.nullOr types.path;
      # The app's module sets its icon
      default = null;
      description = "The logo of the agent the sandbox runs, beside the main logo and a bit smaller. The app's icon by default.";
    };
  };

  # The launcher's config (cmd/launcher main.go), beside what the other modules put in it
  config.build.launcherConfig = {
    inherit (ids)
      appId
      slice
      appPid
      stateDir
      home
      scratchpad
      ;
    inherit (ids) sandbox;
    inherit (config.build) appArgs;
    # The app's name for the user, in the launcher's words ("Starting Claude")
    app = sl.app.displayName;
    unit = ids.appUnit;
    inherit (ids) journal sandboxJournal;
    homeDirs = lib.unique config.build.homeDirs;
    requiredBinds = lib.mapAttrsToList (_: b: b.src) (
      lib.filterAttrs (_: b: b.enable && !b.optional) config.permissions.binds
    );
    state = lib.getExe config.build.state;
    nixpakLauncher = lib.getExe sandboxed.config.script;
    ready = sl.readyLine;
    tools = {
      ip = lib.getExe' pkgs.iproute2 "ip";
      journalctl = lib.getExe' osConfig.systemd.package "journalctl";
      nsenter = lib.getExe' pkgs.util-linux "nsenter";
      nixStore = lib.getExe' osConfig.nix.package "nix-store";
      setpriv = lib.getExe' pkgs.util-linux "setpriv";
      systemctl = lib.getExe' osConfig.systemd.package "systemctl";
      systemdRun = lib.getExe' osConfig.systemd.package "systemd-run";
      systemdCat = lib.getExe' osConfig.systemd.package "systemd-cat";
      unshare = lib.getExe' pkgs.util-linux "unshare";
      inherit (osConfig.security) wrapperDir;
    };
    splash = [
      (lib.getExe' sl.packages.permissions-window "sandbox-splash")
      "--title=${ids.displayName}"
    ]
    ++ lib.optional (config.splash.logo != null) "--logo=${config.splash.logo}"
    ++ lib.optional (config.splash.logoDark != null) "--logo-dark=${config.splash.logoDark}"
    ++ lib.optional (config.splash.agentLogo != null) "--agent-logo=${config.splash.agentLogo}";
  };

  # Each launcher's .desktop file, written here from build.desktop, never upstream's: named by the launcher's app ID,
  # its windows' StartupWMClass, running the launcher by name, found on PATH: gnome-shell keeps a .desktop file it read
  # until it notices a change, which a profile switch doesn't make, and a store path there would run the launcher of the
  # generation it read. The default launcher keeps the app's MIME types (its URL handler, claude://) and installs the
  # app's icons. Nothing of nixpak's own launcher (its bin/) lands on PATH, whatever the app's program is called
  config.build.package =
    let
      d = config.build.desktop;
      line = k: v: "${k}=${v}\n";
      appActions = lib.mapAttrsToList (n: a: {
        inherit n;
        name = a.name;
        exec = "${ids.sandbox} ${a.args}";
      }) d.actions;
      coreActions = lib.mapAttrsToList (n: arg: {
        inherit n;
        name = n;
        exec = "${ids.sandbox} ${arg}";
      }) config.build.desktopActions;
      shell = {
        n = "Shell";
        name = "New shell";
        exec = "${lib.getExe pkgs.xdg-terminal-exec} ${ids.sandbox} --shell";
      };
      actionList = map (a: a) appActions ++ [ shell ] ++ coreActions;
      text =
        "[Desktop Entry]\n"
        + line "Type" "Application"
        + line "Name" ids.displayName
        + line "Exec" "${ids.sandbox}${lib.optionalString (d.execArgs != "") " ${d.execArgs}"}"
        + line "StartupWMClass" ids.appId
        + line "Actions" "${lib.concatMapStringsSep ";" (a: a.n) actionList};"
        + lib.optionalString (launcherName == null && d.mimeTypes != [ ]) (
          line "MimeType" "${lib.concatStringsSep ";" d.mimeTypes};"
        )
        + lib.concatStrings (lib.mapAttrsToList line d.entries)
        + lib.concatMapStrings (a: "\n[Desktop Action ${a.n}]\n" + line "Exec" a.exec + line "Name" a.name) actionList;
      desktopFile = pkgs.writeTextDir "share/applications/${ids.desktopFile}" text;
    in
    pkgs.symlinkJoin {
      name = "${ids.sandbox}-sandboxed";
      paths = [
        wrapper
        desktopFile
      ]
      ++ lib.optional (launcherName == null && d.icons != null) (
        pkgs.runCommand "${ids.sandbox}-icons" { } "mkdir -p $out/share && ln -s ${d.icons} $out/share/icons"
      );
    };
}
