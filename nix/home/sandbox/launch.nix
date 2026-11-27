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
  actions = lib.concatMapStrings (a: ";${a}") (lib.attrNames config.build.desktopActions);
in
{
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

  # First path wins on collisions: the wrapper shadows nixpak's bin/<app>, while the icons carry over. Each launcher
  # installs upstream's .desktop file under its app ID, its windows' StartupWMClass. A named launcher takes only that
  # file: the default launcher installs the icons and keeps the app's URL handler (claude://)
  config.build.package = pkgs.symlinkJoin {
    name = "${ids.sandbox}-sandboxed";
    paths = [ wrapper ] ++ lib.optional (launcherName == null) sandboxed.config.env;
    postBuild = ''
      # The package's only .desktop file, whose name changed upstream
      set -- ${sandboxed.config.env}/share/applications/*.desktop
      [[ $# == 1 ]]
      d=$out/share/applications/${ids.desktopFile}
      mkdir -p "$out/share/applications"
      rm -f "$out/share/applications/''${1##*/}" "$d"
      sed ${
        lib.escapeShellArgs (
          [
            "-e"
            "s/^Actions=.*/&;Shell${actions}/"
            "-e"
            "/^StartupWMClass=/d"
            "-e"
            "s/^\\[Desktop Entry\\]$/&\\nStartupWMClass=${ids.appId}/"
          ]
          ++ lib.optionals (launcherName != null) [
            "-e"
            "0,/^Name=/s/^Name=.*/Name=${ids.displayName}/"
            "-e"
            "s/^Exec=${sl.app.name} /Exec=${ids.sandbox} /"
            "-e"
            "/^MimeType=/d"
          ]
        )
      } "$(readlink -f "$1")" >"$d"
      grep -q '^Actions=.*;Shell${actions}$' "$d"
      [[ $(grep -c '^StartupWMClass=' "$d") == 1 ]]
      grep -qxF 'StartupWMClass=${ids.appId}' "$d"
      ${lib.optionalString (launcherName != null) ''
        grep -qxF 'Name=${ids.displayName}' "$d"
        ! grep -q '^Exec=${sl.app.name} ' "$d" || exit 1
        ! grep -q '^MimeType=' "$d" || exit 1
      ''}
      # The launcher by name, found on PATH as upstream's Exec finds it: gnome-shell keeps a .desktop file it read
      # until it notices a change, which a profile switch doesn't make, and a store path there would run the
      # launcher of the generation it read
      printf '\n[Desktop Action Shell]\nExec=%s %s --shell\nName=New shell\n' \
        ${lib.getExe pkgs.xdg-terminal-exec} "${ids.sandbox}" >>"$d"
      ${lib.concatStrings (
        lib.mapAttrsToList (action: arg: ''
          printf '\n[Desktop Action ${action}]\nExec=%s ${arg}\nName=${action}\n' \
            "${ids.sandbox}" >>"$d"
        '') config.build.desktopActions
      )}
    '';
  };
}
