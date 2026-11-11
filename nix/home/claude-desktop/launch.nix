# The launcher: claude-desktop[-<name>] on the host's PATH (claude-desktop.sh), the app's unit it starts
# (app-unit.sh), and the .desktop file
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
  sandboxed = config.build.sandboxed;
  # nixpak's sloth.env panics on unset variables, so filter the environment before its launcher.
  # Unset passthrough variables expand to nothing
  vars = lib.concatStringsSep "\n  " (
    lib.mapAttrsToList (
      n: v: if v.value == null then "\${${n}+\"${n}=\$${n}\"}" else "\"${n}=${v.value}\""
    ) (lib.filterAttrs (_: v: v.enable) config.env)
  );
  varsPrelude = ''
    VARS=(
      ${vars}
    )
    readonly VARS
  '';
  # The app's unit, which the wrapper starts in the slice
  appUnit = sl.script "app-unit.sh" {
    name = "claude-desktop${ids.suffix}-app";
    runtimeInputs = [ pkgs.coreutils ];
    vars = config.build.appUnitVars // {
      NIXPAK_LAUNCHER = lib.getExe sandboxed.config.script;
    };
    prelude = varsPrelude;
  };
  wrapper = sl.script "claude-desktop.sh" {
    name = "claude-desktop${ids.suffix}";
    runtimeInputs = [
      pkgs.coreutils
      osConfig.nix.package
      osConfig.systemd.package
    ];
    vars = config.build.launcherVars // {
      SCRATCHPAD = ids.scratchpad;
      APP_ID = ids.appId;
      APP_PID = toString ids.appPid;
      SETPRIV = lib.getExe' pkgs.util-linux "setpriv";
      STATE = lib.getExe config.build.state;
      SLICE = ids.slice;
      APP_UNIT = "claude-desktop${ids.suffix}-app.service";
      APP_RUN = lib.getExe appUnit;
    };
    prelude = varsPrelude + ''
      REQUIRED_BINDS=(
        ${lib.escapeShellArgs (
          lib.mapAttrsToList (_: b: b.src) (lib.filterAttrs (_: b: b.enable && !b.optional) config.binds)
        )}
      )
      HOME_DIRS=(${lib.escapeShellArgs config.build.homeDirs})
      readonly REQUIRED_BINDS HOME_DIRS
    '';
  };
  actions = lib.concatMapStrings (a: ";${a}") (lib.attrNames config.build.desktopActions);
in
{
  # First path wins on collisions: the wrapper shadows nixpak's bin/claude-desktop, while the icons carry over. Each
  # launcher installs upstream's .desktop file under its app ID, its windows' StartupWMClass. A named launcher
  # takes only that file: the default launcher installs the icons and keeps the claude:// handler
  build.package = pkgs.symlinkJoin {
    name = "claude-desktop${ids.suffix}-sandboxed";
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
            "0,/^Name=/s/^Name=.*/Name=Claude (${launcherName})/"
            "-e"
            "s/^Exec=claude-desktop /Exec=claude-desktop-${launcherName} /"
            "-e"
            "/^MimeType=/d"
          ]
        )
      } "$(readlink -f "$1")" >"$d"
      grep -q '^Actions=.*;Shell${actions}$' "$d"
      [[ $(grep -c '^StartupWMClass=' "$d") == 1 ]]
      grep -qxF 'StartupWMClass=${ids.appId}' "$d"
      ${lib.optionalString (launcherName != null) ''
        grep -qxF 'Name=Claude (${launcherName})' "$d"
        ! grep -q '^Exec=claude-desktop ' "$d" || exit 1
        ! grep -q '^MimeType=' "$d" || exit 1
      ''}
      # The launcher by name, found on PATH as upstream's Exec finds it: gnome-shell keeps a .desktop file it read
      # until it notices a change, which a profile switch doesn't make, and a store path there would run the
      # launcher of the generation it read
      printf '\n[Desktop Action Shell]\nExec=%s %s --shell\nName=New shell\n' \
        ${lib.getExe pkgs.xdg-terminal-exec} "claude-desktop${ids.suffix}" >>"$d"
      ${lib.concatStrings (
        lib.mapAttrsToList (action: arg: ''
          printf '\n[Desktop Action ${action}]\nExec=%s ${arg}\nName=${action}\n' \
            "claude-desktop${ids.suffix}" >>"$d"
        '') config.build.desktopActions
      )}
    '';
  };
}
