# Paseo in the core's FHS env: its package, the app root it runs from (index.js: the ready line, the launcher's app ID),
# its .desktop file with the paseo:// handler, and its config.json at each launch. Every launcher keeps ~/.paseo and
# Electron's userData (~/.config/Paseo) in its own home, the default one too; a consumer binds them to share
{
  lib,
  pkgs,
  config,
  hm,
  sl,
  launcherName,
  ...
}:
let
  inherit (lib) mkOption types;
  ids = sl.idsOf launcherName;
  pkg = config.package;
  # Besides Electron's own (--no-sandbox, --class=, --remote-debugging-port=), the app takes only an absolute path to a
  # directory that exists in the sandbox (the project to open, desktop/src/open-project-routing.ts) and an agent link,
  # paseo://h/<server>/agent/<agent>: anything else, a relative path, a file, another paseo:// URL, makes Paseo run as its
  # CLI (desktop/src/daemon/cli/passthrough.ts). So build.appArgs stays empty, Chromium's switches go through
  # PASEO_ELECTRON_FLAGS, and the wrapper makes a relative directory absolute (wrapperPrelude)
  appRoot = pkgs.runCommand "paseo-app-root${ids.suffix}" { } ''
    mkdir $out
    cp ${
      pkgs.replaceVars ./index.js {
        ready = builtins.toJSON sl.readyLine;
        main = builtins.toJSON "${pkg}/share/paseo-desktop/packages/desktop/dist/main.js";
      }
    } $out/index.js
    cp ${
      pkgs.writeText "package.json" (
        builtins.toJSON {
          name = "paseo-sandbox";
          # The desktop's version is app.getVersion(), this file's when packaged: one the daemon's doesn't match
          # restarts a desktop-managed daemon at every launch (desktop/src/daemon/daemon-manager.ts)
          inherit (pkg) version;
          main = "index.js";
          # The windows' app ID, with index.js keeping main.js from setting its own
          desktopName = ids.desktopFile;
        }
      )
    } $out/package.json
  '';
in
{
  options.package = mkOption {
    type = types.package;
    default = sl.packages.paseo-desktop;
    defaultText = lib.literalExpression "agent-sandbox.packages.\${system}.paseo-desktop";
    description = "The Paseo desktop app, laid out as a packaged Electron app (`libexec/paseo-desktop/paseo-electron`).";
  };
  options.build.appRoot = mkOption {
    type = types.package;
    internal = true;
    readOnly = true;
    default = appRoot;
    description = "The app root the launcher's app runs from: package.json and index.js.";
  };

  config = {
    # Paseo needs nothing of the FHS env itself (it runs from the store as it is); what runs under it does: the agents,
    # its terminals' shells, tools fetched at runtime
    build.app = sl.fhsEnvOf config {
      name = "paseo";
      runScript = "${pkg}/libexec/paseo-desktop/paseo-electron ${appRoot} --no-sandbox";
    };
    build.storeRoots = [ appRoot ];
    build.stateInputs = [
      pkgs.jq
      pkgs.gawk
    ];
    build.stateVars = {
      PASEO_CONFIG = "${sl.hostPathOf config launcherName ".paseo"}/config.json";
      PASEO_DEFAULTS = "${./config-defaults.json}";
    };
    build.homeDirs = sl.boundHomeDirsOf config [ ".paseo" ];
    # `paseo .`: a directory given relative to the caller's, made absolute while that still means something. It must
    # be at the same path in the sandbox, bound, for Paseo to open it
    build.wrapperPrelude = ''
      args=()
      for a; do
        [[ $a == /* || $a == -* || $a == *:* || ! -d $a ]] || a=$(${pkgs.coreutils}/bin/realpath -s -- "$a")
        args+=("$a")
      done
      set -- "''${args[@]}"
    '';
    build.stateHome = builtins.readFile ./home.sh;
    # As upstream's paseo-desktop.desktop has them
    build.desktop = {
      entries = {
        Categories = "Development";
        Comment = "Self-hosted daemon for AI coding agents";
        GenericName = "AI Coding Agents";
        Icon = "paseo-desktop";
        Version = "1.5";
      };
      # Upstream registers none (Paseo takes links as arguments, desktop/src/main.ts): the default launcher's
      mimeTypes = [ "x-scheme-handler/paseo" ];
      icons = "${pkg}/share/icons";
    };
    splash.agentLogo = lib.mkDefault "${pkg}/share/icons/hicolor/512x512/apps/paseo-desktop.png";
    build.assertions = [
      {
        # Throws at startup in a packaged app (desktop/src/window/chrome.ts); APPIMAGE would wake electron-updater
        assertion =
          !lib.any (v: config.env.${v}.enable or false) [
            "PASEO_DESKTOP_WINDOW_CONTROLS"
            "APPIMAGE"
          ];
        message = "${ids.opt}env must not set PASEO_DESKTOP_WINDOW_CONTROLS (Paseo throws at startup when packaged) or APPIMAGE (electron-updater would update the app)";
      }
      {
        assertion = config.build.appArgs == [ ];
        message = "${ids.opt}Paseo takes no arguments but an absolute directory and a paseo://h/<server>/agent/<agent> link, and runs as its CLI on any other; pass Chromium's switches in env.PASEO_ELECTRON_FLAGS";
      }
    ];
  };
}
