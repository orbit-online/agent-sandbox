# Claude Desktop in its FHS env: its package, the asar patch (patch-asar.sh: the ready line, the tray icon, the
# notification backend, the MCP channels), the directories it keeps in the home (~/.claude and ~/.config/Claude,
# bound from the host's for the default launcher), its config merged at each launch, `claude` on PATH, its .desktop
# file, and the `mcp` flag of binds, which its filesystem MCP server (mcp.nix) and the environment doc go by
{
  lib,
  pkgs,
  config,
  hm,
  inputs,
  sl,
  launcherName,
  ...
}:
let
  inherit (lib) mkOption types;
  ids = sl.idsOf launcherName;
  home = hm.home.homeDirectory;
  # The app keeps Claude Code under a versioned path, off PATH
  claudeCode = sl.script "claude.sh" {
    runtimeInputs = [ pkgs.coreutils ];
    dir = ./.;
  };
  asar = "${config.package.unwrapped}/lib/claude-desktop/resources/app.asar";
  patchedAsar = pkgs.runCommand "claude-desktop-app.asar" {
    nativeBuildInputs = [
      pkgs.asar
      pkgs.jq
    ];
    ASAR = asar;
    DESKTOP_NAME = ids.desktopFile;
    READY = sl.readyLine;
    CHANNELS = builtins.toJSON config.mcpChannels;
    CHANNELS_JS = ./channels.js;
  } "source ${./patch-asar.sh}";
in
{
  options.package =
    lib.mkPackageOption inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system} "claude-desktop"
      { pkgsText = "inputs.llm-agents.packages.\${system}"; };
  # Claude Desktop's own option of a bind, beside the core's
  options.permissions.binds = mkOption {
    type = types.attrsOf (
      types.submodule {
        options.mcp = mkOption {
          type = types.bool;
          default = true;
          description = "Expose the path to the filesystem MCP server, and list it in the environment doc when read-only.";
        };
      }
    );
  };

  config = lib.mkMerge [
    (sl.keepInHome config launcherName [
      ".claude"
      ".config/Claude"
    ] { })
    {
      # The sandbox's own binds and the app's config aren't for the filesystem MCP server
      permissions.binds =
        lib.genAttrs config.build.coreBinds (_: {
          mcp = lib.mkDefault false;
        })
        // lib.optionalAttrs (launcherName == null) { "${home}/.config/Claude".mcp = lib.mkDefault false; };
      build.environmentBind = b: {
        listed = b.rw || b.mcp;
        tags = lib.optional b.mcp "MCP";
      };
      # The state script's home step (state.sh) merges the app's config: it writes to the file too, so a merge rather
      # than a link to the store
      build.stateInputs = [ pkgs.jq ];
      build.stateVars = {
        DOT_CLAUDE = sl.hostPathOf config launcherName ".claude";
        CONFIG = "${sl.hostPathOf config launcherName ".config/Claude"}/claude_desktop_config.json";
        MCP_SERVERS = "${pkgs.writeText "mcp-servers.json" (builtins.toJSON config.mcpServers)}";
        TRAY = lib.boolToString config.features.tray.enable;
      };
      build.stateHome = ''
        : "''${DOT_CLAUDE:?}" "''${CONFIG:?}" "''${MCP_SERVERS:?}" "''${TRAY:?}"
        mkdir -p "$DOT_CLAUDE" "''${CONFIG%/*}"
        # shellcheck disable=SC2016 # jq's variables
        merge "$CONFIG" '{}' jq --slurpfile m "$MCP_SERVERS" --argjson tray "$TRAY" \
          '.mcpServers = $m[0] | .preferences.menuBarEnabled = $tray' || :
      '';
      build.pathPackages = [ claudeCode ];
      # Chromium's, so it never asks for a keyring the sandbox doesn't reach
      build.appArgs = [ "--password-store=basic" ];
      build.fhsBwrapArgs = [ "--ro-bind ${patchedAsar} ${asar}" ];
      build.app = sl.fhsAppOf config config.package;
      # As upstream's com.anthropic.Claude.desktop has them
      build.desktop = {
        entries = {
          Categories = "Utility;Development";
          Comment = "Desktop application for Claude.ai";
          GenericName = "AI Assistant";
          Icon = "claude-desktop";
          Keywords = "AI;Chat;Assistant;Claude;Code;LLM";
          SingleMainWindow = "true";
          StartupNotify = "true";
          Version = "1.5";
        };
        mimeTypes = [ "x-scheme-handler/claude" ];
        actions = {
          NewChat = {
            name = "New chat";
            args = "claude://claude.ai/new";
          };
          NewCode = {
            name = "New Claude Code session";
            args = "claude://code/new";
          };
        };
        icons = "${config.package.unwrapped}/share/icons";
      };
      # The unwrapped app, which the closure holds anyway; package would bring its FHS env without the module's changes
      splash.agentLogo = lib.mkDefault "${config.package.unwrapped}/share/icons/hicolor/256x256/apps/claude-desktop.png";
    }
  ];
}
