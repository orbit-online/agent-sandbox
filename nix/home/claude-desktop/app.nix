# Claude Desktop in its FHS env: its package, the asar patch (patch-asar.sh: the ready line, the tray icon, the
# notification backend, the MCP channels), the directories it keeps in the home (~/.claude and ~/.config/Claude,
# bound from the host's for the default launcher), its config merged at each launch, and `claude` on PATH
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
  ids = sl.idsOf launcherName;
  sys = {
    mcp = false;
  };
  # Where a path under the home directory is on the host: its bind's source, or the sandbox's home
  hostBind =
    rel:
    let
      b = config.permissions.binds."${hm.home.homeDirectory}/${rel}" or null;
    in
    if b != null && b.enable then b.src else null;
  hostPath = rel: if hostBind rel != null then hostBind rel else "${ids.home}/${rel}";
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

  config = {
    # A named launcher keeps them in its own home
    permissions.binds = lib.mkIf (launcherName == null) {
      "${hm.home.homeDirectory}/.claude".rw = true;
      "${hm.home.homeDirectory}/.config/Claude" = sys // {
        rw = true;
      };
    };
    # The state script's home step (state.sh) works in the bind sources of ~/.claude and ~/.config/Claude where they're
    # bound, and merges the app's config: it writes to the file too, so a merge rather than a link to the store
    build.homeDirs = lib.filter (d: d != null) [
      (hostBind ".claude")
      (hostBind ".config/Claude")
    ];
    build.stateInputs = [ pkgs.jq ];
    build.stateVars = {
      DOT_CLAUDE = hostPath ".claude";
      CONFIG = "${hostPath ".config/Claude"}/claude_desktop_config.json";
      MCP_SERVERS = "${pkgs.writeText "mcp-servers.json" (builtins.toJSON config.mcpServers)}";
      TRAY = lib.boolToString config.features.tray.enable;
    };
    build.stateHome = ''
      : "''${DOT_CLAUDE:?}" "''${CONFIG:?}" "''${MCP_SERVERS:?}" "''${TRAY:?}"
      mkdir -p "$DOT_CLAUDE" "''${CONFIG%/*}"
      config='{}'
      [[ ! -s $CONFIG ]] || config=$(<"$CONFIG")
      jq --slurpfile m "$MCP_SERVERS" --argjson tray "$TRAY" \
        '.mcpServers = $m[0] | .preferences.menuBarEnabled = $tray' <<<"$config" | replace "$CONFIG"
    '';
    build.pathPackages = [ claudeCode ];
    build.fhsBwrapArgs = [ "--ro-bind ${patchedAsar} ${asar}" ];
    # The core's arguments to the package's buildFHSEnv, through the core's bwrap
    build.app = config.package.override (prev: {
      buildFHSEnv = args: (prev.buildFHSEnv.override { bubblewrap = sl.bwrapFhs; }) (config.build.fhsEnvArgs args);
    });
    # The unwrapped app, which the closure holds anyway; package would bring its FHS env without the module's changes
    splash.agentLogo = lib.mkDefault "${config.package.unwrapped}/share/icons/hicolor/256x256/apps/claude-desktop.png";
  };
}
