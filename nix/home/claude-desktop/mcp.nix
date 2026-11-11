# The app's local MCP servers: the sandbox's filesystem (its binds) and claude-code, the features' own, and Home
# Manager's programs.mcp.servers
{
  lib,
  pkgs,
  config,
  hm,
  inputs,
  sl,
  ...
}:
let
  # The Bash tool sources CLAUDE_ENV_FILE before each command. The Code tab gets this from the SessionStart hook,
  # which claude mcp serve does not run. Drops the snapshot's ugrep/bfs shadows of grep and find
  bashEnv = pkgs.writeText "claude-bash-env" "unset -f grep find 2>/dev/null\n";
in
{
  options.mcpServers = lib.mkOption {
    type = lib.types.attrsOf (pkgs.formats.json { }).type;
    readOnly = true;
    default = config.build.mcpServers;
    defaultText = lib.literalMD "the sandbox's servers and `programs.mcp.servers`";
    description = "Local MCP servers the app gets, replacing `mcpServers` in claude_desktop_config.json on launch: the sandbox's `filesystem` and `claude-code`, and `programs.mcp.servers`.";
  };
  # What the features add to mcpServers
  options.build.mcpServers = lib.mkOption {
    type = lib.types.attrsOf (pkgs.formats.json { }).type;
    internal = true;
    visible = false;
  };

  config.build = {
    mcpServers = {
      filesystem = {
        command = lib.getExe (
          sl.script "mcp-server-filesystem.sh" {
            runtimeInputs = [ pkgs.jq ];
            vars.MCP_SERVER_FILESYSTEM = lib.getExe pkgs.mcp-server-filesystem;
          }
        );
        args = lib.attrNames (lib.filterAttrs (_: b: b.enable && b.mcp) config.binds);
      };
      claude-code = {
        command = lib.getExe inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.claude-code;
        args = [
          "mcp"
          "serve"
        ];
        env = {
          PATH = sl.searchPathOf config;
          CLAUDE_ENV_FILE = "${bashEnv}";
          NIX_CONF_DIR = "${sl.nixConf}";
        };
      };
    }
    // sl.hmMcpServers;
    storeRoots = [
      (pkgs.writeText "mcp-servers.json" (builtins.toJSON config.mcpServers))
      bashEnv
    ];
  };
}
