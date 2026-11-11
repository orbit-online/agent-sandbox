# The app's local MCP servers: the sandbox's filesystem (its binds) and claude-code, the features' own, and Home
# Manager's programs.mcp.servers
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
  options.mcpChannels = lib.mkOption {
    type = lib.types.listOf (lib.types.strMatching "[A-Za-z0-9_-]+");
    default = [ ];
    example = [ "osticket" ];
    description = ''
      Servers in `mcpServers` whose `notifications/claude/channel` the app delivers into a Code session, as a turn of
      its own holding `<mcp-event server="NAME">`, the content, `</mcp-event>`. The notification's `params` are
      `{ content, meta: { session } }`: `session` a session's `local_<uuid>` id, `content` at most 2000 characters
      without `<` or `>`. An archived session is unarchived first; one the app no longer has or can't deliver to gets a
      new session in its folder, or in the home directory. Only the server's copy for the sessions delivers, the one
      whose MCP client is named `local-agent-mode-NAME`: the app starts each server a second time for its chat.
    '';
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
          pkgs.writeShellApplication {
            name = "mcp-server-filesystem";
            runtimeInputs = [ pkgs.jq ];
            # Claude Desktop rejects the draft-07 $schema the server declares (modelcontextprotocol/servers#4841).
            # The client's roots are dropped, so the CLI args stay the allowed dirs
            text = ''
              jq -c --unbuffered 'select(.method != "notifications/roots/list_changed")
                | if .method == "initialize" then del(.params.capabilities.roots) end' |
                ${lib.getExe pkgs.mcp-server-filesystem} "$@" |
                jq -c --unbuffered 'walk(if type == "object" then del(."$schema") else . end)'
            '';
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
    assertions = map (name: {
      assertion = config.mcpServers ? ${name};
      message = "${ids.opt}mcpChannels names ${name}, which isn't in mcpServers";
    }) config.mcpChannels;
  };
}
