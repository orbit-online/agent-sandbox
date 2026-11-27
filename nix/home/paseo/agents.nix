# What the agents Paseo runs get without the user's doing: the sandbox's environment doc and its MCP servers
# (build.mcpServers: the permissions broker's, programs.mcp.servers), in the form each agent reads.
# Claude Code: the doc through its managed memory file, /etc/claude-code/CLAUDE.md, which imports the one at
# environmentPath; the servers in ~/.claude.json's mcpServers (home.sh), which it reads whatever settingSources Paseo's
# SDK sessions pass. Not /etc/claude-code/managed-mcp.json: that one is exclusive and would shut out Paseo's own
# `paseo` server. Codex: both in its system config, /etc/codex/config.toml, a layer below the user's
# ~/.codex/config.toml, merged table by table, the user's winning a key (codex-rs/config/src/loader/mod.rs, merge.rs,
# rust-v0.172.0): the servers as mcp_servers, the doc inlined as developer_instructions, which Paseo puts ahead of its
# own for a thread (codex-app-server-agent.ts). Nothing of Codex's is written into the home. Paseo leaves
# CLAUDE_CONFIG_DIR and CODEX_HOME unset, so these are the files they read
{
  lib,
  pkgs,
  config,
  sl,
  launcherName,
  ...
}:
let
  ids = sl.idsOf launcherName;
  servers = config.build.mcpServers;
  mcpServers = pkgs.writeText "paseo-mcp-servers${ids.suffix}.json" (builtins.toJSON servers);
  # The doc as Codex gets it: the static part and this launcher's, without the frontmatter or the import (Codex
  # follows none), and the servers with the keys Codex takes of a stdio one
  codexConfig =
    pkgs.runCommand "paseo-codex-config${ids.suffix}.toml"
      {
        nativeBuildInputs = [
          pkgs.jq
          pkgs.remarshal
        ];
        inherit (config.build.environment) generated;
        file = config.build.environment.file;
        servers = mcpServers;
      }
      ''
        { cat "$file"; echo; printf '%s' "$generated"; } >doc.md
        jq -n --rawfile doc doc.md --slurpfile s "$servers" '{
          developer_instructions: $doc,
          mcp_servers: ($s[0] | map_values({command} + (if .args then {args} else {} end) + (if .env then {env} else {} end)))
        }' >config.json
        json2toml config.json $out
      '';
  claudeJson = sl.hostBindOf config ".claude.json";
in
{
  options.mcpServers = lib.mkOption {
    type = lib.types.attrsOf (pkgs.formats.json { }).type;
    readOnly = true;
    default = servers;
    defaultText = lib.literalMD "the sandbox's servers and `programs.mcp.servers`";
    description = "Local MCP servers the agents Paseo runs get: merged at each launch into Claude Code's `~/.claude.json` beside the user's own, and in Codex's system config, `/etc/codex/config.toml`: the permissions broker's `permissions` server and `programs.mcp.servers`. A server of the user's by the same name wins.";
  };

  config = {
    build.mcpServers = sl.hmMcpServers;
    files."/etc/claude-code/CLAUDE.md".text = "@${sl.app.environmentPath}\n";
    files."/etc/codex/config.toml".source = codexConfig;
    build.storeRoots = [ mcpServers ];
    build.stateVars = {
      MCP_SERVERS = "${mcpServers}";
      MCP_RECORD = "${ids.home}/.local/state/agent-sandbox/mcp-servers.json";
      # Bound from the host as a file, the host's: left alone (and out of reach of the confined step, which binds
      # directories)
      CLAUDE_JSON = lib.optionalString (claudeJson == null) "${ids.home}/.claude.json";
    };
  };
}
