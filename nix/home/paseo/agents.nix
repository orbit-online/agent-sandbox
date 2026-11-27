# What the agents Paseo runs get without the user's doing: the sandbox's environment doc and its MCP servers
# (build.mcpServers: the permissions broker's, programs.mcp.servers), in the form each agent reads.
# Claude Code: the doc through its managed memory file, /etc/claude-code/CLAUDE.md, which imports the one at
# environmentPath; the servers in ~/.claude.json's mcpServers, which it reads whatever settingSources Paseo's SDK
# sessions pass. Not /etc/claude-code/managed-mcp.json: that one is exclusive and would shut out Paseo's own `paseo`
# server. Codex: both in a block of its own in ~/.codex/config.toml and ~/.codex/AGENTS.md, the doc inlined, as Codex
# follows no imports. Paseo leaves CLAUDE_CONFIG_DIR and CODEX_HOME unset, so these are the files they read
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
  ids = sl.idsOf launcherName;
  servers = config.build.mcpServers;
  # The doc as Codex gets it: the static part and this launcher's, without the frontmatter or the import
  agentsDoc =
    pkgs.runCommand "paseo-agents${ids.suffix}.md" { generated = config.build.environment.generated; }
      ''
        { cat ${config.build.environment.file}; echo; printf '%s' "$generated"; } >$out
      '';
  # Codex's keys of a stdio server
  codexMcp = (pkgs.formats.toml { }).generate "paseo-codex-mcp${ids.suffix}.toml" {
    mcp_servers = lib.mapAttrs (
      _: s:
      lib.filterAttrs (_: v: v != null) {
        inherit (s) command;
        args = s.args or null;
        env = s.env or null;
      }
    ) servers;
  };
  mcpServers = pkgs.writeText "paseo-mcp-servers${ids.suffix}.json" (builtins.toJSON servers);
  claudeJson = sl.hostBindOf config ".claude.json";
in
{
  options.mcpServers = lib.mkOption {
    type = lib.types.attrsOf (pkgs.formats.json { }).type;
    readOnly = true;
    default = servers;
    defaultText = lib.literalMD "the sandbox's servers and `programs.mcp.servers`";
    description = "Local MCP servers the agents Paseo runs get, merged at each launch into Claude Code's `~/.claude.json` and Codex's `~/.codex/config.toml` beside the user's own: the permissions broker's `permissions` server and `programs.mcp.servers`.";
  };

  config = {
    build.mcpServers = sl.hmMcpServers;
    files."/etc/claude-code/CLAUDE.md".text = "@${sl.app.environmentPath}\n";
    build.storeRoots = [
      agentsDoc
      codexMcp
      mcpServers
    ];
    build.stateVars = {
      MCP_SERVERS = "${mcpServers}";
      MCP_RECORD = "${ids.home}/.local/state/agent-sandbox/mcp-servers.json";
      # Bound from the host as a file, out of reach of the confined step, which binds directories: left alone
      CLAUDE_JSON = lib.optionalString (claudeJson == null) "${ids.home}/.claude.json";
      CODEX_DIR = sl.hostPathOf config launcherName ".codex";
      CODEX_MCP = "${if servers == { } then pkgs.writeText "empty" "" else codexMcp}";
      AGENTS_DOC = "${agentsDoc}";
    };
    build.homeDirs = lib.filter (d: d != null) [ (sl.hostBindOf config ".codex") ];
  };
}
