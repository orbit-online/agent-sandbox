# Paseo, an app on the sandbox's core (nix/home/sandbox): its descriptor, which the core turns into agent-sandbox.paseo,
# and what is Paseo's alone, in app.nix (the app) and agents.nix (what the agents it runs get)
{ inputs }:
import ../sandbox { inherit inputs; } {
  name = "paseo";
  appId = "sh.paseo.Paseo";
  displayName = "Paseo";
  # The broker's words ("Paseo wants to …"): Paseo runs several agents, and the name says which sandbox asks
  agent = "Paseo";
  description = "Paseo";
  # Claude Code's convention, as in Claude Desktop's sandbox, so a user's CLAUDE.md imports it in either. Claude Code
  # in Paseo gets it through /etc/claude-code/CLAUDE.md, Codex inlined in ~/.codex/AGENTS.md (agents.nix)
  environmentPath = "/etc/claude/environment.md";
  environment = ./environment.md;
  modules = [
    ./app.nix
    ./agents.nix
  ];
  # Home Manager's MCP servers, which every launcher's agents get (agents.nix): local ones, as Codex gets their
  # command, args and env alone, and not named paseo, the server Paseo hands every agent itself
  assertions =
    { lib, sl, ... }:
    lib.mapAttrsToList (name: s: {
      assertion = s.command or null != null && name != "paseo";
      message = "agent-sandbox.paseo: programs.mcp.servers.${name} must be a local server (command) and not named paseo, which is the server Paseo gives its agents";
    }) sl.hmMcpServers;
}
