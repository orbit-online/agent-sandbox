# Claude Desktop, one app on the sandbox's core (nix/home/sandbox): its descriptor, which the core turns into
# agent-sandbox.claude-desktop, and what is Claude Desktop's alone, in app.nix and mcp.nix
{ inputs }:
import ../sandbox { inherit inputs; } {
  name = "claude-desktop";
  appId = "com.anthropic.Claude";
  displayName = "Claude";
  agent = "Claude";
  description = "Claude Desktop";
  # Where the user's CLAUDE.md imports it from
  environmentPath = "/etc/claude/environment.md";
  environment = ./environment.md;
  modules = [
    ./app.nix
    ./mcp.nix
  ];
  # Home Manager's MCP servers, which every launcher's app gets (mcp.nix): local ones, beside the sandbox's own
  assertions =
    { lib, sl, ... }:
    lib.mapAttrsToList (name: s: {
      assertion =
        s.command or null != null
        && !lib.elem name [
          "filesystem"
          "claude-code"
        ];
      message = "agent-sandbox.claude-desktop: programs.mcp.servers.${name} must be a local server (command) and not named filesystem or claude-code, which are the sandbox's own";
    }) sl.hmMcpServers;
}
