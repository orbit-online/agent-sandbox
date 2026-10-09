{ self }:
{
  lib,
  config,
  pkgs,
  ...
}:
{
  # Gives the claude-desktop sandbox its own LAN interface, see netns-macvlan --help
  config.security.wrappers.netns-macvlan =
    lib.mkIf
      (lib.any (u: u.agent-sandbox.claude-desktop.enable or false) (
        lib.attrValues config.home-manager.users
      ))
      {
        source = lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.netns-macvlan;
        capabilities = "cap_net_admin+ep";
        owner = "root";
        group = "users";
        permissions = "u+rx,g+x";
      };
}
