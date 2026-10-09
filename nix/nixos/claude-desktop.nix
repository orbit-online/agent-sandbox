{ self }:
{
  lib,
  config,
  pkgs,
  ...
}:
let
  # The Home Manager users who enable the sandbox
  users = lib.attrNames (
    lib.filterAttrs (_: u: u.agent-sandbox.claude-desktop.enable or false) (
      config.home-manager.users or { }
    )
  );
  inUsersGroup =
    name:
    let
      u = config.users.users.${name};
    in
    u.group == "users"
    || lib.elem "users" u.extraGroups
    || lib.elem name config.users.groups.users.members;
in
{
  config = lib.mkIf (users != [ ]) {
    # Gives a claude-desktop sandbox its own LAN interface, see netns-macvlan --help. Human users only: whoever can run it
    # can give their own namespaces a LAN interface outside the host firewall
    security.wrappers.netns-macvlan = {
      source = lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.netns-macvlan;
      capabilities = "cap_net_admin+ep";
      owner = "root";
      group = "users";
      permissions = "u+rx,g+x";
    };
    assertions = map (name: {
      assertion = inUsersGroup name;
      message = "agent-sandbox.claude-desktop: ${name} enables the sandbox but isn't in group users, which netns-macvlan is limited to. Add users to users.users.${name}.extraGroups.";
    }) users;
  };
}
