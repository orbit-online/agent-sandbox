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
  # The sandbox maps the first one into its user namespace, see bwrap-subid.sh
  hasSubIds =
    name:
    let
      u = config.users.users.${name};
    in
    u.autoSubUidGidRange || (u.subUidRanges != [ ] && u.subGidRanges != [ ]);
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
    assertions = lib.concatMap (name: [
      {
        assertion = inUsersGroup name;
        message = "agent-sandbox.claude-desktop: ${name} enables the sandbox but isn't in group users, which netns-macvlan is limited to. Add users to users.users.${name}.extraGroups.";
      }
      {
        assertion = hasSubIds name;
        message = "agent-sandbox.claude-desktop: ${name} enables the sandbox but has no subordinate uid and gid range, which the sandbox maps into its user namespace. Set users.users.${name}.autoSubUidGidRange, or subUidRanges and subGidRanges.";
      }
    ]) users;
  };
}
