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
  # Each launcher's journald namespaces, the host side's and the sandbox's, see the Home Manager module's lib.nix
  # (ids.journal, ids.sandboxJournal)
  journals = lib.unique (
    lib.concatMap (
      u:
      lib.concatMap
        (
          n:
          let
            j = "claude-desktop${lib.optionalString (n != null) "-${n}"}";
          in
          [
            j
            "${j}_sandbox"
          ]
        )
        ([ null ] ++ lib.attrNames config.home-manager.users.${u}.agent-sandbox.claude-desktop.launchers)
    ) users
  );
  # The sandbox maps the first one into its user namespace, see cmd/launcher's bwrap.go
  hasSubIds =
    name:
    let
      u = config.users.users.${name};
    in
    u.autoSubUidGidRange || (u.subUidRanges != [ ] && u.subGidRanges != [ ]);
in
{
  imports = [ (import ./network.nix { inherit self; }) ];

  config = lib.mkIf (users != [ ]) {
    agent-sandbox.network.enable = true;
    # Connects a claude-desktop sandbox to the network through a netkit pair, see netns-netkit --help: cap_net_admin and
    # cap_bpf for the pair and its programs, setgid sandbox-uplink for the maps pinned in the bpffs of network.nix.
    # The wrapper module keeps setgid to wrappers without capabilities, so it goes in permissions. Setgid takes the
    # group of the file, so the helper itself refuses callers outside group users: whoever runs it gives their own
    # namespaces a network outside the host firewall
    security.wrappers.netns-netkit = {
      source = lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.netns-netkit;
      capabilities = "cap_net_admin,cap_bpf+ep";
      owner = "root";
      group = "sandbox-uplink";
      permissions = "u+rx,g+xs,o+x";
    };
    # Two journald namespaces per launcher (systemd-journald@.service), whose files the launcher binds into the sandbox,
    # so their directories have to be there before journald first starts
    systemd.targets.sockets.wants = map (j: "systemd-journald@${j}.socket") journals;
    systemd.tmpfiles.rules = map (j: "d /var/log/journal/%m.${j} 2755 root systemd-journal - -") journals;
    assertions = lib.concatMap (name: [
      {
        assertion = inUsersGroup name;
        message = "agent-sandbox.claude-desktop: ${name} enables the sandbox but isn't in group users, which netns-netkit is limited to. Add users to users.users.${name}.extraGroups.";
      }
      {
        assertion = hasSubIds name;
        message = "agent-sandbox.claude-desktop: ${name} enables the sandbox but has no subordinate uid and gid range, which the sandbox maps into its user namespace. Set users.users.${name}.autoSubUidGidRange, or subUidRanges and subGidRanges.";
      }
    ]) users;
  };
}
