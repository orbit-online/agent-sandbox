# The host side of every app's sandboxes (nix/home/sandbox), for every Home Manager user who enables one: the netkit
# helper, the sandbox network, the hooks, and each sandbox's journald namespaces
{ self }:
{
  lib,
  config,
  pkgs,
  ...
}:
let
  # Each Home Manager user's sandboxes of the apps they enable, any app (the Home Manager module's shared.nix)
  sandboxesOf = u: lib.filter (s: s.enable) (u.agent-sandbox.sandboxes or [ ]);
  # The Home Manager users who enable a sandbox
  users = lib.attrNames (
    lib.filterAttrs (_: u: sandboxesOf u != [ ]) (config.home-manager.users or { })
  );
  inUsersGroup =
    name:
    let
      u = config.users.users.${name};
    in
    u.group == "users"
    || lib.elem "users" u.extraGroups
    || lib.elem name config.users.groups.users.members;
  # Each sandbox's journald namespaces, the host side's and the sandbox's, see the Home Manager module's lib.nix
  # (ids.journal, ids.sandboxJournal)
  journals = lib.unique (
    lib.concatMap (
      u:
      lib.concatMap (s: [
        s.journal
        s.sandboxJournal
      ]) (sandboxesOf config.home-manager.users.${u})
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
  imports = [
    (import ./network.nix { inherit self; })
    (import ./hooks.nix { inherit self; })
  ];

  options.agent-sandbox.delegateCpuset = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = ''
      Delegate the cpuset controller to every user's manager, and so to the sandboxes, next to the pids, memory and cpu
      that systemd's user@.service delegates. k3s and kubelet refuse to start without it. Inside its own subtree a
      sandbox can then only narrow the CPUs and memory nodes its processes run on to a subset of its parent's. A
      partition, which would take CPUs from the rest of the machine, needs a partition root as parent or
      cpuset.cpus.exclusive set in every ancestor below the root cgroup, which the sandbox can't write (the kernel's
      cgroup-v2.rst, Cpuset).
    '';
  };

  config = lib.mkIf (users != [ ]) {
    # A drop-in: a list of controllers adds to user@.service's (systemd.resource-control(5), Delegate=)
    systemd.services."user@".serviceConfig.Delegate =
      lib.mkIf config.agent-sandbox.delegateCpuset "cpuset";
    agent-sandbox.network.enable = true;
    # Connects a sandbox to the network through a netkit pair, see netns-netkit --help: cap_net_admin and
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
        message = "agent-sandbox: ${name} enables a sandbox but isn't in group users, which netns-netkit is limited to. Add users to users.users.${name}.extraGroups.";
      }
      {
        assertion = hasSubIds name;
        message = "agent-sandbox: ${name} enables a sandbox but has no subordinate uid and gid range, which the sandbox maps into its user namespace. Set users.users.${name}.autoSubUidGidRange, or subUidRanges and subGidRanges.";
      }
    ]) users;
  };
}
