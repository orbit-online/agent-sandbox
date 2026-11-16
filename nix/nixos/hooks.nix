# Root-owned hooks the launcher runs at phases of each sandbox through the sandbox-hooks wrapper (sandbox-hooks --help),
# for consumers to do what needs privileges, a device moved into the netns of the sandbox say. The wrapper holds the
# union of the capabilities the hooks declare, setgid sandbox-hooks; without hooks there is no wrapper.
# claude-desktop.nix imports it
{ self }:
{
  lib,
  config,
  pkgs,
  ...
}:
let
  cfg = config.agent-sandbox.hooks;
  capabilities = [
    "CAP_CHOWN"
    "CAP_DAC_OVERRIDE"
    "CAP_DAC_READ_SEARCH"
    "CAP_FOWNER"
    "CAP_FSETID"
    "CAP_KILL"
    "CAP_SETGID"
    "CAP_SETUID"
    "CAP_SETPCAP"
    "CAP_LINUX_IMMUTABLE"
    "CAP_NET_BIND_SERVICE"
    "CAP_NET_BROADCAST"
    "CAP_NET_ADMIN"
    "CAP_NET_RAW"
    "CAP_IPC_LOCK"
    "CAP_IPC_OWNER"
    "CAP_SYS_MODULE"
    "CAP_SYS_RAWIO"
    "CAP_SYS_CHROOT"
    "CAP_SYS_PTRACE"
    "CAP_SYS_PACCT"
    "CAP_SYS_ADMIN"
    "CAP_SYS_BOOT"
    "CAP_SYS_NICE"
    "CAP_SYS_RESOURCE"
    "CAP_SYS_TIME"
    "CAP_SYS_TTY_CONFIG"
    "CAP_MKNOD"
    "CAP_LEASE"
    "CAP_AUDIT_WRITE"
    "CAP_AUDIT_CONTROL"
    "CAP_SETFCAP"
    "CAP_MAC_OVERRIDE"
    "CAP_MAC_ADMIN"
    "CAP_SYSLOG"
    "CAP_WAKE_ALARM"
    "CAP_BLOCK_SUSPEND"
    "CAP_AUDIT_READ"
    "CAP_PERFMON"
    "CAP_BPF"
    "CAP_CHECKPOINT_RESTORE"
  ];
  hookType = lib.types.submodule {
    options = {
      path = lib.mkOption {
        type = lib.types.pathInStore;
        description = "The executable, a store path: sandbox-hooks refuses one that isn't a file of root.";
      };
      capabilities = lib.mkOption {
        type = lib.types.listOf (lib.types.enum capabilities);
        default = [ ];
        example = [ "CAP_NET_ADMIN" ];
        description = "The capabilities the hook holds on the host, and all it holds.";
      };
    };
  };
  phase =
    when: args:
    lib.mkOption {
      type = lib.types.listOf hookType;
      default = [ ];
      description = ''
        Hooks the launcher of every sandbox of every user runs ${when}, in order, as `<hook> ${args}` (the launcher
        name empty for the default one), with the capabilities each declares, the user's uid and group
        `sandbox-hooks` as its gids, an empty environment and `/`, killed after 30 seconds. A hook that fails is
        logged${lib.optionalString (args != "stop <uid> <launcher name>") ", and the sandbox starts without what it does after a warning on the splash"}.
      '';
    };
  all = cfg.start ++ cfg.stop;
  caps = lib.unique (lib.concatMap (h: h.capabilities) all);
in
{
  options.agent-sandbox.hooks = {
    start =
      phase
        "once the network namespace of the sandbox is set up (its netkit pair and addresses), before the app starts and before the launcher's network.hooks, with that network namespace on fd 3 (`ip link set <dev> netns /proc/self/fd/3`)"
        "start <uid> <launcher name>";
    stop = phase "after the sandbox ended" "stop <uid> <launcher name>";
  };

  # Only with a sandbox user, as netns-netkit
  config = lib.mkIf (all != [ ] && config.agent-sandbox.network.enable) {
    # Read by sandbox-hooks, which checks that root owns it and every hook in it
    environment.etc."agent-sandbox/hooks.json".text = builtins.toJSON (
      lib.mapAttrs (_: map (h: { inherit (h) path capabilities; })) { inherit (cfg) start stop; }
    );
    users.groups.sandbox-hooks = { };
    # As netns-netkit: the wrapper module keeps setgid to wrappers without capabilities, so it goes in permissions, and
    # the helper refuses callers outside group users itself. Without a capability, none in the set
    security.wrappers.sandbox-hooks = {
      source = lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.sandbox-hooks;
      capabilities = lib.optionalString (caps != [ ]) "${lib.concatMapStringsSep "," lib.toLower caps}+ep";
      owner = "root";
      group = "sandbox-hooks";
      permissions = "u+rx,g+xs,o+x";
    };
  };
}
