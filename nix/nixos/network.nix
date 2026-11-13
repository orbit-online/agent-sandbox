# The host side of the sandbox network: einat NATs the sandboxes on the uplinks, and sandbox-uplink keeps the
# programs around it attached (cmd/sandbox-uplink). claude-desktop.nix enables it when a user enables the sandbox
{ self }:
{
  lib,
  config,
  pkgs,
  ...
}:
let
  cfg = config.agent-sandbox.network;
  packages = self.packages.${pkgs.stdenv.hostPlatform.system};
  uplink = lib.getExe packages.sandbox-uplink;
  uplinkArgs = lib.escapeShellArgs (
    map (u: "--uplink=${u}") (lib.optionals (cfg.uplinks != null) cfg.uplinks)
  );
  # The bpffs sandbox-uplink pins in (internal/uplink.PinDir): its own instance, as /sys/fs/bpf belongs to root alone
  pinDir = "/run/sandbox-uplink";
  # The netkit primaries' names (internal/uplink.PrimaryPrefix)
  primaries = "sbx-*";
  hardening = {
    CapabilityBoundingSet = [
      "CAP_BPF"
      "CAP_NET_ADMIN"
    ];
    AmbientCapabilities = [
      "CAP_BPF"
      "CAP_NET_ADMIN"
    ];
    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;
    ProtectKernelModules = true;
    ProtectKernelTunables = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    ProtectProc = "invisible";
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    SystemCallFilter = [
      "@system-service"
      "bpf"
    ];
    RestrictAddressFamilies = [
      "AF_NETLINK"
      "AF_UNIX"
      "AF_INET"
      "AF_INET6"
    ];
    UMask = "0077";
  };
in
{
  options.agent-sandbox.network = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      internal = true;
      description = "Run the host side of the sandbox network. On when a user enables the sandbox.";
    };
    uplinks = lib.mkOption {
      type = lib.types.nullOr (lib.types.listOf lib.types.str);
      default = null;
      example = [ "enp3s0" ];
      description = ''
        The devices the sandboxes reach the network through, NATed by einat. By default every physical NIC carrying
        Ethernet frames (Ethernet and Wi-Fi), or the bridge or bond it is enslaved to, found when einat starts and
        again when a NIC appears.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        # The primary and peer programs of netkit and bpf_redirect_peer into netkit came in 6.7, the uid and gid options
        # of bpffs (the mount at pinDir) in 6.8; 6.7 ignores them and sandbox-uplink couldn't pin
        assertion = lib.versionAtLeast config.boot.kernelPackages.kernel.version "6.8";
        message = "agent-sandbox: the sandbox network needs Linux 6.8 or later, this machine has ${config.boot.kernelPackages.kernel.version}.";
      }
    ];

    users.users.sandbox-uplink = {
      isSystemUser = true;
      group = "sandbox-uplink";
    };
    # The per-launcher helper registers sandbox addresses as this group
    users.groups.sandbox-uplink = { };

    systemd.mounts = [
      {
        what = "bpffs";
        where = pinDir;
        type = "bpf";
        # netns-netkit, setgid sandbox-uplink, makes a dir per sandbox here. bpffs makes its root sticky
        options = "mode=0770,uid=sandbox-uplink,gid=sandbox-uplink";
      }
    ];

    # Unmodified einat-ebpf, without root: loading and attaching its programs needs CAP_BPF and CAP_NET_ADMIN,
    # bpf_trace_printk and its timers CAP_PERFMON
    systemd.services.sandbox-einat = {
      description = "einat, NAT for the sandbox network";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = hardening // {
        # Skips without an uplink, which einat refuses
        ExecCondition = "${uplink} einat-config ${uplinkArgs} %t/sandbox-einat/einat.toml";
        ExecStart = "${lib.getExe' packages.einat "einat"} -c %t/sandbox-einat/einat.toml";
        Restart = "on-failure";
        DynamicUser = true;
        RuntimeDirectory = "sandbox-einat";
        CapabilityBoundingSet = hardening.CapabilityBoundingSet ++ [ "CAP_PERFMON" ];
        AmbientCapabilities = hardening.AmbientCapabilities ++ [ "CAP_PERFMON" ];
      };
    };

    # A restart of einat (a new uplink) restarts it too, for the uplinks; einat moving ahead of pre otherwise (link
    # up) it follows on its own. Its links stay pinned when it stops
    systemd.services.sandbox-uplink = {
      description = "Programs of the sandbox network around einat on the uplinks";
      wantedBy = [ "sandbox-einat.service" ];
      partOf = [ "sandbox-einat.service" ];
      after = [ "sandbox-einat.service" ];
      unitConfig.RequiresMountsFor = pinDir;
      serviceConfig = hardening // {
        Type = "notify";
        ExecStart = "${uplink} run ${uplinkArgs}";
        Restart = "on-failure";
        User = "sandbox-uplink";
        Group = "sandbox-uplink";
        # Its IP sockets only join the mDNS groups; the kernel sends the reports
        IPAddressDeny = "any";
        # And forwarding on the netkit primaries, which ProtectKernelTunables would keep read-only
        ReadWritePaths = [
          pinDir
          "/proc/sys/net/ipv4/conf"
          "/proc/sys/net/ipv6/conf"
        ];
      };
    };

    # A new physical NIC can be a new uplink (with uplinks set, one of those back): einat again when its config
    # changes, which loses its NAT state, or when it isn't running (failed or stopped)
    systemd.services.sandbox-einat-reload = {
      description = "Restart einat when its uplinks changed";
      path = [
        pkgs.diffutils
        config.systemd.package
      ];
      serviceConfig = {
        Type = "oneshot";
        PrivateTmp = true;
      };
      script = ''
        new=$(mktemp)
        if ${uplink} einat-config ${uplinkArgs} "$new"; then
          cmp -s "$new" /run/sandbox-einat/einat.toml && systemctl -q is-active sandbox-einat.service && exit 0
        elif ! systemctl -q is-active sandbox-einat.service; then
          exit 0
        fi
        systemctl --no-block restart sandbox-einat.service
      '';
    };
    services.udev.extraRules =
      let
        match =
          if cfg.uplinks == null then
            ''TEST=="device"''
          else
            # The final name, after .link files renamed it
            ''NAME=="${lib.concatStringsSep "|" cfg.uplinks}"'';
      in
      ''
        ACTION=="add", SUBSYSTEM=="net", ${match}, RUN+="${lib.getExe' config.systemd.package "systemctl"} --no-block restart sandbox-einat-reload.service"
      '';

    # dhcpcd gives a new netkit primary an IPv4LL address otherwise
    networking.dhcpcd.denyInterfaces = [ primaries ];
    networking.networkmanager.unmanaged = [ "interface-name:${primaries}" ];
    systemd.network.networks."10-sandbox-primaries" = lib.mkIf config.systemd.network.enable {
      matchConfig.Name = primaries;
      linkConfig.Unmanaged = true;
    };
  };
}
