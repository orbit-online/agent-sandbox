# The netns of the sandbox, connected through a netkit pair whose programs let it reach the network through the einat
# uplinks alone (netns-netkit --help, nix/nixos/network.nix), so host services, routes and abstract sockets stay out of
# reach. With network.enable off, lo alone. Always its own netns: there is no option to share the host's
{
  lib,
  pkgs,
  config,
  osConfig,
  sl,
  launcherName,
  ...
}:
let
  ids = sl.idsOf launcherName;
  # The NixOS module's hooks (nix/nixos/hooks.nix), which its sandbox-hooks wrapper runs for every launcher
  osHooks = osConfig.agent-sandbox.hooks or {
    start = [ ];
    stop = [ ];
  };
  # An IPv4 or IPv6 address (no prefix length or zone), all a nameserver line of resolv.conf takes
  octet = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
  isIP =
    s:
    builtins.match "${octet}(\\.${octet}){3}" s != null
    || (
      !lib.hasInfix "/" s
      && (builtins.tryEval (builtins.deepSeq (lib.network.ipv6.fromString s) true)).success
    );
  # nixpak's bwrap, mode subid (cmd/launcher bwrap.go), whose helper sets up the netns before nixpak's launcher
  # hears the sandbox is there and lets the app start (helper.go, netSetup)
  bwrapHost = sl.bwrapOf (
    [
      "--mode=subid"
      "--newuidmap=${osConfig.security.wrapperDir}/newuidmap"
      "--newgidmap=${osConfig.security.wrapperDir}/newgidmap"
      "--subid-broker=${lib.getExe sl.packages.subid-broker}"
      "--units=${
        builtins.toJSON {
          systemdRun = lib.getExe' osConfig.systemd.package "systemd-run";
          systemctl = lib.getExe' osConfig.systemd.package "systemctl";
          app = ids.appUnit;
          prefix = ids.unitPrefix;
          inherit (ids) slice journal sandboxJournal;
          systemdCat = lib.getExe' osConfig.systemd.package "systemd-cat";
        }
      }"
    ]
    ++ lib.optional (osHooks.start != [ ]) "--hooks=${
      builtins.toJSON (
        { exe = "${osConfig.security.wrapperDir}/sandbox-hooks"; }
        // lib.optionalAttrs (launcherName != null) { name = launcherName; }
      )
    }"
    # Without it the netns keeps what bwrap gives it: lo, up
    ++ lib.optional config.network.enable "--net=${
      builtins.toJSON (
        {
          netnsNetkit = "${osConfig.security.wrapperDir}/netns-netkit";
          nsenter = lib.getExe' pkgs.util-linux "nsenter";
          ip = lib.getExe' pkgs.iproute2 "ip";
          inherit (config.network) mdns hooks;
        }
        // lib.optionalAttrs (launcherName != null) { name = launcherName; }
      )
    }"
  );
  # nixpak's pasta slot, where it runs pasta after bwrap's info and before it lets the app start. A no-op: the bwrap
  # helper set the netns up already. nixpak only gives the sandbox a netns of its own with pasta on
  netSetup = pkgs.writeShellApplication {
    name = "pasta";
    text = ":";
  };
  nixpak = config.build.sandboxed.config;
in
{
  options.network.enable = lib.mkOption {
    type = lib.types.bool;
    default = true;
    description = ''
      Join the netns of the sandbox to the network (netkit pair, DNS, `port` grants of the permissions broker). Off,
      the sandbox keeps a netns of its own with `lo` alone, for local models say: it reaches servers of the host only
      through host sockets of the permissions broker.
    '';
  };

  options.network.mdns = lib.mkOption {
    type = lib.types.bool;
    default = config.network.enable;
    defaultText = lib.literalExpression "network.enable";
    description = ''
      mDNS (`.local` names) in the sandbox: queries go out of the uplink with the default route, from the address
      of the host and port 5353, and the responses on the LAN come in, to a querier on port 5353 in the sandbox (avahi,
      say; a legacy unicast query from another port gets no answer). Responses, probes and announcements of the sandbox stay in,
      so the sandbox claims no names on the LAN.
    '';
  };

  options.network.hooks = lib.mkOption {
    type = lib.types.listOf lib.types.pathInStore;
    default = [ ];
    description = ''
      Executables the launcher runs in the netns of the sandbox, as the owner of its user namespace (all capabilities
      over the netns, none on the host), once `eth0` is up and the NixOS module's `agent-sandbox.hooks.start` ran,
      before the app starts: addresses and routes for devices such a hook moved in. With an empty environment, so a
      hook names what it runs by its store path. A hook that fails starts the sandbox
      without what it does, after a warning on the splash. Without `network.enable` none run.
    '';
  };

  options.nameservers = lib.mkOption {
    type = lib.types.listOf lib.types.str;
    default = [ ];
    example = [ "192.168.1.1" ];
    description = ''
      The DNS servers of the sandbox, IPv4 or IPv6 addresses, which each launch writes to its resolv.conf. Empty: the
      launcher follows systemd-resolved on the host, or NetworkManager without it, and gives the sandbox the servers of
      the uplink with the default route (none of a VPN); with neither, the sandbox has no DNS. The sandbox reaches its
      servers through the uplinks only: a resolver of the host, on 127.0.0.53 say, is out of its reach.
    '';
  };

  config = {
    build.storeRoots = [ bwrapHost ];
    build.launcherConfig = {
      inherit (config) nameservers;
      network = config.network.enable;
      hooks = osHooks.start ++ osHooks.stop != [ ];
    };
    # Hardcoded, see netSetup. transparent: bind the host's /etc/hosts and resolv.conf (both covered in fhs.nix), no
    # extra pasta args
    build.nixpak = [
      {
        bubblewrap.package = bwrapHost;
        bubblewrap.network = lib.mkForce true;
        pasta = {
          enable = lib.mkForce true;
          package = lib.mkForce netSetup;
          mode = lib.mkForce "transparent";
          args = lib.mkForce [ ];
        };
      }
    ];
    build.assertions = [
      {
        assertion = lib.all isIP config.nameservers;
        message = "agent-sandbox.claude-desktop: ${
          if launcherName == null then "" else "launchers.${launcherName}."
        }nameservers must be IP addresses: ${lib.concatStringsSep ", " (map builtins.toJSON config.nameservers)}";
      }
      {
        assertion = nixpak.bubblewrap.network && nixpak.pasta.enable && nixpak.pasta.package == netSetup;
        message = "agent-sandbox.claude-desktop: the sandbox always gets its own netns with a netkit pair; ${
          if launcherName == null then "sandbox" else "launchers.${launcherName}.sandbox"
        } must not change bubblewrap.network or pasta";
      }
    ];
  };
}
