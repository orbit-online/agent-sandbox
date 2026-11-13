# The netns of the sandbox, connected through a netkit pair whose programs let it reach the network through the einat
# uplinks alone (netns-netkit --help, nix/nixos/network.nix), so host services, routes and abstract sockets stay out of
# reach. Always on: there is no option to share the host's
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
  # nixpak's bwrap, mode subid (cmd/launcher bwrap.go), whose helper sets up the netns before nixpak's launcher
  # hears the sandbox is there and lets the app start (helper.go, netSetup)
  bwrapHost = sl.bwrapOf [
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
    "--net=${
      builtins.toJSON (
        {
          netnsNetkit = "${osConfig.security.wrapperDir}/netns-netkit";
          nsenter = lib.getExe' pkgs.util-linux "nsenter";
          ip = lib.getExe' pkgs.iproute2 "ip";
        }
        // lib.optionalAttrs (launcherName != null) { name = launcherName; }
      )
    }"
  ];
  # nixpak's pasta slot, where it runs pasta after bwrap's info and before it lets the app start. A no-op: the bwrap
  # helper set the netns up already. nixpak only gives the sandbox a netns of its own with pasta on
  netSetup = pkgs.writeShellApplication {
    name = "pasta";
    text = ":";
  };
  nixpak = config.build.sandboxed.config;
in
{
  options.nameservers = lib.mkOption {
    type = lib.types.listOf lib.types.str;
    default = [ ];
    example = [ "192.168.1.1" ];
    description = ''
      The DNS servers of the sandbox, which each launch writes to its resolv.conf. The sandbox reaches them through the
      uplinks only: a resolver of the host, on 127.0.0.53 say, is out of its reach.
    '';
  };

  config = {
    build.storeRoots = [ bwrapHost ];
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
        assertion = nixpak.bubblewrap.network && nixpak.pasta.enable && nixpak.pasta.package == netSetup;
        message = "agent-sandbox.claude-desktop: the sandbox always gets its own netns with a netkit pair; ${
          if launcherName == null then "sandbox" else "launchers.${launcherName}.sandbox"
        } must not change bubblewrap.network or pasta";
      }
    ];
  };
}
