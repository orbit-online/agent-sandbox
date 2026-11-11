# The sandbox's own netns with a macvlan on the LAN (netns-macvlan --help), so host services, routes and abstract
# sockets stay out of reach. Its DHCP lease brings the DNS servers. Always on: there is no option to share the host's
{
  lib,
  pkgs,
  config,
  hm,
  osConfig,
  sl,
  launcherName,
  ...
}:
let
  ids = sl.idsOf launcherName;
  dhcpScript = sl.script "udhcpc.sh" {
    name = "claude-desktop-udhcpc";
    runtimeInputs = [ pkgs.iproute2 ];
    vars.RESOLV_CONF = sl.sandboxResolvConf;
  };
  # udhcpc's mount namespace, see dhcp-root.sh
  dhcpRoot =
    let
      tools = [
        pkgs.coreutils
        pkgs.util-linux
      ];
    in
    sl.script "dhcp-root.sh" {
      name = "claude-desktop-dhcp-root";
      runtimeInputs = tools;
      vars = {
        CLOSURE = "${
          pkgs.closureInfo {
            rootPaths = tools ++ [
              pkgs.busybox
              dhcpScript
            ];
          }
        }/store-paths";
        HOME_SRC = ids.home;
        SANDBOX_HOME = hm.home.homeDirectory;
        BUSYBOX = lib.getExe pkgs.busybox;
        SETPRIV = lib.getExe' pkgs.util-linux "setpriv";
        UDHCPC = lib.getExe' pkgs.busybox "udhcpc";
        UDHCPC_SCRIPT = lib.getExe dhcpScript;
      };
    };
  # nixpak's bwrap, mode subid (cmd/launcher bwrap.go), whose helper sets up the netns before nixpak's launcher
  # hears the sandbox is there and lets the app start (helper.go, netSetup)
  bwrapHost = sl.bwrapOf [
    "--mode=subid"
    "--newuidmap=${osConfig.security.wrapperDir}/newuidmap"
    "--newgidmap=${osConfig.security.wrapperDir}/newgidmap"
    "--subid-broker=${lib.getExe sl.packages.subid-broker}"
    "--net=${
      builtins.toJSON (
        {
          netnsMacvlan = "${osConfig.security.wrapperDir}/netns-macvlan";
          dhcpRoot = lib.getExe dhcpRoot;
          nsenter = lib.getExe' pkgs.util-linux "nsenter";
          unshare = lib.getExe' pkgs.util-linux "unshare";
          ip = lib.getExe' pkgs.iproute2 "ip";
        }
        # Salts the macvlan's MAC, so launchers don't clash on the LAN
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
      message = "agent-sandbox.claude-desktop: the sandbox always gets its own netns with a macvlan; ${
        if launcherName == null then "sandbox" else "launchers.${launcherName}.sandbox"
      } must not change bubblewrap.network or pasta";
    }
  ];
}
