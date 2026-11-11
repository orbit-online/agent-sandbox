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
  # Runs in nixpak's pasta slot, see net-setup.sh
  netSetup = sl.script "net-setup.sh" {
    name = "pasta";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.util-linux
      pkgs.iproute2
    ];
    vars = {
      NETNS_MACVLAN = "${osConfig.security.wrapperDir}/netns-macvlan";
      DHCP_ROOT = lib.getExe dhcpRoot;
      # Salts the macvlan's MAC, so launchers don't clash on the LAN
      NAME = lib.optionalString (launcherName != null) launcherName;
    };
  };
  nixpak = config.build.sandboxed.config;
in
{
  build.storeRoots = [ netSetup ];
  # Hardcoded, see netSetup. transparent: bind the host's /etc/hosts and resolv.conf (both covered in fhs.nix), no
  # extra pasta args
  build.nixpak = [
    {
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
