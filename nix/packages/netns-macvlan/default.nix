{ buildGoModule, lib, ... }:
buildGoModule {
  pname = "netns-macvlan";
  version = "0.1.0";
  # The root module's go.mod, the binary's package and what it uses from internal/, so other changes don't rebuild it
  src = lib.fileset.toSource {
    root = ../../..;
    fileset = lib.fileset.unions [
      ../../../go.mod
      ../../../go.sum
      ../../../cmd/netns-macvlan
      ../../../internal/journal
    ];
  };
  subPackages = [ "cmd/netns-macvlan" ];
  vendorHash = "sha256-TTC3gETdoWGwhDrjb97qkl+b8vx77E3bIBfz0YyI9D0=";
  env.CGO_ENABLED = 0;
  meta = {
    description = "Give a user-owned network namespace its own macvlan on the LAN";
    mainProgram = "netns-macvlan";
    platforms = lib.platforms.linux;
  };
}
