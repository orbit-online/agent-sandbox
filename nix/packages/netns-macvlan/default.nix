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
    ];
  };
  subPackages = [ "cmd/netns-macvlan" ];
  vendorHash = "sha256-9xChTn8g6LMOz7R8FLGVh75coc8a4Ipck7/bPvLbSyA=";
  env.CGO_ENABLED = 0;
  meta = {
    description = "Give a user-owned network namespace its own macvlan on the LAN";
    mainProgram = "netns-macvlan";
    platforms = lib.platforms.linux;
  };
}
