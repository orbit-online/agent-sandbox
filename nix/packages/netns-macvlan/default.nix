{ buildGoModule, lib, ... }:
buildGoModule {
  pname = "netns-macvlan";
  version = "0.1.0";
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./go.mod
      ./go.sum
      ./main.go
    ];
  };
  vendorHash = "sha256-NGNdHlTTdSY56EcqKk7ce9Pn5ruK5/E5uHYe/wgeGYg=";
  env.CGO_ENABLED = 0;
  meta = {
    description = "Give a user-owned network namespace its own macvlan on the LAN";
    mainProgram = "netns-macvlan";
    platforms = lib.platforms.linux;
  };
}
