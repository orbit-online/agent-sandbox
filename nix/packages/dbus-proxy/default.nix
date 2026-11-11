{
  buildGoModule,
  lib,
  dbus,
  ...
}:
buildGoModule {
  pname = "dbus-proxy";
  version = "0.1.0";
  # The root module's go.mod and the binary's package, so other changes don't rebuild it
  src = lib.fileset.toSource {
    root = ../../..;
    fileset = lib.fileset.unions [
      ../../../go.mod
      ../../../go.sum
      ../../../cmd/dbus-proxy
    ];
  };
  # The binary and its own internal/ packages, whose tests run too
  subPackages = [ "cmd/dbus-proxy/..." ];
  vendorHash = "sha256-WzKEXB0gc22cyl9MoTCOa84Ziz5PwX2K7Gm9fXRu+SI=";
  # A static binary; the tests run with the race detector, which needs cgo
  env.CGO_ENABLED = 0;
  preCheck = ''
    export CGO_ENABLED=1
  '';
  checkFlags = [ "-race" ];
  # The tests run a dbus-daemon of their own, and dbus-send as a libdbus client
  nativeCheckInputs = [ dbus ];
  # Under xdg-dbus-proxy's name too: the module hands it to nixpak as pkgs.xdg-dbus-proxy, whose wrapper runs
  # bin/xdg-dbus-proxy
  postInstall = ''
    ln -s dbus-proxy $out/bin/xdg-dbus-proxy
  '';
  meta = {
    description = "Filter a sandbox's D-Bus traffic, taking xdg-dbus-proxy's arguments";
    mainProgram = "dbus-proxy";
    platforms = lib.platforms.linux;
  };
}
