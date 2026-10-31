{
  buildGoModule,
  lib,
  util-linux,
  ...
}:
buildGoModule {
  pname = "subid-broker";
  version = "0.1.0";
  # The root module's go.mod, the binary's package and what it uses from internal/, so other changes don't rebuild it
  src = lib.fileset.toSource {
    root = ../../..;
    fileset = lib.fileset.unions [
      ../../../go.mod
      ../../../go.sum
      ../../../cmd/subid-broker
      ../../../internal/proc
    ];
  };
  subPackages = [ "cmd/subid-broker" ];
  vendorHash = "sha256-6WYYokJ/y3VehAE6U6RdX5+6Tvi+yP/WjHCeabw+1Xg=";
  env.CGO_ENABLED = 0;
  ldflags = [ "-X main.nsenter=${lib.getExe' util-linux "nsenter"}" ];
  # The shims, which the sandbox puts where shadow's would be
  postInstall = ''
    ln -s subid-broker $out/bin/newuidmap
    ln -s subid-broker $out/bin/newgidmap
  '';
  meta = {
    description = "Write uid and gid maps for user namespaces inside a sandbox";
    mainProgram = "subid-broker";
    platforms = lib.platforms.linux;
  };
}
