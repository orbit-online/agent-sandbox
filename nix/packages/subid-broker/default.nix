{
  buildGoModule,
  lib,
  util-linux,
  ...
}:
buildGoModule {
  pname = "subid-broker";
  version = "0.1.0";
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./go.mod
      ./go.sum
      ./main.go
      ./main_test.go
    ];
  };
  vendorHash = "sha256-/AeexGPNJ4t8NKrmqSbxJTvU1B6AtCRr4Op6NHRtwm8=";
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
