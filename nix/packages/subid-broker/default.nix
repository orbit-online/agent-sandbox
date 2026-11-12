{
  buildGoModule,
  lib,
  makeBinaryWrapper,
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
      ../../../internal/journal
      ../../../internal/proc
    ];
  };
  subPackages = [ "cmd/subid-broker" ];
  vendorHash = "sha256-mzzwfsVPFJgTBn30CHWEMKt4+eNnAxr7sxuW65oDRYI=";
  env.CGO_ENABLED = 0;
  nativeBuildInputs = [ makeBinaryWrapper ];
  # The shims, which the sandbox puts where shadow's would be. The wrapper passes argv[0] on, which picks the mode
  postInstall = ''
    wrapProgram $out/bin/subid-broker --prefix PATH : ${lib.makeBinPath [ util-linux ]}
    ln -s subid-broker $out/bin/newuidmap
    ln -s subid-broker $out/bin/newgidmap
  '';
  meta = {
    description = "Write uid and gid maps for user namespaces inside a sandbox";
    mainProgram = "subid-broker";
    platforms = lib.platforms.linux;
  };
}
