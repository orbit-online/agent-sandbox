{
  buildGoModule,
  lib,
  libbpf,
  linuxHeaders,
  llvmPackages,
  runCommand,
  ...
}:
let
  # The programs, which the binary loads from the store
  object =
    runCommand "sandbox-uplink.bpf.o"
      {
        nativeBuildInputs = [ llvmPackages.clang-unwrapped ];
        # With the headers it includes, by their paths in the repo
        src = lib.fileset.toSource {
          root = ../../..;
          fileset = lib.fileset.unions [
            ../../../cmd/sandbox-uplink/uplink.bpf.c
            ../../../internal/uplink/uplink.bpf.h
          ];
        };
      }
      ''
        clang -O2 -g -Wall -Werror -target bpf -I${lib.getDev libbpf}/include -I${linuxHeaders}/include \
          -c $src/cmd/sandbox-uplink/uplink.bpf.c -o $out
      '';
in
buildGoModule {
  pname = "sandbox-uplink";
  version = "0.1.0";
  # The root module's go.mod, the binary's package and what it uses from internal/, so other changes don't rebuild it
  src = lib.fileset.toSource {
    root = ../../..;
    fileset = lib.fileset.unions [
      ../../../go.mod
      ../../../go.sum
      ../../../cmd/sandbox-uplink
      ../../../internal/journal
      ../../../internal/uplink
    ];
  };
  subPackages = [ "cmd/sandbox-uplink" ];
  vendorHash = "sha256-c4SDibQJBTsXkcVfi4x+2aq382KqP1F+79VumaZao0o=";
  env.CGO_ENABLED = 0;
  ldflags = [ "-X main.object=${object}" ];
  meta = {
    description = "Keep the programs of the sandbox network attached on the uplinks, around einat";
    mainProgram = "sandbox-uplink";
    platforms = lib.platforms.linux;
  };
}
