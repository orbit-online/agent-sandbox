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
    runCommand "netns-netkit.bpf.o"
      {
        nativeBuildInputs = [ llvmPackages.clang-unwrapped ];
        # With the headers it includes, by their paths in the repo
        src = lib.fileset.toSource {
          root = ../../..;
          fileset = lib.fileset.unions [
            ../../../cmd/netns-netkit/netkit.bpf.c
            ../../../cmd/netns-netkit/mdns.bpf.h
            ../../../internal/uplink/uplink.bpf.h
          ];
        };
      }
      ''
        clang -O2 -g -Wall -Werror -target bpf -I${lib.getDev libbpf}/include -I${linuxHeaders}/include \
          -c $src/cmd/netns-netkit/netkit.bpf.c -o $out
      '';
in
buildGoModule {
  pname = "netns-netkit";
  version = "0.1.0";
  # The root module's go.mod, the binary's package and what it uses from internal/, so other changes don't rebuild it
  src = lib.fileset.toSource {
    root = ../../..;
    fileset = lib.fileset.unions [
      ../../../go.mod
      ../../../go.sum
      ../../../cmd/netns-netkit
      ../../../internal/journal
      ../../../internal/uplink
    ];
  };
  subPackages = [ "cmd/netns-netkit" ];
  vendorHash = "sha256-jL3hLzTjMkh7FrZsxdOIlGSCgXIb9JKauFBxLUKqZJk=";
  env.CGO_ENABLED = 0;
  ldflags = [ "-X main.object=${object}" ];
  meta = {
    description = "Connect a user-owned network namespace to the network through a netkit pair";
    mainProgram = "netns-netkit";
    platforms = lib.platforms.linux;
  };
}
