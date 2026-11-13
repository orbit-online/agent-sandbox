# einat-ebpf as its flake builds it, with NAT66: its package.nix sets buildFeatures, which naersk ignores, so without
# cargoBuildOptions the binary lacks the ipv6 feature
{
  callPackage,
  lib,
  input,
}:
callPackage "${input}/nix/package.nix" {
  naersk =
    let
      naersk = callPackage input.inputs.naersk { };
    in
    naersk
    // {
      buildPackage =
        args:
        naersk.buildPackage (
          args
          // {
            cargoBuildOptions = o: o ++ [ "--features=${lib.concatStringsSep "," args.buildFeatures}" ];
          }
        );
    };
}
