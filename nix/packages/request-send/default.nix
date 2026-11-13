# The host commands of the request-send and request-send-write capabilities (nix/home/claude-desktop/request-send.nix):
# one HTTP request per call, sent with the user's users CA certificate and its TPM key
{
  buildGoModule,
  lib,
  ...
}:
buildGoModule {
  pname = "request-send";
  version = "0.1.0";
  # The root module's go.mod and the binary's package, so other changes don't rebuild it
  src = lib.fileset.toSource {
    root = ../../..;
    fileset = lib.fileset.unions [
      ../../../go.mod
      ../../../go.sum
      ../../../cmd/request-send
      ../../../internal/journal
    ];
  };
  subPackages = [ "cmd/request-send" ];
  vendorHash = "sha256-tqIS/tLBIRH2lP6eDk0roGiAoaeKrM9AdcBgehBc9tg=";
  env.CGO_ENABLED = 0;
  meta = {
    description = "Send HTTP requests for a sandboxed Claude with your users CA certificate and its TPM key";
    mainProgram = "request-send";
    platforms = lib.platforms.linux;
  };
}
