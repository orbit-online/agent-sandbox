{
  buildGoModule,
  lib,
  ...
}:
buildGoModule {
  pname = "sandbox-hooks";
  version = "0.1.0";
  # The root module's go.mod, the binary's package and what it uses from internal/, so other changes don't rebuild it
  src = lib.fileset.toSource {
    root = ../../..;
    fileset = lib.fileset.unions [
      ../../../go.mod
      ../../../go.sum
      ../../../cmd/sandbox-hooks
      ../../../internal/caller
      ../../../internal/journal
    ];
  };
  subPackages = [ "cmd/sandbox-hooks" ];
  vendorHash = "sha256-95VnlPu2HIg1F200CrZq28bwmJmmuFGNxGTeKdhr4wc=";
  env.CGO_ENABLED = 0;
  meta = {
    description = "Run the hooks root configured for a phase of a sandbox";
    mainProgram = "sandbox-hooks";
    platforms = lib.platforms.linux;
  };
}
