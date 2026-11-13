{
  buildGoModule,
  dbus,
  lib,
  util-linux,
  ...
}:
buildGoModule {
  pname = "launcher";
  version = "0.1.0";
  # The root module's go.mod, the binary's package and what it uses from internal/, so other changes don't rebuild it
  src = lib.fileset.toSource {
    root = ../../..;
    fileset = lib.fileset.unions [
      ../../../go.mod
      ../../../go.sum
      ../../../cmd/launcher
      ../../../internal
    ];
  };
  # internal/'s own tests run here, the launcher being their widest user
  subPackages = [
    "cmd/launcher"
    "internal/..."
  ];
  vendorHash = "sha256-8MjdStRba6RVMaQ2mHZGO623li6fgGKLg2BhyMsZzaA=";
  env.CGO_ENABLED = 0;
  # internal/sandbox's tests make pid namespaces with unshare; the DNS test runs a system bus of its own
  nativeCheckInputs = [
    dbus
    util-linux
  ];
  meta = {
    description = "Start a sandbox's launcher, or join the running sandbox";
    mainProgram = "launcher";
    platforms = lib.platforms.linux;
  };
}
