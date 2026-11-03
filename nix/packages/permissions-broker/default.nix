{
  buildGoModule,
  lib,
  dbus,
  makeBinaryWrapper,
  util-linux,
  ...
}:
buildGoModule {
  pname = "permissions-broker";
  version = "0.1.0";
  # The root module's go.mod, the binary's package and what it uses from internal/, so other changes don't rebuild it
  src = lib.fileset.toSource {
    root = ../../..;
    fileset = lib.fileset.unions [
      ../../../go.mod
      ../../../go.sum
      ../../../cmd/permissions-broker
      ../../../internal/proc
      ../../../internal/dbuspolicy
    ];
  };
  # The policy package for its tests: it has no binary
  subPackages = [
    "cmd/permissions-broker"
    "internal/dbuspolicy"
  ];
  vendorHash = "sha256-4Of8zQcd0WJzGnwkK/GWhawzSDpKSHcjyx8mcLJaadE=";
  env.CGO_ENABLED = 0;
  nativeBuildInputs = [ makeBinaryWrapper ];
  # nsenter from the util-linux it's tested against (helpers.go relies on its --keep-caps behaviour); systemd-run and
  # systemctl from the host system, to match the running user manager
  postInstall = ''
    wrapProgram $out/bin/permissions-broker \
      --prefix PATH : ${lib.makeBinPath [ util-linux ]} \
      --suffix PATH : /run/current-system/sw/bin
  '';
  # TestShare and the attach tests run nsenter and unshare, the notification tests a bus of their own
  nativeCheckInputs = [
    dbus
    util-linux
  ];
  meta = {
    description = "Grant a sandbox outside access while it runs";
    mainProgram = "permissions-broker";
    platforms = lib.platforms.linux;
  };
}
