{
  buildGoModule,
  lib,
  libnotify,
  systemd,
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
    ];
  };
  subPackages = [ "cmd/permissions-broker" ];
  vendorHash = "sha256-tJjl2D5Mv+/ukjWB0EmbYxeQ/v3mU8VFMRQJ742kKk8=";
  env.CGO_ENABLED = 0;
  ldflags = [
    "-X main.nsenter=${lib.getExe' util-linux "nsenter"}"
    "-X main.unshareBin=${lib.getExe' util-linux "unshare"}"
    "-X main.notifySend=${lib.getExe' libnotify "notify-send"}"
    "-X main.systemdRun=${lib.getExe' systemd "systemd-run"}"
    "-X main.systemctl=${lib.getExe' systemd "systemctl"}"
  ];
  # TestShare and the type C tests run nsenter and unshare
  nativeCheckInputs = [ util-linux ];
  meta = {
    description = "Grant a sandbox outside access while it runs";
    mainProgram = "permissions-broker";
    platforms = lib.platforms.linux;
  };
}
