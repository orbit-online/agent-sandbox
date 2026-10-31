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
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./go.mod
      ./go.sum
      ./broker.go
      ./main.go
      ./mcp.go
      ./plugins.go
      ./sandbox.go
      ./main_test.go
    ];
  };
  vendorHash = "sha256-JFVM75kWu8MwLwRPqMG2pnqiQhiaOMCwYZMiMuoJPfc=";
  env.CGO_ENABLED = 0;
  ldflags = [
    "-X main.nsenter=${lib.getExe' util-linux "nsenter"}"
    "-X main.notifySend=${lib.getExe' libnotify "notify-send"}"
    "-X main.systemdRun=${lib.getExe' systemd "systemd-run"}"
    "-X main.systemctl=${lib.getExe' systemd "systemctl"}"
  ];
  # TestShare runs nsenter
  nativeCheckInputs = [ util-linux ];
  meta = {
    description = "Grant a sandbox outside access while it runs";
    mainProgram = "permissions-broker";
    platforms = lib.platforms.linux;
  };
}
