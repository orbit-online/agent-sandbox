{
  buildGoModule,
  kdePackages,
  lib,
  makeWrapper,
  pkg-config,
  ...
}:
let
  inherit (kdePackages) qtbase qtdeclarative;
  # The host's Qt plugins and QML modules may be another Qt's: only these, which match the one linked. Plasma's style
  # and platform theme among them, so the window looks like the rest of the desktop
  qmlPath = lib.makeSearchPath qtbase.qtQmlPrefix [
    qtdeclarative
    kdePackages.qqc2-desktop-style
    kdePackages.kirigami.unwrapped
    kdePackages.sonnet
  ];
  pluginPath = lib.makeSearchPath qtbase.qtPluginPrefix [
    qtbase
    kdePackages.qtwayland
    kdePackages.plasma-integration
    kdePackages.qqc2-desktop-style
  ];
in
buildGoModule {
  pname = "permissions-window";
  version = "0.1.0";
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./go.mod
      ./go.sum
      ./main.go
      ./window.go
      ./window_test.go
      ./Main.qml
      ./Permissions.qml
      ./tst_permissions.qml
    ];
  };
  vendorHash = "sha256-ZkZIt1u0K249lyb24g9vuPaVwz2q/NDBVzHbQaeScwU=";
  nativeBuildInputs = [
    makeWrapper
    pkg-config
  ];
  buildInputs = [
    qtbase
    qtdeclarative
  ];
  # miqt binds Qt through cgo
  env.CGO_ENABLED = 1;
  dontWrapQtApps = true;
  ldflags = [ "-X main.qmlPath=${placeholder "out"}/share/permissions-window/Main.qml" ];
  # Offscreen, in Plasma's style as on the host
  preCheck = ''
    export HOME=$TMPDIR QT_QPA_PLATFORM=offscreen QT_QUICK_CONTROLS_STYLE=org.kde.desktop QML_IMPORT_PATH=${qmlPath} \
      QT_PLUGIN_PATH=${pluginPath}
  '';
  # What each action in the window sends, against a mock broker
  postCheck = ''
    ${lib.getExe' qtdeclarative "qmltestrunner"} -input tst_permissions.qml
  '';
  postInstall = ''
    install -Dm644 -t $out/share/permissions-window Main.qml Permissions.qml
    wrapProgram $out/bin/permissions-window --set QML_IMPORT_PATH ${qmlPath} --set QT_PLUGIN_PATH ${pluginPath} \
      --unset QML2_IMPORT_PATH
  '';
  meta = {
    description = "The Permissions window of agent-sandbox's permissions broker";
    mainProgram = "permissions-window";
    platforms = lib.platforms.linux;
  };
}
