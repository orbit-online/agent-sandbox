{
  buildGoModule,
  kdePackages,
  lib,
  makeWrapper,
  pkg-config,
  writeShellApplication,
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
buildGoModule (finalAttrs: {
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
      ./Section.qml
      ./TabPage.qml
      ./Card.qml
      ./FieldRow.qml
      ./Quote.qml
      ./CallList.qml
      ./RequestRow.qml
      ./GrantRow.qml
      ./Badges.qml
      ./Badge.qml
      ./ReadOnlyText.qml
      ./CommandScope.qml
      ./tst_permissions.qml
      ./Preview.qml
      ./preview-state.json
      ./splash/main.go
      ./splash/state.go
      ./splash/splash_test.go
      ./splash/Splash.qml
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
  # buildGoModule's checkPhase drops -trimpath from GOFLAGS, which changes every action ID, so go test would compile
  # miqt's cgo again instead of taking it from the build phase's cache. The tests don't need source paths
  checkFlags = [ "-trimpath" ];
  # Offscreen, in Plasma's style as on the host
  preCheck = ''
    export HOME=$TMPDIR QT_QPA_PLATFORM=offscreen QT_QUICK_CONTROLS_STYLE=org.kde.desktop QML_IMPORT_PATH=${qmlPath} \
      QT_PLUGIN_PATH=${pluginPath}
  '';
  # What each action in the window sends, against a mock broker
  postCheck = ''
    ${lib.getExe' qtdeclarative "qmltestrunner"} -input tst_permissions.qml
  '';
  # Qt Quick draws text from distance fields by default, which smears small text, bold most, at fractional scales:
  # QML_DISABLE_DISTANCEFIELD draws the controls' text with the font's own glyphs too, as the window's own text asks
  # with renderType
  postInstall = ''
    install -Dm644 -t $out/share/permissions-window Main.qml Permissions.qml Section.qml TabPage.qml Card.qml \
      FieldRow.qml Quote.qml CallList.qml RequestRow.qml GrantRow.qml \
      Badges.qml Badge.qml ReadOnlyText.qml CommandScope.qml Preview.qml preview-state.json
    install -Dm644 -t $out/share/sandbox-splash splash/Splash.qml
    # The splash a sandbox's launcher shows while it starts (sandbox-splash --help)
    mv $out/bin/splash $out/bin/sandbox-splash
    for b in permissions-window sandbox-splash; do
      wrapProgram $out/bin/$b --set QML_IMPORT_PATH ${qmlPath} --set QT_PLUGIN_PATH ${pluginPath} \
        --unset QML2_IMPORT_PATH --set QML_DISABLE_DISTANCEFIELD 1
    done
  '';
  # The window against a mock broker, for working on its looks (preview.sh)
  passthru.preview = writeShellApplication {
    name = "permissions-window-preview";
    runtimeEnv = {
      QML_BIN = lib.getExe' qtdeclarative "qml";
      QML_DIR = "${finalAttrs.finalPackage}/share/permissions-window";
      QML_IMPORT_PATH = qmlPath;
      QT_PLUGIN_PATH = pluginPath;
      QML_DISABLE_DISTANCEFIELD = "1";
    };
    text = builtins.readFile ./preview.sh;
  };
  meta = {
    description = "The Permissions window of agent-sandbox's permissions broker";
    mainProgram = "permissions-window";
    platforms = lib.platforms.linux;
  };
})
