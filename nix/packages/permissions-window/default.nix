{
  kdePackages,
  lib,
  makeWrapper,
  python3,
  stdenvNoCC,
  ...
}:
let
  python = python3.withPackages (p: [ p.pyside6 ]);
  inherit (kdePackages) qtbase;
  # The host's Qt plugins and QML modules may be another Qt's: only these, which match PySide6's. Plasma's style and
  # platform theme among them, so the window looks like the rest of the desktop
  qmlPath = lib.makeSearchPath qtbase.qtQmlPrefix [
    kdePackages.qtdeclarative
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
  env = [
    "--set QML_IMPORT_PATH ${qmlPath}"
    "--set QT_PLUGIN_PATH ${pluginPath}"
    "--unset QML2_IMPORT_PATH"
  ];
in
stdenvNoCC.mkDerivation {
  pname = "permissions-window";
  version = "0.1.0";
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./permissions_window.py
      ./Main.qml
      ./test_window.py
    ];
  };
  nativeBuildInputs = [ makeWrapper ];
  dontBuild = true;
  installPhase = ''
    install -Dm644 -t $out/share/permissions-window permissions_window.py Main.qml
    makeWrapper ${lib.getExe python} $out/bin/permissions-window ${lib.concatStringsSep " " env} \
      --add-flags "-I $out/share/permissions-window/permissions_window.py"
  '';
  # Offscreen, in Plasma's style as on the host
  doInstallCheck = true;
  installCheckPhase = ''
    makeWrapper ${lib.getExe python} test-python ${lib.concatStringsSep " " env} \
      --set PYTHONPATH $out/share/permissions-window --set QT_QUICK_CONTROLS_STYLE org.kde.desktop
    HOME=$TMPDIR ./test-python -m unittest -v test_window
  '';
  meta = {
    description = "The Permissions window of agent-sandbox's permissions broker";
    mainProgram = "permissions-window";
    platforms = lib.platforms.linux;
  };
}
