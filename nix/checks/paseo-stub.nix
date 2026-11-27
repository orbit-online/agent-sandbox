# Stands in for packages.paseo-desktop in the VM test (vm/paseo.nix): what the module uses of it, in its places.
# libexec/paseo-desktop/paseo-electron takes Electron's arguments, an app root, then --no-sandbox and the rest, and runs
# that app root (the module's index.js) in node against a fake Electron (paseo-stub-electron.js), whose main.js is
# paseo-stub-main.js at Paseo's share/paseo-desktop/packages/desktop/dist/main.js. No GPU, no Electron.
# `<app root> --no-sandbox --exec CMD...` runs CMD instead, which through the launcher's re-entry means inside the
# running sandbox
{
  lib,
  runCommand,
  writeShellScript,
  nodejs-slim,
}:
let
  electron = writeShellScript "paseo-electron" ''
    if [[ ''${2:-} == --no-sandbox && ''${3:-} == --exec ]]; then
      exec "''${@:4}"
    fi
    exec ${lib.getExe nodejs-slim} ${./paseo-stub-electron.js} "$0" "$@"
  '';
  # 1x1, transparent: the splash's agent logo
  png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
in
runCommand "paseo-desktop-stub"
  {
    version = "0.18.0-stub";
    meta.mainProgram = "paseo-desktop";
  }
  ''
    mkdir -p $out/libexec/paseo-desktop $out/share/paseo-desktop/packages/desktop/dist \
      $out/share/icons/hicolor/512x512/apps
    ln -s ${electron} $out/libexec/paseo-desktop/paseo-electron
    cp ${./paseo-stub-main.js} $out/share/paseo-desktop/packages/desktop/dist/main.js
    echo ${png} | base64 -d >$out/share/icons/hicolor/512x512/apps/paseo-desktop.png
  ''
