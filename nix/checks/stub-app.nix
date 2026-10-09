# Stands in for llm-agents' claude-desktop in the VM test: the same shape (a buildFHSEnv with passthru.unwrapped
# holding lib/claude-desktop/resources/app.asar), so the module's asar patch and FHS overrides apply as they do to the
# real app. Launched plainly, it logs its pid and netns to ~/stub-app.log and stays up as the first instance.
# `--exec CMD...` runs CMD instead, which through the wrapper's claude:// re-entry means inside the running sandbox.
{
  lib,
  stdenvNoCC,
  buildFHSEnv,
  writeShellScript,
  writeScriptBin,
  asar,
  coreutils,
}:
let
  app = writeShellScript "claude-desktop" ''
    args=()
    for a; do [[ $a == --password-store=basic ]] || args+=("$a"); done
    if [[ ''${args[0]:-} == --exec ]]; then
      exec "''${args[@]:1}"
    fi
    echo "$$ $(${lib.getExe' coreutils "readlink"} /proc/self/ns/net)" >>"$HOME/stub-app.log"
    exec ${lib.getExe' coreutils "sleep"} infinity
  '';
  unwrapped = stdenvNoCC.mkDerivation {
    pname = "claude-desktop-stub";
    version = "0";
    dontUnpack = true;
    nativeBuildInputs = [ asar ];
    installPhase = ''
      mkdir -p app $out/bin $out/share/applications $out/lib/claude-desktop/resources
      echo '{"main": "main.js"}' >app/package.json
      echo '"use strict";' >app/main.js
      # Unpacked like the real app's native modules, so app.asar.unpacked exists
      touch app/stub.node
      asar pack app $out/lib/claude-desktop/resources/app.asar --unpack '{*.node,github-mcp-server}'
      ln -s ${app} $out/bin/claude-desktop
    '';
  };
in
buildFHSEnv {
  pname = "claude-desktop";
  version = "0";
  passthru = { inherit unwrapped; };
  targetPkgs = _: [
    unwrapped
    (writeScriptBin "nettest" (builtins.readFile ../../scripts/nettest.sh))
  ];
  runScript = "claude-desktop";
  extraInstallCommands = ''
    ln -s ${unwrapped}/share $out/share
  '';
}
