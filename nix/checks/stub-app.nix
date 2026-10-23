# Stands in for llm-agents' claude-desktop in the VM test: the same shape (a buildFHSEnv with passthru.unwrapped
# holding lib/claude-desktop/resources/app.asar), so the module's asar patch and FHS overrides apply as they do to the
# real app. Launched plainly, it logs its pid, netns, mount ns, pid ns and effective capabilities to ~/stub-app.log,
# then the session bus's reply to its RequestName for the tray item's name (StatusNotifierItem-<pid>-1, 1 when it got
# it, denied when the proxy refused), and stays up as the first instance.
# `--exec CMD...` runs CMD instead, which through the wrapper's claude:// re-entry means inside the running sandbox.
{
  lib,
  stdenvNoCC,
  buildFHSEnv,
  writeShellScript,
  writeScriptBin,
  asar,
  coreutils,
  glib,
}:
let
  app = writeShellScript "claude-desktop" ''
    args=()
    for a; do [[ $a == --password-store=basic ]] || args+=("$a"); done
    if [[ ''${args[0]:-} == --exec ]]; then
      exec "''${args[@]:1}"
    fi
    ns() { ${lib.getExe' coreutils "readlink"} /proc/self/ns/$1; }
    while read -r k v; do [[ $k != CapEff: ]] || caps=$v; done </proc/self/status
    # DO_NOT_QUEUE | REPLACE_EXISTING, as Chromium asks
    bus=denied
    if reply=$(${lib.getExe' glib "gdbus"} call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus \
      --method org.freedesktop.DBus.RequestName "org.freedesktop.StatusNotifierItem-$$-1" 6 2>/dev/null) &&
      [[ $reply =~ ^\(uint32\ ([0-9]+),\)$ ]]; then
      bus=''${BASH_REMATCH[1]}
    fi
    echo "$$ $(ns net) $(ns mnt) $(ns pid) $caps $bus" >>"$HOME/stub-app.log"
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
      # The .desktop file the module adds its shell action to, and rewrites for a named launcher
      printf '%s\n' '[Desktop Entry]' Name=Claude Actions=NewChat 'Exec=claude-desktop %U' 'MimeType=x-scheme-handler/claude;' \
        "" '[Desktop Action NewChat]' 'Name=New chat' 'Exec=claude-desktop claude://claude.ai/new' \
        >$out/share/applications/com.anthropic.Claude.desktop
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
