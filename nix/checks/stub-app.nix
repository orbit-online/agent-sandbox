# Stands in for llm-agents' claude-desktop in the VM test: the same shape (a buildFHSEnv with passthru.unwrapped
# holding lib/claude-desktop/resources/app.asar), so the module's asar patch and FHS overrides apply as they do to the
# real app. Launched plainly, it logs its pid, netns, mount ns, pid ns and effective capabilities to ~/stub-app.log,
# then the session bus's reply to its RequestName for the tray item's name (StatusNotifierItem-<pid>-1, 1 when it got
# it, denied when the proxy refused), prints the ready line the launcher waits for, and stays up as the first instance.
# `--exec CMD...` runs CMD instead, which through the wrapper's claude:// re-entry means inside the running sandbox.
# `program` and `desktopFiles` give it another shape, as the checks' stand-in app does: its program named otherwise,
# other .desktop files, which the module never reads
{
  lib,
  stdenvNoCC,
  buildFHSEnv,
  writeShellScript,
  writeScriptBin,
  asar,
  coreutils,
  glib,
  libnotify,
  program ? "claude-desktop",
  desktopFiles ? null,
}:
let
  app = writeShellScript program ''
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
    # What the real app's patched asar prints once its first window is ready
    echo 'agent-sandbox: ready'
    exec ${lib.getExe' coreutils "sleep"} infinity
  '';
  unwrapped = stdenvNoCC.mkDerivation {
    pname = "${program}-stub";
    version = "0";
    dontUnpack = true;
    nativeBuildInputs = [ asar ];
    installPhase = ''
      mkdir -p app $out/bin $out/share/applications $out/lib/claude-desktop/resources
      echo '{"main": "main.js"}' >app/package.json
      echo '"use strict";' >app/main.js
      # The real app's tray icon choice, minified, for the module's patch
      echo 'function c(e){return e||rk()==="gnome"||a.nativeTheme.shouldUseDarkColors?"TrayIconLinux-Dark.png":"TrayIconLinux.png"}' >>app/main.js
      # The .desktop file the module installs under each launcher's app ID, with its shell action, and rewrites for a named
      # launcher
      ${
        if desktopFiles == null then
          ''
            printf '%s\n' '[Desktop Entry]' Name=Claude Actions=NewChat 'Exec=claude-desktop %U' 'MimeType=x-scheme-handler/claude;' StartupWMClass=com.anthropic.Claude \
              "" '[Desktop Action NewChat]' 'Name=New chat' 'Exec=claude-desktop claude://claude.ai/new' \
              >$out/share/applications/com.anthropic.Claude.desktop
          ''
        else
          lib.concatStrings (
            lib.mapAttrsToList (n: text: "cp ${builtins.toFile n text} $out/share/applications/${n}\n") desktopFiles
          )
      }
      # The icon the module's .desktop file names and the splash shows
      mkdir -p $out/share/icons/hicolor/256x256/apps
      cp ${../home/sandbox/assets/orbit-landskab-farve.svg} $out/share/icons/hicolor/256x256/apps/${program}.svg
      # Unpacked like the real app's native modules, so app.asar.unpacked exists
      touch app/stub.node
      asar pack app $out/lib/claude-desktop/resources/app.asar --unpack '{*.node,github-mcp-server}'
      ln -s ${app} $out/bin/${program}
    '';
  };
in
buildFHSEnv {
  pname = program;
  version = "0";
  passthru = { inherit unwrapped; };
  targetPkgs = _: [
    unwrapped
    # notify-send, which uses libnotify as Electron does
    libnotify
    (writeScriptBin "nettest" (builtins.readFile ../../scripts/nettest.sh))
  ];
  runScript = program;
  extraInstallCommands = ''
    ln -s ${unwrapped}/share $out/share
  '';
}
