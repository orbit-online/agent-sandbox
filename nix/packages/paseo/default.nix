# Paseo's desktop app from its flake input, built on this flake's nixpkgs: Electron 44, which upstream builds against
# (this nixpkgs' default is 43), and the hash of the npm deps as this nixpkgs' fetchNpmDeps makes them, which differs
# from upstream's nix/npm-deps.hash. Bump the hash with the input.
# Upstream's build skips install scripts (npmRebuildFlags), so the root postinstall never applies the patches in
# patches/ and the renderer fails with React error #130 at its first render (getpaseo/paseo#7673). Applying them before
# the build fixes it, as the workaround on that issue does; drop it once upstream's build runs the postinstall.
# That build is `passthru.unpackaged`, upstream's Linux output.
#
# Upstream's Linux output runs the binary as `electron`, and Electron 44 takes a binary of that name for an unpackaged
# app (tried: a copy under another name has `app.isPackaged` true, a link doesn't, as /proc/self/exe resolves it), so
# Paseo runs in development mode: React DevTools fetched from Google, userData picked by `git rev-parse` in the cwd, the
# daemon with PASEO_NODE_ENV=development. This output lays the app out as electron-builder's packaged Linux build does,
# around a copy of the Electron binary named `Paseo`: the rest of the Electron files linked beside it, and in
# `resources/` what the packaged code paths of Paseo read there (see the paths below). `resources/app.asar` is a directory without a
# package.json, so Electron doesn't load it as the app and falls back to default_app.asar, which runs the app root given
# as the first argument: upstream's `electron-app`, or one of the sandbox's own. No `package-type` file and no
# $APPIMAGE, so electron-updater's AppImageUpdater stays inactive and never asks for an update.
#
# libexec/paseo-desktop/paseo-electron runs that binary with Electron's environment (as nixpkgs' electron wrapper sets
# it), taking Electron's arguments: an app root, then `--no-sandbox` and the like. bin/paseo-desktop runs it on
# upstream's app root.
{
  input,
  lib,
  stdenv,
  electron_44,
  makeWrapper,
  wrapGAppsHook3,
  gsettings-desktop-schemas,
  glib,
  gtk3,
  gtk4,
}:
let
  upstream = input.packages.${stdenv.hostPlatform.system};
  electron = electron_44.unwrapped;

  desktop =
    (upstream.desktop.override {
      electron = electron_44;
      paseo = upstream.paseo.override { npmDepsHash = "sha256-SZV3WTKLb+JhxWNo/jWyx+2sipzfL93YbbqQSihd3Wo="; };
    }).overrideAttrs
      (old: {
        preBuild = (old.preBuild or "") + ''
          npm run postinstall
        '';
        # The runner the packaged app starts the daemon and the CLI through, which the runtime trace leaves out as the
        # unpackaged app never loads it.
        postInstall = (old.postInstall or "") + ''
          install -Dm644 packages/desktop/dist/daemon/node-entrypoint-runner.js \
            $out/share/paseo-desktop/packages/desktop/dist/daemon/node-entrypoint-runner.js
        '';
      });
in
stdenv.mkDerivation {
  pname = "paseo-desktop";
  inherit (desktop) version;

  nativeBuildInputs = [
    makeWrapper
    wrapGAppsHook3
  ];
  # What nixpkgs' electron wrapper puts in its environment (GSETTINGS_SCHEMAS_PATH, GIO modules, pixbuf loaders).
  buildInputs = [
    gsettings-desktop-schemas
    glib
    gtk3
    gtk4
  ];
  dontWrapGApps = true;

  buildCommand = ''
    gappsWrapperArgsHook
    share=${desktop}/share/paseo-desktop
    dir=$out/libexec/paseo-desktop
    res=$dir/resources
    mkdir -p $res $out/bin $out/share

    for f in ${electron}/libexec/electron/*; do
      case "$(basename "$f")" in
        electron | resources) ;;
        *) ln -s "$f" "$dir/" ;;
      esac
    done
    cp ${electron}/libexec/electron/electron $dir/Paseo
    ln -s ${electron}/libexec/electron/resources/default_app.asar $res/

    # The modules of the daemon and the CLI (desktop/src/daemon/runtime-paths.ts, daemon/cli/entrypoints.ts). No
    # package.json, see above.
    mkdir $res/app.asar
    ln -s $share/node_modules $res/app.asar/node_modules
    # The runner the daemon and the CLI start through (daemon/runtime-paths.ts).
    mkdir $res/app.asar.unpacked
    ln -s $share/packages/desktop/dist $res/app.asar.unpacked/dist
    # The renderer (main.ts getAppDistDir; the daemon's web UI, server/src/server/config.ts), the window icon and the
    # editor icons (main.ts, features/editor-targets/runtime.ts).
    ln -s $share/packages/app/dist $res/app-dist
    ln -s $share/packages/desktop/assets/icon.png $res/icon.png
    ln -s $share/packages/desktop/assets/editor-targets $res/editor-target-icons
    # The CLI shim the daemon passes as PASEO_CLI (integrations/cli-install/path.ts). A copy: it follows links to itself
    # and finds the binary at ../Paseo from where it ends up.
    install -Dm755 ${input}/packages/desktop/bin/paseo $res/bin/paseo
    patchShebangs $res/bin/paseo

    makeWrapper $dir/Paseo $dir/paseo-electron \
      "''${gappsWrapperArgs[@]}" \
      --set CHROME_DEVEL_SANDBOX $dir/chrome-sandbox
    makeWrapper $dir/paseo-electron $out/bin/paseo-desktop \
      --add-flags "$share/electron-app --no-sandbox --class=paseo-desktop" \
      --set CHROME_DESKTOP paseo-desktop.desktop

    ln -s ${desktop}/share/{applications,icons} $out/share/
    ln -s $share $out/share/paseo-desktop
  '';

  passthru.unpackaged = desktop;

  meta = desktop.meta // {
    mainProgram = "paseo-desktop";
    platforms = lib.platforms.linux;
  };
}
