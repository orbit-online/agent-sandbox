# The app in buildFHSEnv's bwrap: its patched asar, its pid (app-pid.sh), the files, /etc and the PATH packages at
# /run/current-system/sw
{
  lib,
  pkgs,
  config,
  osConfig,
  sl,
  launcherName,
  ...
}:
let
  inherit (lib) escapeShellArg;
  ids = sl.idsOf launcherName;
  # Replaces the host's /etc/hosts, whose entries point at the host's loopback or networks the netns doesn't reach.
  # The hostname line is the one NixOS writes: the UTS namespace starts with the host's hostname
  hosts =
    let
      inherit (osConfig.networking) hostName domain;
      # FQDN first, as in nixos/modules/config/networking.nix
      hostNames =
        lib.optional (hostName != "" && domain != null) "${hostName}.${domain}"
        ++ lib.optional (hostName != "") hostName;
    in
    pkgs.writeText "claude-desktop-hosts" (
      ''
        127.0.0.1 localhost
        ::1 localhost
      ''
      + lib.optionalString (hostNames != [ ]) "127.0.0.2 ${toString hostNames}\n"
    );
  # /run/current-system links into the system closure: the PATH tools, bash (SHELL) and glibc's fallback
  # locale archive come from this instead
  currentSystemSw = pkgs.buildEnv {
    name = "claude-desktop-sw";
    paths = sl.sandboxPackagesOf config ++ config.build.sw;
  };
  # The entries claude-desktop's FHS env takes from /etc, minus shadow, sudoers, nix (NIX_CONF_DIR) and the
  # shell rc files (the sandbox's shell is bash with the FHS env's /etc/profile, not the host's login shell)
  etcEntries =
    sl.hostEtc
    ++ [
      "nsswitch.conf"
      "localtime"
      "zoneinfo"
      "os-release"
      "fonts"
      "ssl/certs"
      "pki"
    ]
    ++ lib.optional config.audio "alsa";
  # Those NixOS generates, linked as in /etc/static (a source in /etc links within the tree, localtime to zoneinfo).
  # Bound from here, as the host's /etc binds the generation's store paths, which a host GC empties under a running
  # sandbox
  under = d: target: target == d || lib.hasPrefix "${d}/" target;
  etcFiles = lib.filterAttrs (
    _: e: e.enable && lib.any (d: under d e.target) etcEntries
  ) osConfig.environment.etc;
  etc = pkgs.runCommand "claude-desktop-etc" { } (
    lib.concatLines (
      lib.mapAttrsToList (
        _: e:
        let
          src = toString e.source;
          up = lib.concatStrings (lib.replicate (lib.length (lib.splitString "/" e.target) - 1) "../");
        in
        ''
          mkdir -p "$(dirname "$out"/${escapeShellArg e.target})"
          ln -s ${
            escapeShellArg (if lib.hasPrefix "/etc/" src then up + lib.removePrefix "/etc/" src else src)
          } "$out"/${escapeShellArg e.target}
        ''
      ) etcFiles
    )
  );
  etcBinds = map (d: [
    "${etc}/${d}"
    "/etc/${d}"
  ]) (lib.filter (d: lib.any (e: under d e.target) (lib.attrValues etcFiles)) etcEntries);

  asar = "${config.package.unwrapped}/lib/claude-desktop/resources/app.asar";
  patchedAsar = pkgs.runCommand "claude-desktop-app.asar" {
    nativeBuildInputs = [
      pkgs.asar
      pkgs.jq
    ];
    ASAR = asar;
    DESKTOP_NAME = ids.desktopFile;
    READY = sl.readyLine;
    CHANNELS = builtins.toJSON config.mcpChannels;
    CHANNELS_JS = ./channels.js;
  } "source ${./patch-asar.sh}";
  # The FHS env's runScript, see app-pid.sh
  appPidScript = sl.script "app-pid.sh" {
    name = "claude-desktop-app-pid";
    vars = {
      APP_PID = toString ids.appPid;
      SETPRIV = lib.getExe' pkgs.util-linux "setpriv";
      SETSID = lib.getExe' pkgs.util-linux "setsid";
    };
  };
in
{
  config = {
    build.etcEntries = etcEntries;
    env.PATH = "${sl.xdgOpen}/bin:${sl.searchPathOf config}";
    build.sw = [
      pkgs.bashInteractive
      osConfig.i18n.glibcLocales
      # A command in a cgroup of its own with a memory limit, see environment.md
      (sl.script "cgrun.sh" {
        name = "cgrun";
        runtimeInputs = [
          pkgs.coreutils
          pkgs.gnugrep
        ];
      })
    ];
    build.storeRoots = [
      config.build.app
      sl.xdgOpen
      currentSystemSw
      etc
    ];
    build.nixpak = [
      {
        bubblewrap.bind.ro = lib.mkAfter (
          etcBinds
          ++ [
            [
              "${currentSystemSw}"
              "/run/current-system/sw"
            ]
          ]
        );
      }
    ];
    build.fhsBwrapArgs = [
      # For app-pid.sh, which drops it
      "--cap-add CAP_CHECKPOINT_RESTORE"
      "--ro-bind ${patchedAsar} ${asar}"
      # Written by bwrap-subid.sh
      "--ro-bind-data 22 /etc/subuid"
      "--ro-bind-data 23 /etc/subgid"
    ];

    # nixpak binds /nix/store after all bind.ro entries, so the overlay and environment.md go into the FHS env's own
    # bwrap, as do the files: the FHS env links only some entries of the outer /etc. Being in the package, they're in
    # storeRoots. resolv.conf and hosts are links in its rootfs, which win over the host ones that nixpak's pasta module
    # binds (the FHS env links the rest of /etc to /.host-etc, the outer /etc). A bind onto those would fail once the
    # host replaced the file under it. shadow's newuidmap and newgidmap in the rootfs are the broker's shims, for tools
    # that run them by path: setuid can't work in bwrap, which sets no_new_privs
    build.app = config.package.override (prev: {
      buildFHSEnv =
        args:
        (prev.buildFHSEnv.override { bubblewrap = sl.bwrapFhs; }) (
          args
          // {
            unsharePid = true;
            runScript = "${lib.getExe appPidScript} ${args.runScript or "bash"}";
            extraBwrapArgs =
              args.extraBwrapArgs or [ ]
              ++ config.build.fhsBwrapArgs
              # Shallowest first, so a file in a bound directory overrides it
              ++ map (f: "--ro-bind ${f.source} ${lib.escapeShellArg f.path}") (sl.byDepth config.files);
            profile = args.profile or "" + builtins.readFile ./fhs-profile.sh;
            extraBuildCommands = args.extraBuildCommands or "" + ''
              ln -s ${sl.sandboxResolvConf} $out/etc/resolv.conf
              ln -s ${hosts} $out/etc/hosts
              for f in {bin,sbin}/new{u,g}idmap; do
                ln -sf ${sl.packages.subid-broker}/bin/''${f#*/} $out/usr/$f
              done
            '';
          }
        );
    });
  };
}
