# What every launcher module shares, passed to them as `sl`: the module's own scripts, the flake's packages, and the
# names that follow from a launcher's name (null for the default launcher)
{
  inputs,
  pkgs,
  lib,
  hm,
  osConfig,
}:
let
  cfg = hm.agent-sandbox.claude-desktop;
  packages = inputs.self.packages.${pkgs.stdenv.hostPlatform.system};
in
rec {
  inherit packages;
  # A script from this directory as a writeShellApplication. `vars` become readonly variables ahead of it,
  # `prelude` is raw bash between those and the script
  script =
    file:
    {
      name ? lib.removeSuffix ".sh" file,
      vars ? { },
      prelude ? "",
      runtimeInputs ? [ ],
    }:
    pkgs.writeShellApplication {
      inherit name runtimeInputs;
      text =
        lib.concatLines (lib.mapAttrsToList (n: v: "readonly ${n}=${lib.escapeShellArg v}") vars)
        + prelude
        + builtins.readFile (./. + "/${file}");
    };

  xdgOpen = script "xdg-open.sh" { runtimeInputs = [ pkgs.glib ]; };
  # The app keeps Claude Code under a versioned path, off PATH
  claudeCode = script "claude.sh" { runtimeInputs = [ pkgs.coreutils ]; };
  # The same nix as the host, so the sandbox's store database is never migrated to a schema one side can't read
  # .out: the man output is a symlink, see storeRoots
  sandboxPackagesOf =
    lcfg:
    lcfg.path
    ++ [
      claudeCode
      osConfig.nix.package.out
    ];
  # PATH for the app (so the Code tab's shells) and the claude-code MCP server
  searchPathOf =
    lcfg:
    lib.concatStringsSep ":" (
      lcfg.extraPath
      ++ [
        (lib.makeBinPath (sandboxPackagesOf lcfg))
        osConfig.security.wrapperDir
        "/run/current-system/sw/bin"
      ]
    );

  # What the app prints on stdout once its first window is ready (patch-asar.sh), which ends the launcher's splash
  readyLine = "agent-sandbox: ready";

  # The launcher names, the default one as null
  names = [ null ] ++ lib.attrNames cfg.launchers;
  # A named launcher's suffix to file names, empty for the default one
  suffixOf = name: lib.optionalString (name != null) "-${name}";
  # The longest launcher name, see its assertion. cmd/permissions-broker/socketpath_test.go binds the broker's sockets at
  # it, and the eval tests check the two agree
  launcherNameMax = 46;
  # Holds the sandbox's home directory, its Nix store and Claude Code's temp dir (home/, nix/, tmp-scratchpad/)
  stateDirOf = name: "${hm.xdg.dataHome}/claude-desktop${suffixOf name}";
  # The launcher's cgroup slice, holding the app's unit, the broker's and its calls'. A - in
  # a slice's name nests it in the slice before it (claude-desktop-work.slice in claude-desktop.slice), so each is
  # escaped: one slice per launcher, each a sibling of app.slice. systemd makes it when a unit names it
  sliceOf = name: "${lib.replaceStrings [ "-" ] [ "\\x2d" ] "claude-desktop${suffixOf name}"}.slice";
  # The app's pid in the FHS env's pid ns (see app-pid.sh), one per launcher: their tray items share the session bus
  appPidOf = name: 100 + lib.lists.findFirstIndex (n: n == name) null names;
  # What a launcher is called by: its file name suffix, the sandbox's app ID (the proxy's /.flatpak-info names the
  # app by it to the portals, and the wrapper finds its running sandbox by it; it names the launcher's .desktop file
  # and its windows' app ID too, the Permissions window's included: gnome-shell drops a portal notification unless
  # <app ID>.desktop exists. The default launcher's is upstream's, so its .desktop file keeps upstream's name; a
  # launcher's name is a valid last element), and its state dir with the sandbox's home and scratchpad in it
  idsOf =
    name:
    let
      stateDir = stateDirOf name;
      appId = "com.anthropic.Claude${lib.optionalString (name != null) ".${name}"}";
    in
    {
      inherit name appId stateDir;
      suffix = suffixOf name;
      desktopFile = "${appId}.desktop";
      appPid = appPidOf name;
      slice = sliceOf name;
      home = "${stateDir}/home";
      scratchpad = "${stateDir}/tmp-scratchpad";
      # Where the option's definitions say so in messages
      opt = "agent-sandbox.claude-desktop: ${lib.optionalString (name != null) "launchers.${name}."}";
    };

  # bwrap with a range of ids, see bwrap-subid.sh: nixpak's (on the host) and the FHS env's (inside)
  bwrapSubid =
    vars:
    script "bwrap-subid.sh" {
      name = "bwrap";
      runtimeInputs = [
        pkgs.coreutils
        pkgs.gnugrep
      ];
      vars = {
        BWRAP = lib.getExe' pkgs.bubblewrap "bwrap";
      }
      // vars;
    };
  bwrapHost = bwrapSubid {
    SUBID_MAP = "subid";
    NEWUIDMAP = "${osConfig.security.wrapperDir}/newuidmap";
    NEWGIDMAP = "${osConfig.security.wrapperDir}/newgidmap";
    SUBID_BROKER = lib.getExe packages.subid-broker;
  };
  bwrapFhs = bwrapSubid {
    SUBID_MAP = "parent";
    NEWUIDMAP = lib.getExe' packages.subid-broker "newuidmap";
    NEWGIDMAP = lib.getExe' packages.subid-broker "newgidmap";
    PERMISSIONS_BROKER = lib.getExe packages.permissions-broker;
  };

  # Written by the host's activation, bound from its /etc
  hostEtc = [
    "passwd"
    "group"
    "machine-id"
  ];
  # A launcher's resolv.conf (see network.nix) as the sandbox sees it, where its home directory is bound
  sandboxResolvConf = "${hm.home.homeDirectory}/.config/resolv.conf";
  # The sandbox's own single-user Nix store, stateDir/nix bound rw at /nix. The host store isn't visible: nixpak binds
  # only storeRoots' closure (ro, over the store's copies of the same paths) and there is no daemon socket.
  # Paths have to be valid in the store before the binds land on them, or bwrap mkdirs unregistered
  # mountpoints in it, so the wrapper copies the closure in and roots it before every launch
  nixConf = pkgs.writeTextDir "nix.conf" ''
    experimental-features = nix-command flakes
    # Nix's default is one build at a time
    max-jobs = auto
    substituters = https://cache.nixos.org/
    trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
  '';
  # programs.mcp.servers as Home Manager's own clients take them, env files through a wrapper. Disabled ones left out
  hmMcpServers = lib.optionalAttrs hm.programs.mcp.enable (
    lib.mapAttrs (_: s: removeAttrs s [ "enabled" ]) (
      lib.filterAttrs (_: s: s.enabled or true) (
        lib.mapAttrs (
          name: server:
          lib.hm.mcp.transformMcpServer {
            inherit server;
            extraTransforms = [ (lib.hm.mcp.wrapEnvFilesCommand { inherit pkgs name; }) ];
          }
        ) hm.programs.mcp.servers
      )
    )
  );
  # environment.md split by its markers (see environment-split.sh): all of it, the part every session needs, and the
  # rest as a memo store
  environment = pkgs.runCommand "claude-desktop-environment" {
    nativeBuildInputs = [ pkgs.gawk ];
    SRC = ./environment.md;
    NAME = "agent-sandbox/claude-desktop";
    DESCRIPTION = "The Claude Desktop sandbox you run in: its home, its user namespaces and its Nix store.";
    # As in environmentDoc's frontmatter
    ENVIRONMENT = "bwrap";
  } "source ${./environment-split.sh}";
  # Whether path a is path b or holds it
  holds = a: b: a == b || lib.hasPrefix "${lib.removeSuffix "/" a}/" b;
  # How many characters a UTF-8 string holds, as the broker counts runes: its bytes but the continuation bytes
  # (0x80-0xBF), each the second byte of U+0080-U+00BF's encoding, since a Nix string can't spell a lone byte.
  # lib.stringLength counts bytes
  utf8Length =
    let
      continuation = map (i: builtins.substring 1 1 (builtins.fromJSON ''"\u00${lib.toHexString i}"'')) (
        lib.range 128 191
      );
    in
    s: lib.length (lib.filter (b: !(lib.elem b continuation)) (lib.stringToCharacters s));
  # Binds or files keyed by path in the sandbox, enabled ones, with `path` added, shallowest first
  byDepth =
    attrs:
    lib.sortOn (b: lib.stringLength b.path) (
      lib.mapAttrsToList (path: b: b // { inherit path; }) (lib.filterAttrs (_: b: b.enable) attrs)
    );
}
