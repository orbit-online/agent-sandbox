# What every launcher module of an app shares, passed to them as `sl`: the app's descriptor (default.nix), the module's
# own scripts, the flake's packages, and the names that follow from a launcher's name (null for the default launcher)
{
  inputs,
  pkgs,
  lib,
  hm,
  osConfig,
  app,
}:
let
  cfg = hm.agent-sandbox.${app.name};
  packages = inputs.self.packages.${pkgs.stdenv.hostPlatform.system};
in
rec {
  inherit packages app;
  # A script from this directory, or `dir`, as a writeShellApplication. `vars` become readonly variables ahead of it,
  # `prelude` is raw bash between those and the script
  script =
    file:
    {
      name ? lib.removeSuffix ".sh" file,
      vars ? { },
      prelude ? "",
      runtimeInputs ? [ ],
      dir ? ./.,
    }:
    pkgs.writeShellApplication {
      inherit name runtimeInputs;
      text =
        lib.concatLines (lib.mapAttrsToList (n: v: "readonly ${n}=${lib.escapeShellArg v}") vars)
        + prelude
        + builtins.readFile (dir + "/${file}");
    };

  xdgOpen = script "xdg-open.sh" { runtimeInputs = [ pkgs.glib ]; };
  # The app in the core's FHS env (build.app), for an app module: from a package that builds itself with
  # buildFHSEnv and takes it as an override (as llm-agents' claude-desktop does), or for one that doesn't, a buildFHSEnv
  # of the app's own arguments (name, runScript, targetPkgs, ...). Either way through the core's bwrap and with the
  # core's arguments (build.fhsEnvArgs: the app's pid, the files, /etc, the subid shims, xdg-open)
  fhsAppOf =
    lcfg: package:
    package.override (prev: {
      buildFHSEnv = args: (prev.buildFHSEnv.override { bubblewrap = bwrapFhs; }) (lcfg.build.fhsEnvArgs args);
    });
  fhsEnvOf = lcfg: args: (pkgs.buildFHSEnv.override { bubblewrap = bwrapFhs; }) (lcfg.build.fhsEnvArgs args);
  # Where a path the app keeps in the home directory (rel, relative to it) is on the host: its bind's source when bound
  # read-write, null when not; hostPathOf the sandbox's home in that case. A read-only bind is the host's alone: the
  # state script, which binds what it works in read-write (confine.sh), never writes there
  hostBindOf =
    lcfg: rel:
    let
      b = lcfg.permissions.binds."${hm.home.homeDirectory}/${rel}" or null;
    in
    if b != null && b.enable && b.rw then b.src else null;
  # For build.homeDirs: the host sources of those of rels that are bound read-write
  boundHomeDirsOf = lcfg: rels: lib.filter (d: d != null) (map (hostBindOf lcfg) rels);
  hostPathOf =
    lcfg: launcherName: rel:
    let
      bound = hostBindOf lcfg rel;
    in
    if bound != null then bound else "${(idsOf launcherName).home}/${rel}";
  # For an app module's config: directories the app keeps in the home (rels), bound read-write from the host's own for
  # the default launcher (a named one keeps them in its sandbox's home), and among the directories the state script works
  # in (build.homeDirs) where bound. `bind` adds to each bind
  keepInHome =
    lcfg: launcherName: rels: bind: {
      permissions.binds = lib.mkIf (launcherName == null) (
        lib.genAttrs (map (r: "${hm.home.homeDirectory}/${r}") rels) (_: { rw = true; } // bind)
      );
      build.homeDirs = boundHomeDirsOf lcfg rels;
    };
  # The packages on the sandbox's PATH: the launcher's path, the app's (build.pathPackages), then the same nix as the
  # host, so the sandbox's store database is never migrated to a schema one side can't read. .out: the man output is
  # a symlink, see storeRoots
  sandboxPackagesOf =
    lcfg:
    lcfg.path
    ++ lcfg.build.pathPackages
    ++ [
      osConfig.nix.package.out
      # journalctl and systemctl ahead of the FHS env's systemd-minimal, which reads no compressed journal and has no
      # user units; the host's, as the namespace's journald, and in the sandbox's closure already
      osConfig.systemd.package
    ];
  # PATH for the app (Claude Desktop: its Code tab's shells and the claude-code MCP server)
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
  # The sandbox's name, <app>[-<launcher>]: what every name of the sandbox on the host starts with, and what the
  # privileged helpers (netns-netkit, sandbox-hooks) and the broker know it by
  sandboxOf = name: "${app.name}${suffixOf name}";
  # Every sandbox of every app of the user (shared.nix): what no sandbox may reach, and what must differ between any two
  allSandboxes = hm.agent-sandbox.sandboxes;
  # The runtime dir all apps' launchers share, below $XDG_RUNTIME_DIR: the warnings and errors of their starts, the
  # brokers' grant dirs and control sockets, the GC roots of their closures and subid-broker's sockets
  runtimeDir = "agent-sandbox";
  # The longest sandbox name, <app>[-<launcher>], see the launcher name's assertion: the tightest of the socket paths it
  # goes into, each at most 107 bytes and the NUL (sandboxSockets). cmd/launcher/warn_test.go binds the warning socket
  # at it and cmd/permissions-broker/socketpath_test.go the broker's, internal/caller takes no longer one, and the eval
  # tests check they agree
  sandboxNameMax = 47;
  # The longest launcher name of this app: what the sandbox name leaves besides the app's and its -
  launcherNameMax = sandboxNameMax - lib.stringLength app.name - 1;
  # The sockets bound by a path the sandbox's name is in, with the longest runtime dir (a 10-digit uid): the broker's
  # control socket and request.sock, 60 bytes besides the name, the varlink socket of the sandbox's journald
  # namespace (systemd-journald-varlink@.socket, which systemd-journald@.service requires and systemd refuses past
  # 107 bytes), 48, and the launcher's warning socket (cmd/launcher warn.go), 52
  sandboxSockets =
    name:
    let
      ids = idsOf name;
      runtime = "/run/user/4294967294/${runtimeDir}";
    in
    [
      "${runtime}/${ids.appUnit}.warn"
      "${runtime}/${ids.permissions}-control.sock"
      "${runtime}/${ids.permissions}/request.sock"
      "/run/systemd/journal.${ids.sandboxJournal}/io.systemd.journal"
    ];
  # Holds the sandbox's home directory, its Nix store and Claude Code's temp dir (home/, nix/, tmp-scratchpad/)
  stateDirOf = name: "${hm.xdg.dataHome}/${sandboxOf name}";
  # The launcher's cgroup slice, holding the app's unit, the broker's and its calls'. A - in
  # a slice's name nests it in the slice before it (claude-desktop-work.slice in claude-desktop.slice), so each is
  # escaped: one slice per launcher, each a sibling of app.slice. systemd makes it when a unit names it
  sliceOf = name: "${lib.replaceStrings [ "-" ] [ "\\x2d" ] (sandboxOf name)}.slice";
  # The app's pid in the FHS env's pid ns (see app-pid.sh), one per sandbox of any app: their tray items share the
  # session bus. 100 and up by app and launcher, the default one first
  appPidOf = name: 100 + lib.lists.findFirstIndex (s: s.sandbox == sandboxOf name) null allSandboxes;
  # What a launcher is called by: its file name suffix, the sandbox's app ID (the proxy's /.flatpak-info names the
  # app by it to the portals, and the wrapper finds its running sandbox by it; it names the launcher's .desktop file
  # and its windows' app ID too, the Permissions window's included: gnome-shell drops a portal notification unless
  # <app ID>.desktop exists. The default launcher's is upstream's, so its .desktop file keeps upstream's name; a
  # launcher's name is a valid last element), and its state dir with the sandbox's home and scratchpad in it
  idsOf =
    name:
    let
      stateDir = stateDirOf name;
      sandbox = sandboxOf name;
      appId = "${app.appId}${lib.optionalString (name != null) ".${name}"}";
    in
    {
      inherit
        name
        appId
        stateDir
        sandbox
        ;
      suffix = suffixOf name;
      desktopFile = "${appId}.desktop";
      appPid = appPidOf name;
      slice = sliceOf name;
      # The app's unit, and the start of the names of the host's units for its daemons (cmd/launcher hostUnits)
      appUnit = "${sandbox}-app.service";
      unitPrefix = sandbox;
      # Its journald namespaces, which the NixOS module runs: the host side's, which the sandbox reads but can't write
      # to, and the sandbox's, with the app's output. _ is in no sandbox name
      journal = sandbox;
      sandboxJournal = "${sandbox}_sandbox";
      # The broker's grant dir in the runtime dir, and with -control.sock its control socket
      permissions = "${sandbox}-permissions";
      # What the user sees it called: the splash's title, a named launcher's .desktop Name
      displayName = "${app.displayName}${lib.optionalString (name != null) " (${name})"}";
      home = "${stateDir}/home";
      scratchpad = "${stateDir}/tmp-scratchpad";
      # Where the option's definitions say so in messages
      opt = "agent-sandbox.${app.name}: ${lib.optionalString (name != null) "launchers.${name}."}";
    };

  # bwrap with a range of ids, see cmd/launcher bwrap.go: the FHS env's inside, mode parent, which shares the
  # permissions broker's grant directory first. nixpak's, mode subid, is network.nix's, as it sets up the launcher's
  # network
  bwrapOf =
    args:
    pkgs.writeShellApplication {
      name = "bwrap";
      text = "exec ${lib.getExe packages.launcher} bwrap --bwrap=${lib.getExe' pkgs.bubblewrap "bwrap"} ${lib.escapeShellArgs args} -- \"$@\"\n";
    };
  bwrapFhs = bwrapOf [
    "--mode=parent"
    "--newuidmap=${lib.getExe' packages.subid-broker "newuidmap"}"
    "--newgidmap=${lib.getExe' packages.subid-broker "newgidmap"}"
    "--permissions-broker=${lib.getExe packages.permissions-broker}"
  ];

  # Written by the host's activation, bound from its /etc
  hostEtc = [
    "passwd"
    "group"
    "machine-id"
  ];
  # A launcher's resolv.conf (see network.nix) as the sandbox sees it, where its home directory is bound
  sandboxResolvConf = "${hm.home.homeDirectory}/.config/resolv.conf";
  # The root of the same store without the FHS env's mounts in it (fhs.nix), for `--store local?root=` builds
  nixRoot = "/nix-root";
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
  # The app's environment.md with the core's (this directory's) in place of its `<!-- agent-sandbox: core -->` line,
  # split by its markers (see environment-split.sh): all of it, the part every session needs, and the rest as a memo
  # store
  environment = pkgs.runCommand "${app.name}-environment" {
    nativeBuildInputs = [ pkgs.gawk ];
    MODE = "app";
    APP_SRC = app.environment;
    CORE_SRC = ./environment.md;
    APP = app.name;
    APP_ID = app.appId;
    ENVIRONMENT_PATH = app.environmentPath;
    NAME = "agent-sandbox/${app.name}";
    DESCRIPTION = "The ${app.description} sandbox you run in: its home, its user namespaces and its Nix store.";
    # As in environmentDoc's frontmatter
    ENVIRONMENT = "bwrap";
  } "source ${./environment-split.sh}";
  # The memo store of the core's sections that load by topic, which every app's sandbox shares: one store path whatever
  # the app, so a host with two apps lists it once
  coreEnvironment = pkgs.runCommand "agent-sandbox-environment" {
    nativeBuildInputs = [ pkgs.gawk ];
    MODE = "core";
    CORE_SRC = ./environment.md;
    NAME = "agent-sandbox/core";
    DESCRIPTION = "The agent sandbox you run in, whatever its app: its home, its user namespaces and its Nix store.";
    ENVIRONMENT = "bwrap";
  } "source ${./environment-split.sh}";
  # The memo stores of a launcher with memo.enable: the core's, and the app's own when its part of the doc has sections
  # that load by topic (app.environment is a file, read at eval)
  memoStores =
    [ "${coreEnvironment}/environment.memo" ]
    ++ lib.optional (lib.hasInfix "<!-- memo: " (builtins.readFile app.environment)) "${environment}/environment.memo";
  # The options of a feature (features.nix): a switch, its words for the user and for the agent, and its body. The body
  # is definitions of the launcher's `permissions` options, kept as they were written, mkForce and the like inside
  # them included, until features.nix merges them into those options while the feature is on
  feature = {
    options = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Turn the feature on.";
      };
      description = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "What the feature gives the sandbox, in one line, for the user and for the agent: the Permissions window and the sandbox's environment doc (`/etc/claude/environment.md` for Claude Desktop) show it while the feature is on. Required for a feature that is on.";
      };
      note = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "What to know before turning the feature on, in one line: what it exposes, what it changes. Shown with the description.";
      };
      permissions = lib.mkOption {
        type = lib.mkOptionType {
          name = "permissions";
          description = "definitions of `permissions` options";
          descriptionClass = "noun";
          merge = _: defs: lib.mkMerge (map (d: d.value) defs);
        };
        default = { };
        example = lib.literalExpression ''{ devices."/dev/kvm" = { }; }'';
        description = "The body: definitions of the launcher's `permissions` options, merged into them while the feature is on, so the assertions on those options hold for what it adds and an entry it adds is overridden like any other.";
      };
    };
  };
  # Whether path a is path b or holds it
  holds = a: b: a == b || lib.hasPrefix "${lib.removeSuffix "/" a}/" b;
  # Whether a string is an absolute path in its clean form: no ., .. or empty segments, so no two spellings of one
  # path. The checks on paths compare them as written
  cleanPath =
    p:
    p == "/"
    ||
      lib.hasPrefix "/" p
      && !lib.any (
        seg:
        lib.elem seg [
          ""
          "."
          ".."
        ]
      ) (lib.tail (lib.splitString "/" p));
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
