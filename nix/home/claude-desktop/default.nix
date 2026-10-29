# Namespaces of the sandbox. U1 maps the user's /etc/subuid and /etc/subgid range, inner id x as host start+x, except
# the user's own uid and gid (1000 and 100 below), which stay themselves: everything the app writes to host paths is
# the user's. U2 maps all of U1's ids as themselves. bwrap-subid.sh writes both maps.
#
# init userns (host)
# │  runs: nixpak launcher, xdg-dbus-proxy, the pasta-slot script (netSetup), bwrap's parent,
# │        netns-macvlan (cap_net_admin, creates eth0 in N), subid-broker (writes maps below U1 on request)
# │
# └─ U1  bwrap's userns (0-999 → start+0-999, 1000 → 1000, 1001-65535 → start+1001-65535)
#    │  owns: N (netns: lo + eth0 macvlan), M1 (sandbox mount tree), P (pid ns), ipc, uts, cgroup
#    │  runs (in N, M1, P): bwrap's init and the FHS env script as uid 1000 without capabilities; udhcpc +
#    │        dhcpScript (net_admin and net_raw only), netSetup's ip calls (in N)
#    │
#    └─ U2  buildFHSEnv's bwrap (all of U1's ids)
#          owns: M2 (tmpfs /etc with the rootfs' resolv.conf and hosts links, subuid and subgid, patched app.asar),
#                P2 (pid ns, where app-pid.sh starts the app at a pid of the launcher's, with CAP_CHECKPOINT_RESTORE)
#          runs (in N, M2, P2): Claude Desktop, Code tab shells, the local MCP servers, `claude-desktop --shell`,
#                claude:// re-entry, and the user namespaces they create, whose maps the newuidmap and newgidmap
#                shims ask subid-broker for
{ inputs }:
{
  pkgs,
  lib,
  config,
  options,
  osConfig,
  ...
}:
let
  cfg = config.agent-sandbox.claude-desktop;
  inherit (lib)
    mkOption
    types
    escapeShellArg
    ;
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
        lib.concatLines (lib.mapAttrsToList (n: v: "readonly ${n}=${escapeShellArg v}") vars)
        + prelude
        + builtins.readFile (./. + "/${file}");
    };

  xdgOpen = script "xdg-open.sh" { runtimeInputs = [ pkgs.glib ]; };

  subidBroker = inputs.self.packages.${pkgs.stdenv.hostPlatform.system}.subid-broker;
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
    SUBID_BROKER = lib.getExe subidBroker;
  };
  bwrapFhs = bwrapSubid {
    SUBID_MAP = "parent";
    NEWUIDMAP = lib.getExe' subidBroker "newuidmap";
    NEWGIDMAP = lib.getExe' subidBroker "newgidmap";
  };

  # A named launcher's suffix to file names, empty for the default one
  suffixOf = name: lib.optionalString (name != null) "-${name}";
  # Holds the sandbox's home directory, its Nix store and Claude Code's temp dir (home/, nix/, tmp-scratchpad/)
  stateDirOf = name: "${config.xdg.dataHome}/claude-desktop${suffixOf name}";
  # The app's pid in the FHS env's pid ns (see app-pid.sh), one per launcher: their tray items share the session bus
  appPidOf = name: 100 + lib.lists.findFirstIndex (n: n == name) null ([ null ] ++ lib.attrNames cfg.launchers);
  # The same nix as the host, so the sandbox's store database is never migrated to a schema one side can't read
  # .out: the man output is a symlink, see storeRoots
  sandboxPackagesOf = lcfg: lcfg.path ++ [ osConfig.nix.package.out ];
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

  # The sandbox's own single-user Nix store, stateDir/nix bound rw at /nix. The host store isn't visible: nixpak binds
  # only storeRoots' closure (ro, over the store's copies of the same paths) and there is no daemon socket.
  # Paths have to be valid in the store before the binds land on them, or bwrap mkdirs unregistered
  # mountpoints in it, so the wrapper copies the closure in and roots it before every launch
  nixConf = pkgs.writeTextDir "nix.conf" ''
    experimental-features = nix-command flakes
    substituters = https://cache.nixos.org/
    trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
  '';
  # Run by the user's own hooks, see environment.md
  storeGc = script "store-gc.sh" {
    name = "claude-desktop-store-gc";
    runtimeInputs = [
      osConfig.nix.package
      pkgs.coreutils
      pkgs.findutils
      pkgs.gnugrep
      pkgs.util-linux
    ];
  };
  scratchpadPrune = script "scratchpad-prune.sh" {
    name = "claude-desktop-scratchpad-prune";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.findutils
    ];
  };
  # Written by the host's activation, bound from its /etc
  hostEtc = [
    "passwd"
    "group"
    "machine-id"
  ];
  # The host's /run/opengl-driver, as NixOS builds it
  graphicsDrivers = pkgs.buildEnv {
    name = "graphics-drivers";
    paths = [ osConfig.hardware.graphics.package ] ++ osConfig.hardware.graphics.extraPackages;
  };
  # A launcher's resolv.conf (see resolvConf) as the sandbox sees it, where its home directory is bound
  sandboxResolvConf = "${config.home.homeDirectory}/.config/resolv.conf";
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
  dhcpScript = script "udhcpc.sh" {
    name = "claude-desktop-udhcpc";
    runtimeInputs = [ pkgs.iproute2 ];
    vars.RESOLV_CONF = sandboxResolvConf;
  };
  # The Bash tool sources CLAUDE_ENV_FILE before each command. The Code tab gets this from the SessionStart hook,
  # which claude mcp serve does not run. Drops the snapshot's ugrep/bfs shadows of grep and find
  bashEnv = pkgs.writeText "claude-bash-env" "unset -f grep find 2>/dev/null\n";
  # environment.md split by its markers (see environment-split.sh): all of it, the part every session needs, and the
  # rest as a memo store
  environment =
    pkgs.runCommand "claude-desktop-environment"
      {
        nativeBuildInputs = [ pkgs.gawk ];
        SRC = ./environment.md;
        NAME = "agent-sandbox/claude-desktop";
        DESCRIPTION = "The Claude Desktop sandbox you run in: its home, its user namespaces and its Nix store.";
        # As in environmentDoc's frontmatter
        ENVIRONMENT = "bwrap";
      }
      "source ${./environment-split.sh}";
  # Home Manager's memo, when imported
  memoCfg = config.programs.agent-memos or { };
  # memo's config with the sandbox's store right after the embedded ones. The host's config can't list it: memo
  # reports a missing store on every call
  memoConfig =
    let
      stores = memoCfg.settings.stores or [ ];
      embeds = lib.length (memoCfg.embeds or [ ]);
    in
    (pkgs.formats.yaml { }).generate "agent-memos-config.yaml" (
      memoCfg.settings or { }
      // {
        stores = lib.take embeds stores ++ [ "/etc/claude/environment.memo" ] ++ lib.drop embeds stores;
      }
    );
  # programs.mcp.servers as Home Manager's own clients take them, env files through a wrapper. Disabled ones left out
  hmMcpServers = lib.optionalAttrs config.programs.mcp.enable (
    lib.mapAttrs (_: s: removeAttrs s [ "enabled" ]) (
      lib.filterAttrs (_: s: s.enabled or true) (
        lib.mapAttrs (
          name: server:
          lib.hm.mcp.transformMcpServer {
            inherit server;
            extraTransforms = [ (lib.hm.mcp.wrapEnvFilesCommand { inherit pkgs name; }) ];
          }
        ) config.programs.mcp.servers
      )
    )
  );

  # Options of the default launcher and each named one, lcfg being its settings
  launcherOptions = lcfg: {
    package =
      lib.mkPackageOption inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system} "claude-desktop"
        { pkgsText = "inputs.llm-agents.packages.\${system}"; };
    sandbox = mkOption {
      type = types.deferredModule;
      default = { };
      description = "Extra nixpak configuration.";
    };
    environmentFile = mkOption {
      type = types.path;
      default = "${environment}/${lib.optionalString lcfg.memo.enable "core-"}environment.md";
      defaultText = lib.literalMD "`environment.md`, with `memo.enable` only the sections every session needs";
      description = "What Claude in the sandbox knows about it, imported by `/etc/claude/environment.md`. Replace it to describe a consumer's own setup.";
    };
    memo.enable = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Give the sandbox Home Manager's memo (`programs.agent-memos`): its package on PATH, and its config with the
        sandbox's own store, `/etc/claude/environment.memo`, right after the embedded stores. That store holds the
        sections of `environment.md` that load by topic, and `environmentFile` keeps the rest.
      '';
    };
    environmentText = mkOption {
      type = types.lines;
      default = "";
      description = "Appended to the sandbox's `/etc/claude/environment.md`, which Claude loads every session: per-user notes, `@` imports and read-when triggers.";
    };
    binds = mkOption {
      type = types.attrsOf (
        types.submodule (
          { name, ... }:
          {
            options = {
              enable = mkOption {
                type = types.bool;
                default = true;
                description = "Mount the path.";
              };
              optional = mkOption {
                type = types.bool;
                default = false;
                description = "Skip the bind when the host path is missing. Otherwise the launcher refuses to start.";
              };
              src = mkOption {
                type = types.str;
                default = name;
                defaultText = lib.literalExpression "<name>";
                description = "Host path.";
              };
              rw = mkOption {
                type = types.bool;
                default = false;
                description = "Mount read-write.";
              };
              mcp = mkOption {
                type = types.bool;
                default = true;
                description = "Expose the path to the filesystem MCP server.";
              };
            };
          }
        )
      );
      default = { };
      description = "Host paths mounted in the sandbox, keyed by the path in the sandbox.";
    };
    files = mkOption {
      type = types.attrsOf (
        types.submodule (
          { name, config, ... }:
          {
            options = {
              enable = mkOption {
                type = types.bool;
                default = true;
                description = "Mount the file.";
              };
              text = mkOption {
                type = types.nullOr types.lines;
                default = null;
                description = "Content of the file. Sets `source`.";
              };
              source = mkOption {
                type = types.path;
                description = "File or directory. The sandbox's store gets it with everything it references.";
              };
            };
            config.source = lib.mkIf (config.text != null) (
              lib.mkDefault (pkgs.writeText (lib.strings.sanitizeDerivationName (baseNameOf name)) config.text)
            );
          }
        )
      );
      default = { };
      example = lib.literalExpression ''{ "/etc/foo/config.json".source = (pkgs.formats.json { }).generate "config.json" { }; }'';
      description = "Files from the Nix store mounted read-only in the sandbox, keyed by the path in the sandbox.";
    };
    env = mkOption {
      type =
        let
          var = types.submodule {
            options = {
              enable = mkOption {
                type = types.bool;
                default = true;
                description = "Set the variable.";
              };
              value = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = ''
                  Value, placed between double quotes in bash at launch, so `$VAR` expands from the host
                  environment. `null` passes the host variable through when it is set.
                '';
              };
            };
          };
        in
        types.attrsOf (types.coercedTo types.str (value: { inherit value; }) var);
      default = { };
      description = "Environment variables in the sandbox, keyed by name. A string is shorthand for `value`.";
    };
    audio = mkOption {
      type = types.bool;
      default = false;
      description = "Mount the PipeWire and PulseAudio sockets. Unmediated access: microphone, camera and screen-cast streams included.";
    };
    kvm = mkOption {
      type = types.bool;
      default = false;
      description = "Mount `/dev/kvm`, for VMs and NixOS tests in the sandbox. Exposes the host kernel's KVM interface: a KVM bug is a way out of the sandbox.";
    };
    devices = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [
        "/dev/nvidiactl"
        "/dev/nvidia0"
        "/dev/nvidia-modeset"
      ];
      description = ''
        Device nodes mounted in the sandbox, each only if it exists on the host at launch. No globs. Exposes the
        driver's ioctl interface: a driver bug is a way out of the sandbox.
      '';
    };
    tray = mkOption {
      type = types.bool;
      default = false;
      description = "Show a tray icon. Closing the window then hides the app instead of quitting it.";
    };
    extraPath = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = lib.literalExpression ''[ "''${config.home.homeDirectory}/.claude/bin" ]'';
      description = "Directories on PATH ahead of `path`'s packages, for the app, its Code tab shells and the claude-code MCP server.";
    };
    path = mkOption {
      type = types.listOf types.package;
      default = with pkgs; [
        coreutils
        findutils
        diffutils
        gnugrep
        gnused
        gawk
        git
        ripgrep
        jq
        gh
        shellcheck
        git-filter-repo
        python3
        unzip
        curl
        procps
        util-linux
        iproute2
        which
        file
      ];
      description = "Packages on PATH for the app, its Code tab shells and the local MCP servers.";
    };
    mcpServers = mkOption {
      type = types.attrsOf (pkgs.formats.json { }).type;
      readOnly = true;
      description = "Local MCP servers the app gets, replacing `mcpServers` in claude_desktop_config.json on launch: the sandbox's `filesystem` and `claude-code`, and `programs.mcp.servers`.";
    };
  };

  # What every launcher's env and binds start with
  launcherDefaults =
    name: lcfg:
    let
      stateDir = stateDirOf name;
      sys = {
        mcp = false;
      };
    in
    {
      mcpServers = {
        filesystem = {
          command = lib.getExe (
            script "mcp-server-filesystem.sh" {
              runtimeInputs = [ pkgs.jq ];
              vars.MCP_SERVER_FILESYSTEM = lib.getExe pkgs.mcp-server-filesystem;
            }
          );
          args = lib.attrNames (lib.filterAttrs (_: b: b.enable && b.mcp) lcfg.binds);
        };
        claude-code = {
          command = lib.getExe inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.claude-code;
          args = [
            "mcp"
            "serve"
          ];
          env = {
            PATH = searchPathOf lcfg;
            CLAUDE_ENV_FILE = "${bashEnv}";
            NIX_CONF_DIR = "${nixConf}";
          };
        };
      }
      // hmMcpServers;
      env =
        lib.genAttrs [
          "HOME"
          "USER"
          "LANG"
          "LC_ALL"
          "XDG_RUNTIME_DIR"
          "WAYLAND_DISPLAY"
          "XDG_SESSION_TYPE"
          "XDG_CONFIG_DIRS"
          "XCURSOR_THEME"
          "XCURSOR_SIZE"
          # The host bus, for nixpak's D-Bus proxy. The sandbox gets the proxy's address
          "DBUS_SESSION_BUS_ADDRESS"
        ] (_: { })
        // {
          # nixpak binds /etc/localtime as a file, so ICU can't read the zone name from the link target
          TZ.value = osConfig.time.timeZone;
          PATH = "${xdgOpen}/bin:${searchPathOf lcfg}";
          # Not the login shell from /etc/passwd
          SHELL = "/run/current-system/sw/bin/bash";
          NIXOS_OZONE_WL = "1";
          # Chromium takes the first desktop it knows. On GNOME it hands the tray its icon as a file in the sandbox's
          # /tmp, which the shell can't read; on COSMIC as pixmaps, with the same GTK theme and proxy settings. GLib and
          # the app's own checks still find GNOME in the list. Empty when the host's is unset
          XDG_CURRENT_DESKTOP = "\${XDG_CURRENT_DESKTOP:+\${XDG_CURRENT_DESKTOP/GNOME/COSMIC:GNOME}}";
          NIX_CONF_DIR = "${nixConf}";
          # Where gtk-theme.sh writes the theme
          GSETTINGS_BACKEND = "keyfile";
          XDG_DATA_DIRS = "${pkgs.gnome-themes-extra}/share\${XDG_DATA_DIRS:+:$XDG_DATA_DIRS}";
        };
      binds = {
        "/nix" = sys // {
          src = "${stateDir}/nix";
          rw = true;
        };
        "/sys" = sys;
        ${config.home.homeDirectory} = sys // {
          src = "${stateDir}/home";
          rw = true;
        };
      }
      # A named launcher keeps them in its own home
      // lib.optionalAttrs (name == null) {
        "${config.home.homeDirectory}/.claude".rw = true;
        "${config.home.homeDirectory}/.config/Claude" = sys // {
          rw = true;
        };
      }
      // lib.genAttrs (map (e: "/etc/${e}") hostEtc) (_: sys // { optional = true; });
      path = lib.mkIf lcfg.memo.enable (lib.mkOptionDefault [ memoCfg.package ]);
      files = lib.mkIf lcfg.memo.enable {
        "${config.home.homeDirectory}/.config/agent-memos/config.yaml".source = memoConfig;
        "/etc/claude/environment.memo".source = "${environment}/environment.memo";
      };
    };

  # What one launcher builds from its settings, lcfg. name is null for the default launcher
  launcher =
    name: lcfg:
    let
      suffix = suffixOf name;
      stateDir = stateDirOf name;
      appPid = appPidOf name;
      bwrapHome = "${stateDir}/home";
      scratchpad = "${stateDir}/tmp-scratchpad";
      sandboxPackages = sandboxPackagesOf lcfg;
      searchPath = searchPathOf lcfg;
      # Where a path under the home directory is on the host: its bind's source, or the sandbox's home
      hostPath =
        rel:
        let
          b = lcfg.binds."${config.home.homeDirectory}/${rel}" or null;
        in
        if b != null && b.enable then b.src else "${bwrapHome}/${rel}";
      # /run/current-system links into the system closure: the PATH tools, bash (SHELL) and glibc's fallback
      # locale archive come from this instead
      currentSystemSw = pkgs.buildEnv {
        name = "claude-desktop-sw";
        paths = sandboxPackages ++ [
          pkgs.bashInteractive
          osConfig.i18n.glibcLocales
          storeGc
          scratchpadPrune
        ];
      };
      # The entries claude-desktop's FHS env takes from /etc, minus shadow, sudoers, nix (NIX_CONF_DIR) and the
      # shell rc files (the sandbox's shell is bash with the FHS env's /etc/profile, not the host's login shell)
      etcEntries =
        hostEtc
        ++ [
          "nsswitch.conf"
          "localtime"
          "zoneinfo"
          "os-release"
          "fonts"
          "ssl/certs"
          "pki"
        ]
        ++ lib.optional lcfg.audio "alsa";
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
      # Everything the sandbox runs from the store. nixpak's closure only covers the app and extraStorePaths, not
      # env values or bind sources, so they all go in here. nixpak --ro-binds every closure path, and bwrap won't
      # mount onto the symlink a symlink store path already is in the store, so those fail the build here
      storeRoots =
        let
          roots = [
            package
            netSetup
            xdgOpen
            # The dark theme gtk-theme.sh switches to; GTK3 has none built in
            pkgs.gnome-themes-extra
            nixConf
            currentSystemSw
            graphicsDrivers
            mcpServers
            bashEnv
            etc
          ];
        in
        pkgs.runCommand "claude-desktop-store-roots" { closure = pkgs.closureInfo { rootPaths = roots; }; }
          ''
            while read -r p; do
              [[ ! -L $p ]] || { echo "$p is a symlink, nixpak can't bind it over the sandbox store's copy" >&2; exit 1; }
            done <"$closure/store-paths"
            printf '%s\n' ${lib.escapeShellArgs roots} >$out
          '';
      storeSync = script "store-sync.sh" {
        name = "claude-desktop-store-sync";
        runtimeInputs = [ osConfig.nix.package ];
        vars = {
          STATE_DIR = stateDir;
          STORE_ROOTS = "${storeRoots}";
        };
      };
      # Shallowest first, so nested binds override their parents. nixpak mounts all rw binds before the ro ones
      binds =
        rw:
        map
          (
            b:
            if b.src == b.path then
              b.src
            else
              [
                b.src
                b.path
              ]
          )
          (
            lib.sortOn (b: lib.stringLength b.path) (
              lib.mapAttrsToList (path: b: b // { inherit path; }) (
                lib.filterAttrs (_: b: b.enable && b.rw == rw) lcfg.binds
              )
            )
          );

      devices = lib.unique (lib.optional lcfg.kvm "/dev/kvm" ++ lcfg.devices);

      asar = "${lcfg.package.unwrapped}/lib/claude-desktop/resources/app.asar";
      patchedAsar = pkgs.runCommand "claude-desktop-app.asar" {
        nativeBuildInputs = [
          pkgs.asar
          pkgs.jq
        ];
        ASAR = asar;
      } "source ${./patch-asar.sh}";
      # The sandbox gets its own netns with a macvlan on the LAN (netns-macvlan --help), so host
      # services, routes and abstract sockets stay out of reach. Its DHCP lease brings the DNS servers
      resolvConf = "${bwrapHome}/.config/resolv.conf";
      # Runs in nixpak's pasta slot, see net-setup.sh
      netSetup = script "net-setup.sh" {
        name = "pasta";
        runtimeInputs = [
          pkgs.coreutils
          pkgs.util-linux
          pkgs.iproute2
        ];
        vars = {
          NETNS_MACVLAN = "${osConfig.security.wrapperDir}/netns-macvlan";
          SETPRIV = lib.getExe' pkgs.util-linux "setpriv";
          UDHCPC = lib.getExe' pkgs.busybox "udhcpc";
          UDHCPC_SCRIPT = lib.getExe dhcpScript;
          # Salts the macvlan's MAC, so launchers don't clash on the LAN
          NAME = lib.optionalString (name != null) name;
        };
      };

      # The FHS env's runScript, see app-pid.sh
      appPidScript = script "app-pid.sh" {
        name = "claude-desktop-app-pid";
        vars = {
          APP_PID = toString appPid;
          SETPRIV = lib.getExe' pkgs.util-linux "setpriv";
          SETSID = lib.getExe' pkgs.util-linux "setsid";
        };
      };

      # nixpak binds /nix/store after all bind.ro entries, so the overlay and environment.md go into the FHS env's own bwrap,
      # as do the files: the FHS env links only some entries of the outer /etc. Being in the package, they're in storeRoots.
      # resolv.conf and hosts are links in its rootfs, which win over the host ones that nixpak's pasta module binds
      # (the FHS env links the rest of /etc to /.host-etc, the outer /etc). A bind onto those would fail once the host
      # replaced the file under it. shadow's newuidmap and newgidmap in the rootfs are the broker's shims, for tools that
      # run them by path: setuid can't work in bwrap, which sets no_new_privs
      package = lcfg.package.override (prev: {
        buildFHSEnv =
          args:
          (prev.buildFHSEnv.override { bubblewrap = bwrapFhs; }) (
            args
            // {
              unsharePid = true;
              runScript = "${lib.getExe appPidScript} ${args.runScript or "bash"}";
              extraBwrapArgs = args.extraBwrapArgs or [ ] ++ [
                # For app-pid.sh, which drops it
                "--cap-add CAP_CHECKPOINT_RESTORE"
                "--ro-bind ${patchedAsar} ${asar}"
                "--ro-bind ${environmentDoc} /etc/claude/environment.md"
                # Written by bwrap-subid.sh
                "--ro-bind-data 22 /etc/subuid"
                "--ro-bind-data 23 /etc/subgid"
              ]
              # Shallowest first, so a file in a bound directory overrides it
              ++ map (f: "--ro-bind ${f.source} ${lib.escapeShellArg f.path}") (
                lib.sortOn (f: lib.stringLength f.path) (
                  lib.mapAttrsToList (path: f: f // { inherit path; }) (lib.filterAttrs (_: f: f.enable) lcfg.files)
                )
              );
              profile = args.profile or "" + builtins.readFile ./fhs-profile.sh;
              extraBuildCommands = args.extraBuildCommands or "" + ''
                ln -s ${sandboxResolvConf} $out/etc/resolv.conf
                ln -s ${hosts} $out/etc/hosts
                for f in {bin,sbin}/new{u,g}idmap; do
                  ln -sf ${subidBroker}/bin/''${f#*/} $out/usr/$f
                done
              '';
            }
          );
      });

      sandboxed = inputs.nixpak.lib.nixpak { inherit lib pkgs; } {
        config =
          { sloth, ... }:
          {
            imports = [ lcfg.sandbox ];
            # The wrapper finds its running sandbox by it
            flatpak.appId = lib.mkIf (name != null) "com.nixpak.ClaudeDesktop.${name}";
            app.package = package;
            dbus.policies = {
              "org.freedesktop.Notifications" = "talk";
            }
            // lib.optionalAttrs lcfg.tray {
              # Chromium names it StatusNotifierItem-<pid>-<n>
              "org.kde.StatusNotifierWatcher" = "talk";
              "org.freedesktop.StatusNotifierItem-${toString appPid}-1" = "own";
            };
            dbus.rules.call."org.freedesktop.portal.Desktop" = [
              "org.freedesktop.portal.OpenURI.OpenURI@/org/freedesktop/portal/desktop"
              "org.freedesktop.portal.Settings.*@/org/freedesktop/portal/desktop"
            ];
            dbus.rules.broadcast."org.freedesktop.portal.Desktop" = [
              "org.freedesktop.portal.Settings.SettingChanged@/org/freedesktop/portal/desktop"
            ];
            gpu = {
              enable = true;
              # Not "nixos": /run/opengl-driver links into the system closure
              provider = "bundle";
              bundlePackage = graphicsDrivers;
            };
            # Hardcoded, see netSetup. transparent: bind the host's /etc/hosts and resolv.conf (both covered in package), no extra pasta args
            bubblewrap.network = lib.mkForce true;
            pasta = {
              enable = lib.mkForce true;
              package = lib.mkForce netSetup;
              mode = lib.mkForce "transparent";
              args = lib.mkForce [ ];
            };
            bubblewrap = {
              package = bwrapHost;
              bindEntireStore = false;
              extraStorePaths = [ storeRoots ];
              bind.rw = binds true;
              # Claude Code's temp dir, so the session scratchpads survive restarts (pruned by scratchpad-prune.sh).
              # A dev bind because nixpak mounts the /tmp tmpfs after the rw and ro binds and before the dev ones.
              # It still ends up nodev where the app runs: the FHS env's bwrap binds /tmp on with nodev
              bind.dev = [
                [
                  scratchpad
                  (sloth.concat' "/tmp/claude-" sloth.uid)
                ]
              ]
              ++ devices;
              bind.ro =
                binds false
                ++ etcBinds
                ++ [
                  [
                    "${currentSystemSw}"
                    "/run/current-system/sw"
                  ]
                ];
              tmpfs = [ "/tmp" ];
              sockets = {
                wayland = true;
                pipewire = lcfg.audio;
                pulse = lcfg.audio;
              };
              newSession = true;
              dieWithParent = true;
            };
          };
      };

      mcpServers = pkgs.writeText "mcp-servers.json" (builtins.toJSON lcfg.mcpServers);
      # /etc/claude/environment.md, for the user's CLAUDE.md to import: an import of environmentFile (linked, so it's in
      # the closure), the binds (minus the ro system ones) and PATH as configured, then environmentText. claude-env reads
      # `environment:` from the frontmatter. Claude Code follows imports four hops deep, and ~/.claude reaches this file
      # in three (CLAUDE.md, the account's, the shared one), so environmentFile is the last that loads
      environmentDoc = pkgs.writeText "claude-environment.md" ''
        ---
        environment: bwrap
        ---

        @${lcfg.environmentFile}

        ## Binds

        ${
          lib.concatMapStrings
            (
              b:
              "- `${b.path}` (${
                lib.concatStringsSep ", " (
                  [ (if b.rw then "rw" else "ro") ]
                  ++ lib.optional b.mcp "MCP"
                  ++ lib.optional (b.src != b.path) "from `${b.src}`"
                )
              })\n"
            )
            (
              lib.sortOn (b: b.path) (
                lib.mapAttrsToList (path: b: b // { inherit path; }) (
                  lib.filterAttrs (_: b: b.enable && (b.rw || b.mcp)) lcfg.binds
                )
              )
            )
        }- `/tmp/claude-<uid>` (rw, from `${scratchpad}`): Claude Code's temp dir with the session scratchpads
        ${lib.concatMapStrings (d: "- `${d}` (dev, if present)\n") devices}
        ## PATH

        ${lib.concatMapStrings (d: "`${d}`, then ") lcfg.extraPath}the packages
        ${lib.concatMapStringsSep ", " lib.getName sandboxPackages}.
        ${lcfg.environmentText}
      '';

      # nixpak's sloth.env panics on unset variables, so filter the environment before its launcher.
      # Unset passthrough variables expand to nothing
      vars = lib.concatStringsSep "\n  " (
        lib.mapAttrsToList (
          n: v: if v.value == null then "\${${n}+\"${n}=\$${n}\"}" else "\"${n}=${v.value}\""
        ) (lib.filterAttrs (_: v: v.enable) lcfg.env)
      );

      gtkTheme = script "gtk-theme.sh" {
        name = "claude-desktop-gtk-theme";
        runtimeInputs = [ pkgs.glib ];
        vars = {
          SANDBOX_CONFIG = "${bwrapHome}/.config";
          SCHEMA_DIR = pkgs.glib.getSchemaPath pkgs.gsettings-desktop-schemas;
        };
      };
      gtkThemeWatch = script "gtk-theme-watch.sh" {
        name = "claude-desktop-gtk-theme-watch";
        runtimeInputs = [
          pkgs.glib
          pkgs.coreutils
          pkgs.procps
        ];
        vars.GTK_THEME = lib.getExe gtkTheme;
      };

      wrapper = script "claude-desktop.sh" {
        name = "claude-desktop${suffix}";
        runtimeInputs = [
          pkgs.jq
          osConfig.nix.package
        ];
        vars = {
          SANDBOX_HOME = bwrapHome;
          SCRATCHPAD = scratchpad;
          RESOLV_CONF = resolvConf;
          APP_ID = sandboxed.config.flatpak.appId;
          APP_PID = toString appPid;
          SETPRIV = lib.getExe' pkgs.util-linux "setpriv";
          DOT_CLAUDE = hostPath ".claude";
          CONFIG = "${hostPath ".config/Claude"}/claude_desktop_config.json";
          MCP_SERVERS = "${mcpServers}";
          TRAY = lib.boolToString lcfg.tray;
          STORE_SYNC = lib.getExe storeSync;
          STORE_ROOTS = "${storeRoots}";
          STORE_ROOTS_LINK = "store-roots${suffix}";
          GTK_THEME = lib.getExe gtkTheme;
          GTK_THEME_WATCH = lib.getExe gtkThemeWatch;
          NIXPAK_LAUNCHER = lib.getExe sandboxed.config.script;
        };
        prelude = ''
          VARS=(
            ${vars}
          )
          REQUIRED_BINDS=(
            ${lib.escapeShellArgs (
              lib.mapAttrsToList (_: b: b.src) (lib.filterAttrs (_: b: b.enable && !b.optional) lcfg.binds)
            )}
          )
          readonly VARS REQUIRED_BINDS
        '';
      };
      claude-desktop = pkgs.symlinkJoin {
        name = "claude-desktop${suffix}-sandboxed";
        # First path wins on collisions: the wrapper shadows nixpak's bin/claude-desktop, while the icons and the
        # .desktop file (Exec=claude-desktop, claude:// handler) carry over. A named launcher takes only a .desktop file of
        # its own: the default launcher installs the icons and keeps the claude:// handler
        paths = [ wrapper ] ++ lib.optional (name == null) sandboxed.config.env;
        postBuild = ''
          # The package's only .desktop file, whose name changed upstream
          set -- ${sandboxed.config.env}/share/applications/*.desktop
          [[ $# == 1 ]]
          d=$out/share/applications/${if name == null then "\${1##*/}" else "claude-desktop-${name}.desktop"}
          mkdir -p "$out/share/applications"
          rm -f "$d"
          sed -e 's/^Actions=.*/&;Shell/' ${
            lib.optionalString (name != null) (
              lib.escapeShellArgs [
                "-e"
                "0,/^Name=/s/^Name=.*/Name=Claude (${name})/"
                "-e"
                "s/^Exec=claude-desktop /Exec=claude-desktop-${name} /"
                "-e"
                "/^MimeType=/d"
              ]
            )
          } "$(readlink -f "$1")" >"$d"
          grep -q '^Actions=.*;Shell$' "$d"
          ${lib.optionalString (name != null) ''
            grep -qxF 'Name=Claude (${name})' "$d"
            ! grep -q '^Exec=claude-desktop ' "$d" || exit 1
            ! grep -q '^MimeType=' "$d" || exit 1
          ''}
          printf '\n[Desktop Action Shell]\nExec=%s %s --shell\nName=New shell\n' \
            ${lib.getExe pkgs.xdg-terminal-exec} "$out/bin/claude-desktop${suffix}" >>"$d"
        '';
      };
    in
    {
      inherit sandboxed netSetup claude-desktop;
    };
  # Built, the default one under ""
  launchers = {
    "" = launcher null cfg;
  }
  // lib.mapAttrs launcher cfg.launchers;

in
{
  options.agent-sandbox.claude-desktop = launcherOptions cfg // {
    enable = lib.mkEnableOption "Claude Desktop, sandboxed with nixpak";
    launchers = mkOption {
      type = types.attrsOf (
        types.submodule (
          { name, config, ... }:
          {
            options = launcherOptions config;
            config = launcherDefaults name config;
          }
        )
      );
      default = { };
      example = lib.literalExpression ''{ work.binds."''${config.home.homeDirectory}/Workspace/work".rw = true; }'';
      description = ''
        More sandboxes next to the default one, which is always there. Each has the same options, starts from the
        module's defaults rather than the default launcher's settings, and keeps its state in
        `~/.local/share/claude-desktop-<name>`: its own home (`~/.claude` and `~/.config/Claude` included, unless bound),
        Nix store and scratchpads. It runs as `claude-desktop-<name>`, shows as "Claude (<name>)", and leaves the
        `claude://` handler to the default launcher.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = osConfig.hardware.graphics.enable;
        message = "agent-sandbox.claude-desktop: the sandbox uses the host's graphics drivers, but hardware.graphics.enable is off on this machine. Enable it there if this is a desktop; the module doesn't, so it never pulls a graphics stack onto a server.";
      }
    ]
    ++ lib.mapAttrsToList (name: s: {
      assertion =
        s.command or null != null
        && !lib.elem name [
          "filesystem"
          "claude-code"
        ];
      message = "agent-sandbox.claude-desktop: programs.mcp.servers.${name} must be a local server (command) and not named filesystem or claude-code, which are the sandbox's own";
    }) hmMcpServers
    ++ lib.concatLists (
      lib.mapAttrsToList (
        name: l:
        let
          opt = if name == "" then "sandbox" else "launchers.${name}.sandbox";
        in
        [
          {
            assertion =
              l.sandboxed.config.bubblewrap.network
              && l.sandboxed.config.pasta.enable
              && l.sandboxed.config.pasta.package == l.netSetup;
            message = "agent-sandbox.claude-desktop: the sandbox always gets its own netns with a macvlan; ${opt} must not change bubblewrap.network or pasta";
          }
        ]
        ++ lib.optional (if name == "" then cfg else cfg.launchers.${name}).memo.enable {
          assertion = options ? programs.agent-memos.package && memoCfg.enable;
          message = "agent-sandbox.claude-desktop: ${
            if name == "" then "memo.enable" else "launchers.${name}.memo.enable"
          } needs Home Manager's memo: import agent-memos' module and set programs.agent-memos.enable";
        }
        ++ lib.optional (name != "") {
          # File names, the app ID and the .desktop file's Name take it as is
          assertion = builtins.match "[a-z][a-z0-9-]*" name != null;
          message = "agent-sandbox.claude-desktop: launcher name ${name} must match [a-z][a-z0-9-]*";
        }
      ) launchers
    );
    home.packages = lib.mapAttrsToList (_: l: l.claude-desktop) launchers;
    agent-sandbox.claude-desktop = launcherDefaults null cfg;
  };
}
