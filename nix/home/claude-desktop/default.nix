# Namespaces of the sandbox. Host uid 1000 is the only uid mapped all the way down (as 0 in U1),
# so everything written to host paths is owned by it.
#
# init userns (host)
# │  runs: nixpak launcher, xdg-dbus-proxy, the pasta-slot script (netSetup), bwrap's parent,
# │        netns-macvlan (cap_net_admin, creates eth0 in N)
# │
# └─ U1  bwrap's first userns (uid 1000 mapped as 0, needed to mount devpts for --dev)
#    │  owns: N (netns: lo + eth0 macvlan), M1 (sandbox mount tree), P (pid ns), ipc, uts, cgroup
#    │  runs: udhcpc + dhcpScript (in N, M1, P; net_admin and net_raw only), netSetup's ip calls (in N)
#    │
#    └─ U2  bwrap's second userns (uid 1000), created after the mount setup; owns nothing
#       │  runs (in N, M1, P): bwrap's init, the FHS env script, claude:// re-entry
#       │
#       └─ U3  buildFHSEnv's bwrap
#             owns: M2 (tmpfs /etc, DHCP resolv.conf, patched app.asar)
#             runs (in N, M2, P): Claude Desktop, Code tab shells, the local MCP servers
{ inputs }:
{
  pkgs,
  lib,
  config,
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
  # No browser in the sandbox; hand links (incl. OAuth sign-in) to the host via the OpenURI portal.
  # The D-Bus proxy blocks Introspect, so gdbus can't look up the signature: type the options explicitly
  xdgOpen = pkgs.writeShellScriptBin "xdg-open" ''
    exec ${lib.getExe' pkgs.glib "gdbus"} call --session \
      --dest org.freedesktop.portal.Desktop --object-path /org/freedesktop/portal/desktop \
      --method org.freedesktop.portal.OpenURI.OpenURI "" "$1" "@a{sv} {}"
  '';

  # Holds the sandbox's home directory and its Nix store (home/, nix/)
  stateDir = "${config.xdg.dataHome}/claude-desktop";
  bwrapHome = "${stateDir}/home";
  # PATH for the app (so the Code tab's shells) and the claude-code MCP server. ~/.claude/bin first: its gh wraps the real one
  searchPath = "${config.home.homeDirectory}/.claude/bin:${lib.makeBinPath sandboxPackages}:/run/wrappers/bin:/run/current-system/sw/bin";
  # The same nix as the host, so the sandbox's store database is never migrated to a schema one side can't read
  # .out: the man output is a symlink, see storeRoots
  sandboxPackages = cfg.path ++ [ osConfig.nix.package.out ];

  # The sandbox's own single-user Nix store, stateDir/nix bound rw at /nix. The host store isn't visible: nixpak binds
  # only storeRoots' closure (ro, over the store's copies of the same paths) and there is no daemon socket.
  # Paths have to be valid in the store before the binds land on them, or bwrap mkdirs unregistered
  # mountpoints in it, so the wrapper copies the closure in and roots it before every launch
  nixConf = pkgs.writeTextDir "nix.conf" ''
    experimental-features = nix-command flakes
    substituters = https://cache.nixos.org/
    trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
  '';
  # /run/current-system links into the system closure: the PATH tools, bash (SHELL) and glibc's fallback
  # locale archive come from this instead
  currentSystemSw = pkgs.buildEnv {
    name = "claude-desktop-sw";
    paths = sandboxPackages ++ [
      pkgs.bashInteractive
      osConfig.i18n.glibcLocales
    ];
  };
  # The entries claude-desktop's FHS env takes from the host /etc, minus shadow, sudoers, nix (NIX_CONF_DIR) and the
  # shell rc files (the sandbox's shell is bash with the FHS env's /etc/profile, not the host's login shell)
  etcEntries = [
    "passwd"
    "group"
    "nsswitch.conf"
    "localtime"
    "zoneinfo"
    "machine-id"
    "os-release"
    "fonts"
    "ssl/certs"
    "pki"
  ]
  ++ lib.optional cfg.audio "alsa";
  # They link through /etc/static into the system closure, so their targets go in storeRoots (localtime links to zoneinfo)
  etcSources = lib.filter (lib.hasPrefix builtins.storeDir) (
    lib.mapAttrsToList (_: e: toString e.source) (
      lib.filterAttrs (
        _: e: e.enable && lib.any (d: e.target == d || lib.hasPrefix "${d}/" e.target) etcEntries
      ) osConfig.environment.etc
    )
  );
  # The host's /run/opengl-driver, as NixOS builds it
  graphicsDrivers = pkgs.buildEnv {
    name = "graphics-drivers";
    paths = [ osConfig.hardware.graphics.package ] ++ osConfig.hardware.graphics.extraPackages;
  };
  # Everything the sandbox runs from the store. nixpak's closure only covers the app and extraStorePaths, not
  # env values or bind sources, so they all go in here. nixpak --ro-binds every closure path, and bwrap won't
  # mount onto the symlink a symlink store path already is in the store, so those fail the build here
  storeRoots =
    let
      roots = [
        package
        netSetup
        xdgOpen
        nixConf
        currentSystemSw
        graphicsDrivers
        mcpServers
        bashEnv
      ]
      ++ etcSources;
    in
    pkgs.runCommand "claude-desktop-store-roots" { closure = pkgs.closureInfo { rootPaths = roots; }; }
      ''
        while read -r p; do
          [[ ! -L $p ]] || { echo "$p is a symlink, nixpak can't bind it over the sandbox store's copy" >&2; exit 1; }
        done <"$closure/store-paths"
        printf '%s\n' ${lib.escapeShellArgs roots} >$out
      '';
  storeSync = pkgs.writeShellApplication {
    name = "claude-desktop-store-sync";
    runtimeInputs = [ osConfig.nix.package ];
    text = ''
      root=${escapeShellArg stateDir}/nix/var/nix/gcroots/claude-desktop
      [[ $(readlink "$root" 2>/dev/null) == ${storeRoots} ]] && exit 0
      echo "claude-desktop: Copying the sandbox closure to ${stateDir}/nix" >&2
      # Unsigned local builds (the app, the patched asar) are fine: the source is the host's own store
      nix --extra-experimental-features nix-command copy --no-check-sigs \
        --to "local?root=${stateDir}" ${storeRoots}
      ln -sfn ${storeRoots} "$root"
      # The old closure is garbage now; ~/.claude/libexec/store-gc collects it from inside the sandbox
      mkdir -p ${escapeShellArg stateDir}/nix/var/claude-desktop
      touch ${escapeShellArg stateDir}/nix/var/claude-desktop/gc-pending
    '';
  };
  # Shallowest first, so nested binds override their parents. nixpak mounts all rw binds before the ro ones
  binds =
    rw:
    map
      (
        b:
        if b.src == b.bind then
          b.src
        else
          [
            b.src
            b.bind
          ]
      )
      (
        lib.sortOn (b: lib.stringLength b.bind) (
          lib.mapAttrsToList (src: b: b // { inherit src; }) (
            lib.filterAttrs (_: b: b.enable && b.rw == rw) cfg.binds
          )
        )
      );

  # The app only persists its sign-in when safeStorage.isEncryptionAvailable(), which is false under
  # --password-store=basic. Opting into Chromium's fixed v10 key makes it true
  asar = "${cfg.package.unwrapped}/lib/claude-desktop/resources/app.asar";
  patchedAsar =
    pkgs.runCommand "claude-desktop-app.asar"
      {
        nativeBuildInputs = [
          pkgs.asar
          pkgs.jq
        ];
      }
      ''
        asar extract ${asar} app
        main=app/$(jq -er .main app/package.json)
        sed -i '1s/^"use strict";/&require("electron").safeStorage.setUsePlainTextEncryption(true);/' "$main"
        grep -q setUsePlainTextEncryption "$main"
        asar pack app app.asar --unpack '{*.node,github-mcp-server}'
        # Bound at the original path, the patched asar reads the original app.asar.unpacked, so the lists must match
        diff <(cd ${asar}.unpacked && find . -type f | sort) <(cd app.asar.unpacked && find . -type f | sort)
        cp app.asar $out
      '';

  # The sandbox gets its own netns with a macvlan on the LAN (netns-macvlan --help), so host
  # services, routes and abstract sockets stay out of reach. Its DHCP lease brings the DNS servers
  resolvConf = "${bwrapHome}/.config/resolv.conf";
  # The same file as the sandbox sees it, where bwrapHome is the home directory
  sandboxResolvConf = "${config.home.homeDirectory}/.config/resolv.conf";
  dhcpScript = pkgs.writeShellScript "claude-desktop-udhcpc" ''
    # $1: the udhcpc event; $interface, $ip, $mask, $router, $dns and $domain come from udhcpc
    PATH=${lib.makeBinPath [ pkgs.iproute2 ]}
    case $1 in
      deconfig) ip -4 addr flush dev "$interface" ;;
      bound | renew)
        [[ $1 == bound ]] && ip -4 addr flush dev "$interface"
        ip addr replace "$ip/$mask" dev "$interface"
        [[ -z ''${router:-} ]] || ip route replace default via "''${router%% *}" dev "$interface"
        # Written in place: the file is bind-mounted, a rename would leave the sandbox on the old inode
        {
          [[ -z ''${domain:-} ]] || echo "search $domain"
          for d in ''${dns:-}; do echo "nameserver $d"; done
        } >${escapeShellArg sandboxResolvConf}
        ;;
    esac
  '';
  # Runs in nixpak's pasta slot: the launcher calls it with `-- <pid>` once the sandbox exists and before the app starts
  netSetup = pkgs.writeShellApplication {
    name = "pasta";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.util-linux
      pkgs.iproute2
    ];
    text = ''
      pid=''${!#}
      # bwrap's parent reports the pid while the child is still building the mount tree; nixpak binds
      # /.flatpak-info last, so once it shows up the sandbox's root is final
      for _ in {1..50}; do
        [[ -e /proc/$pid/root/.flatpak-info ]] && break
        sleep 0.1
      done
      [[ -e /proc/$pid/root/.flatpak-info ]] || {
        echo "claude-desktop: Sandbox root not ready after 5s" >&2
        exit 1
      }
      ${escapeShellArg osConfig.security.wrapperDir}/netns-macvlan "$pid"
      # By now the sandbox runs in a second userns (bwrap needs uid 0 in the first to mount devpts for --dev);
      # the first owns the netns. nsenter 2.42 can't combine --user-parent with other namespaces, so two steps.
      # --keep-caps: exec would otherwise drop the caps setns granted
      ns() {
        nsenter -t "$pid" --user-parent --preserve-credentials --keep-caps \
          nsenter -t "$pid" -n --preserve-credentials --keep-caps "$@"
      }
      ns ip link set lo up
      ns ip link set eth0 up
      # In the sandbox's pid ns so it dies with it, and its mount ns: it parses packets from the LAN, so it gets
      # no more of the host than the app does. -r: the sandbox process's root, as for the claude:// re-entry.
      # Forks to the background once it has a lease or gives up (~10s)
      ns -m -r -p ${lib.getExe' pkgs.util-linux "setpriv"} --inh-caps=-all,+net_admin,+net_raw --ambient-caps=-all,+net_admin,+net_raw \
        --bounding-set=-all,+net_admin,+net_raw \
        ${lib.getExe' pkgs.busybox "udhcpc"} -i eth0 -s ${dhcpScript} -b -t 5 -T 2
    '';
  };

  # nixpak binds /nix/store after all bind.ro entries, so the overlay and environment.md go into the FHS env's own bwrap.
  # The inner bwrap mounts last, so its resolv.conf beats the host one that nixpak binds. Its /etc/resolv.conf
  # is a symlink to /.host-etc/resolv.conf (the outer /etc), and bwrap won't mount onto symlinks
  package = cfg.package.override (prev: {
    buildFHSEnv =
      args:
      prev.buildFHSEnv (
        args
        // {
          extraBwrapArgs = args.extraBwrapArgs or [ ] ++ [
            "--ro-bind ${patchedAsar} ${asar}"
            "--ro-bind ${sandboxResolvConf} /.host-etc/resolv.conf"
            "--ro-bind ${environmentDoc} /etc/claude/environment.md"
          ];
          # The FHS /etc/profile prepends /run/wrappers/bin:/usr/bin:/usr/sbin to PATH and is sourced twice on the
          # way to the Code tab (buildFHSEnv's init, then the app's shell-path-worker running `$SHELL -l`). Move the
          # FHS dirs behind the module's PATH, once, so its tools win and FHS-only ones (tar, gzip, xz) stay reachable
          profile = args.profile or "" + ''
            fhs_prefix=/run/wrappers/bin:/usr/bin:/usr/sbin:
            while case $PATH in "$fhs_prefix"*) true ;; *) false ;; esac; do PATH=''${PATH#"$fhs_prefix"}; done
            for fhs_dir in /usr/bin /usr/sbin; do
              case :$PATH: in *:$fhs_dir:*) ;; *) PATH=$PATH:$fhs_dir ;; esac
            done
            unset fhs_prefix fhs_dir
          '';
        }
      );
  });

  sandboxed = inputs.nixpak.lib.nixpak { inherit lib pkgs; } {
    config = {
      imports = [ cfg.sandbox ];
      app.package = package;
      dbus.policies = {
        "org.freedesktop.Notifications" = "talk";
      }
      // lib.optionalAttrs cfg.tray {
        # Chromium names it StatusNotifierItem-<pid>-<n>; the main process is pid 10
        # in the sandbox's pid ns (after bwrap, the FHS init and its /etc/profile forks)
        "org.kde.StatusNotifierWatcher" = "talk";
        "org.freedesktop.StatusNotifierItem-10-1" = "own";
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
      # Hardcoded, see netSetup. transparent: bind the host's /etc/hosts and resolv.conf, no extra pasta args
      bubblewrap.network = lib.mkForce true;
      pasta = {
        enable = lib.mkForce true;
        package = lib.mkForce netSetup;
        mode = lib.mkForce "transparent";
        args = lib.mkForce [ ];
      };
      bubblewrap = {
        bindEntireStore = false;
        extraStorePaths = [ storeRoots ];
        bind.rw = binds true;
        bind.dev = lib.optional cfg.kvm "/dev/kvm";
        bind.ro = binds false ++ [
          [
            "${currentSystemSw}"
            "/run/current-system/sw"
          ]
        ];
        tmpfs = [ "/tmp" ];
        sockets = {
          wayland = true;
          pipewire = cfg.audio;
          pulse = cfg.audio;
        };
        newSession = true;
        dieWithParent = true;
      };
    };
  };

  mcpServers = pkgs.writeText "mcp-servers.json" (builtins.toJSON cfg.mcpServers);
  # The Bash tool sources CLAUDE_ENV_FILE before each command. The Code tab gets this from the SessionStart hook,
  # which claude mcp serve does not run. Drops the snapshot's ugrep/bfs shadows of grep and find
  bashEnv = pkgs.writeText "claude-bash-env" "unset -f grep find 2>/dev/null\n";
  # /etc/claude/environment.md, imported by ~/.claude's CLAUDE.md: environment.md, the binds (minus the ro system
  # ones) and PATH as configured, then environmentText. claude-env reads `environment:` from the frontmatter
  environmentDoc = pkgs.writeText "claude-environment.md" ''
    ---
    environment: bwrap
    ---

    ${builtins.readFile ./environment.md}
    ## Binds

    ${
      lib.concatMapStrings
        (
          b:
          "- `${b.bind}` (${
            lib.concatStringsSep ", " ([ (if b.rw then "rw" else "ro") ] ++ lib.optional b.mcp "MCP")
          })\n"
        )
        (
          lib.sortOn (b: b.bind) (
            lib.attrValues (lib.filterAttrs (_: b: b.enable && (b.rw || b.mcp)) cfg.binds)
          )
        )
    }${lib.optionalString cfg.kvm "- `/dev/kvm` (dev)\n"}
    ## PATH packages

    ${lib.concatMapStringsSep ", " lib.getName sandboxPackages}
    ${cfg.environmentText}
  '';

  # nixpak's sloth.env panics on unset variables, so filter the environment before its launcher.
  # Unset passthrough variables expand to nothing
  vars = lib.concatStringsSep "\n  " (
    lib.mapAttrsToList (
      n: v: if v.value == null then "\${${n}+\"${n}=\$${n}\"}" else "\"${n}=${v.value}\""
    ) (lib.filterAttrs (_: v: v.enable) cfg.env)
  );

  wrapper = pkgs.writeShellApplication {
    name = "claude-desktop";
    runtimeInputs = [ pkgs.jq ];
    text = ''
      mkdir -p ${escapeShellArg bwrapHome}/.config
      # Bind source for the sandbox's /etc/resolv.conf, filled in by the DHCP client
      touch ${escapeShellArg resolvConf}
      # Without user-dirs.dirs, Chromium saves downloads to $HOME
      # shellcheck disable=SC2016
      echo 'XDG_DOWNLOAD_DIR="$HOME/Downloads"' >${escapeShellArg bwrapHome}/.config/user-dirs.dirs
      vars=(
        ${vars}
      )
      args=(--password-store=basic "$@")

      # Further launches (claude:// URLs) join the running sandbox, so Electron's single-instance lock finds
      # the first instance. The mount ns check stops a stale info file with a recycled pid from pointing at a host process.
      for d in "$XDG_RUNTIME_DIR"/.flatpak/nixpak-app-*; do
        grep -qxF name=${escapeShellArg sandboxed.config.flatpak.appId} "$d/info" 2>/dev/null || continue
        pid=$(grep -oP '"child-pid":\s*\K\d+' "$d/bwrapinfo.json" 2>/dev/null) || continue
        if [[ -e /proc/$pid/ns/mnt && ! /proc/$pid/ns/mnt -ef /proc/self/ns/mnt ]]; then
          # Not -a: that also joins the time ns, still the host's, which needs CAP_SYS_ADMIN in the init userns
          exec env -i "''${vars[@]}" DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/nixpak-bus" \
            nsenter -t "$pid" -U -m -p -n -i -u -C -r -w --preserve-credentials ${lib.getExe package} "''${args[@]}"
        fi
      done

      # The app writes to this file too, so merge instead of symlinking a read-only store path
      conf=${escapeShellArg config.home.homeDirectory}/.config/Claude/claude_desktop_config.json
      mkdir -p "$(dirname "$conf")"
      [[ -s $conf ]] || echo '{}' >"$conf"
      jq --slurpfile m ${mcpServers} --argjson tray ${lib.boolToString cfg.tray} \
        '.mcpServers = $m[0] | .preferences.menuBarEnabled = $tray' "$conf" >"$conf.tmp"
      mv "$conf.tmp" "$conf"

      ${lib.getExe storeSync}

      exec env -i "''${vars[@]}" ${lib.getExe sandboxed.config.script} "''${args[@]}"
    '';
  };
  claude-desktop = (
    pkgs.symlinkJoin {
      name = "claude-desktop-sandboxed";
      # First path wins on collisions: the wrapper shadows nixpak's bin/claude-desktop,
      # while the .desktop file (Exec=claude-desktop, claude:// handler) and icons carry over
      paths = [
        wrapper
        sandboxed.config.env
      ];
    }
  );
in
{
  options.agent-sandbox.claude-desktop = {
    enable = lib.mkEnableOption "Claude Desktop, sandboxed with nixpak";
    package =
      lib.mkPackageOption inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system} "claude-desktop"
        { pkgsText = "inputs.llm-agents.packages.\${system}"; };
    sandbox = mkOption {
      type = types.deferredModule;
      default = { };
      description = "Extra nixpak configuration.";
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
                description = "Mount the path. Missing host paths are skipped.";
              };
              bind = mkOption {
                type = types.str;
                default = name;
                defaultText = lib.literalExpression "<name>";
                description = "Path in the sandbox.";
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
      description = "Host paths mounted in the sandbox, keyed by host path.";
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
    tray = mkOption {
      type = types.bool;
      default = false;
      description = "Show a tray icon. Closing the window then hides the app instead of quitting it.";
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
        # ~/.claude/libexec's git credential helper picks the PAT with it
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
      type = types.attrsOf (
        types.submodule {
          freeformType = (pkgs.formats.json { }).type;
          options = {
            command = mkOption {
              type = types.str;
              description = "Executable to spawn.";
            };
            args = mkOption {
              type = types.listOf types.str;
              default = [ ];
              description = "Arguments to the command.";
            };
            env = mkOption {
              type = types.attrsOf types.str;
              default = { };
              description = "Environment variables for the server.";
            };
          };
        }
      );
      description = "Local MCP servers, replacing `mcpServers` in claude_desktop_config.json on launch.";
      default = {
        filesystem = {
          command = lib.getExe (
            pkgs.writeShellApplication {
              name = "mcp-server-filesystem";
              runtimeInputs = [ pkgs.jq ];
              # Claude Desktop rejects the draft-07 $schema the server declares (modelcontextprotocol/servers#4841)
              text = ''
                # Drop the client's roots so the CLI args stay the allowed dirs
                jq -c --unbuffered 'select(.method != "notifications/roots/list_changed")
                  | if .method == "initialize" then del(.params.capabilities.roots) end' |
                  ${lib.getExe pkgs.mcp-server-filesystem} "$@" |
                  jq -c --unbuffered 'walk(if type == "object" then del(."$schema") else . end)'
              '';
            }
          );
          args = lib.mapAttrsToList (_: b: b.bind) (lib.filterAttrs (_: b: b.enable && b.mcp) cfg.binds);
        };
        claude-code = {
          command = lib.getExe inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.claude-code;
          args = [
            "mcp"
            "serve"
          ];
          env = {
            PATH = searchPath;
            CLAUDE_ENV_FILE = "${bashEnv}";
            NIX_CONF_DIR = "${nixConf}";
          };
        };
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          sandboxed.config.bubblewrap.network
          && sandboxed.config.pasta.enable
          && sandboxed.config.pasta.package == netSetup;
        message = "agent-sandbox.claude-desktop: the sandbox always gets its own netns with a macvlan; sandbox must not change bubblewrap.network or pasta";
      }
    ];
    home.packages = [ claude-desktop ];
    agent-sandbox.claude-desktop.env =
      lib.genAttrs [
        "HOME"
        "USER"
        "LANG"
        "LC_ALL"
        "XDG_RUNTIME_DIR"
        "WAYLAND_DISPLAY"
        "XDG_CURRENT_DESKTOP"
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
        PATH = "${xdgOpen}/bin:${searchPath}";
        # Not the login shell from /etc/passwd
        SHELL = "/run/current-system/sw/bin/bash";
        NIXOS_OZONE_WL = "1";
        NIX_CONF_DIR = "${nixConf}";
      };
    agent-sandbox.claude-desktop.binds =
      let
        sys = {
          mcp = false;
        };
      in
      {
        "${stateDir}/nix" = sys // {
          bind = "/nix";
          rw = true;
        };
        "/sys" = sys;
        ${bwrapHome} = sys // {
          bind = config.home.homeDirectory;
          rw = true;
        };
        "${config.home.homeDirectory}/.claude".rw = true;
        "${config.home.homeDirectory}/.config/Claude" = sys // {
          rw = true;
        };
      }
      // lib.genAttrs (map (e: "/etc/${e}") ([ "static" ] ++ etcEntries)) (_: sys);
  };
}
