{
  self,
  inputs,
  pkgs,
}:
let
  inherit (pkgs) lib;
  # Both modules and a user alice, who sets claude-desktop to `cfg`
  aliceModule = cfg: {
    imports = [
      inputs.home-manager.nixosModules.home-manager
      self.nixosModules.claude-desktop
      # Twice, as when another flake's module imports it too
      self.nixosModules.claude-desktop
    ];
    system.stateVersion = "26.05";
    hardware.graphics.enable = true;
    users.users.alice.isNormalUser = true;
    home-manager.sharedModules = [
      self.homeModules.claude-desktop
      self.homeModules.claude-desktop
    ];
    home-manager.users.alice = {
      home.stateVersion = "26.05";
      agent-sandbox.claude-desktop = cfg;
    };
  };
  nixos =
    cfg:
    inputs.nixpkgs.lib.nixosSystem {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules = [
        (aliceModule cfg)
        {
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "none";
            fsType = "tmpfs";
          };
        }
      ];
    };
  enabled = {
    enable = true;
    kvm = true;
    extraPath = [ "/srv/bin" ];
    binds = {
      "/srv/project".rw = true;
      "/srv/docs" = { };
      "/srv/hidden".mcp = false;
      # A module default, overridden by its sandbox path
      "/home/alice/.claude".src = "/srv/claude";
    };
    files = {
      "/etc/agent-sandbox-test/hello".text = lib.getExe pkgs.hello;
      "/etc/agent-sandbox-test".source = pkgs.writeTextDir "other" "";
      "/srv/off" = {
        enable = false;
        text = "off";
      };
    };
    launchers.work.binds."/srv/work".rw = true;
  };
  system = nixos enabled;
  alice = system.config.home-manager.users.alice;
  failedAssertions = sys: lib.filter (a: !a.assertion) sys.config.home-manager.users.alice.assertions;
  # alice's programs.mcp set to `mcp`
  withMcp =
    mcp:
    (system.extendModules { modules = [ { home-manager.users.alice.programs.mcp = mcp; } ]; })
    .config.home-manager.users.alice;
  aliceMcp = withMcp {
    enable = true;
    servers = {
      plain.command = "/srv/bin/plain";
      secret = {
        command = "/srv/bin/secret";
        env.TOKEN.file = "/run/secrets/token";
      };
      off = {
        command = "/srv/bin/off";
        enabled = false;
      };
    };
  };
  # alice in a group of her own, not in users
  ownGroup = system.extendModules {
    modules = [
      {
        users.users.alice.group = "alice";
        users.groups.alice = { };
      }
    ];
  };
  sandboxedOf =
    sys:
    lib.findFirst (
      p: p.name == "claude-desktop-sandboxed"
    ) null sys.config.home-manager.users.alice.home.packages;
  sandboxed = sandboxedOf system;
  # A stand-in for agent-memos' Home Manager module, with the options this module reads
  memoStub =
    { lib, ... }:
    {
      options.programs.agent-memos = {
        enable = lib.mkEnableOption "memo";
        package = lib.mkOption {
          type = lib.types.package;
          default = pkgs.hello;
        };
        embeds = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [
            "core"
            "docs"
          ];
        };
        settings = lib.mkOption {
          inherit ((pkgs.formats.yaml { })) type;
          default = { };
        };
      };
    };
  # alice with memo, given to the work launcher
  aliceMemo =
    (system.extendModules {
      modules = [
        {
          home-manager.users.alice = {
            imports = [ memoStub ];
            programs.agent-memos = {
              enable = true;
              settings.stores = [
                "embed:core"
                "embed:docs"
                "/srv/team.memo"
              ];
            };
            agent-sandbox.claude-desktop.launchers.work.memo.enable = true;
          };
        }
      ];
    }).config.home-manager.users.alice;
  work = lib.findFirst (p: p.name == "claude-desktop-work-sandboxed") null aliceMemo.home.packages;
  # Another environmentFile, the rest as in enabled
  customDoc = sandboxedOf (
    nixos (enabled // { environmentFile = pkgs.writeText "custom-environment.md" "custom"; })
  );

  # Run by nix-unit through the flake's tests output, see claude-desktop-eval
  evalTests = {
    testAssertionsHold = {
      expr = failedAssertions system;
      expected = [ ];
    };
    testMemoAssertionsHold = {
      expr = lib.filter (a: !a.assertion) aliceMemo.assertions;
      expected = [ ];
    };
    testMemoAssertion = {
      expr = map (a: a.message) (failedAssertions (nixos (enabled // { memo.enable = true; })));
      expected = [
        "agent-sandbox.claude-desktop: memo.enable needs Home Manager's memo: import agent-memos' module and set programs.agent-memos.enable"
      ];
    };
    # The work launcher gets memo's package, its config and the sandbox's store, and the part of environment.md every
    # session needs. The default launcher none of it
    testMemo = {
      expr =
        map
          (l: {
            files = lib.attrNames l.files;
            hello = lib.elem pkgs.hello l.path;
            environmentFile = baseNameOf l.environmentFile;
          })
          [
            aliceMemo.agent-sandbox.claude-desktop
            aliceMemo.agent-sandbox.claude-desktop.launchers.work
          ];
      expected = [
        {
          files = [
            "/etc/agent-sandbox-test"
            "/etc/agent-sandbox-test/hello"
            "/srv/off"
          ];
          hello = false;
          environmentFile = "environment.md";
        }
        {
          files = [
            "/etc/claude/environment.memo"
            "/home/alice/.config/agent-memos/config.yaml"
          ];
          hello = true;
          environmentFile = "core-environment.md";
        }
      ];
    };
    testWrapper = {
      expr = {
        inherit (system.config.security.wrappers.netns-macvlan)
          source
          capabilities
          owner
          group
          permissions
          ;
      };
      expected = {
        source = lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.netns-macvlan;
        capabilities = "cap_net_admin+ep";
        owner = "root";
        group = "users";
        permissions = "u+rx,g+x";
      };
    };
    testNoWrapperWhenDisabled = {
      expr = (nixos { }).config.security.wrappers ? netns-macvlan;
      expected = false;
    };
    testGraphicsAssertion = {
      expr = map (a: a.message) (
        failedAssertions (
          system.extendModules { modules = [ { hardware.graphics.enable = lib.mkForce false; } ]; }
        )
      );
      expected = [
        "agent-sandbox.claude-desktop: the sandbox uses the host's graphics drivers, but hardware.graphics.enable is off on this machine. Enable it there if this is a desktop; the module doesn't, so it never pulls a graphics stack onto a server."
      ];
    };
    testUsersGroupAssertion = {
      expr = map (a: a.message) (lib.filter (a: !a.assertion) ownGroup.config.assertions);
      expected = [
        "agent-sandbox.claude-desktop: alice enables the sandbox but isn't in group users, which netns-macvlan is limited to. Add users to users.users.alice.extraGroups."
      ];
    };
    testSubIdsAssertion = {
      expr = map (a: a.message) (
        lib.filter (a: !a.assertion)
          (system.extendModules {
            modules = [ { users.users.alice.autoSubUidGidRange = lib.mkForce false; } ];
          }).config.assertions
      );
      expected = [
        "agent-sandbox.claude-desktop: alice enables the sandbox but has no subordinate uid and gid range, which the sandbox maps into its user namespace. Set users.users.alice.autoSubUidGidRange, or subUidRanges and subGidRanges."
      ];
    };
    # The module mkForces them, so only a higher priority gets past it
    testNetnsAssertionNetwork = {
      expr = lib.length (
        failedAssertions (nixos (enabled // { sandbox.bubblewrap.network = lib.mkOverride 10 false; }))
      );
      expected = 1;
    };
    testNetnsAssertionPasta = {
      expr = lib.length (
        failedAssertions (nixos (enabled // { sandbox.pasta.package = lib.mkOverride 10 pkgs.passt; }))
      );
      expected = 1;
    };
    testExtraPath = {
      expr = lib.head (
        lib.splitString ":" alice.agent-sandbox.claude-desktop.mcpServers.claude-code.env.PATH
      );
      expected = "/srv/bin";
    };
    testLaunchers = {
      expr = map (p: p.name) (lib.filter (p: lib.hasPrefix "claude-desktop" p.name) alice.home.packages);
      expected = [
        "claude-desktop-sandboxed"
        "claude-desktop-work-sandboxed"
      ];
    };
    testLauncherName = {
      expr = map (a: a.message) (failedAssertions (nixos (enabled // { launchers.Work = { }; })));
      expected = [ "agent-sandbox.claude-desktop: launcher name Work must match [a-z][a-z0-9-]*" ];
    };
    testLauncherNetnsAssertion = {
      expr = map (a: a.message) (
        failedAssertions (
          nixos (enabled // { launchers.work.sandbox.pasta.package = lib.mkOverride 10 pkgs.passt; })
        )
      );
      expected = [
        "agent-sandbox.claude-desktop: the sandbox always gets its own netns with a macvlan; launchers.work.sandbox must not change bubblewrap.network or pasta"
      ];
    };
    # Each app gets a pid of its own, so their tray items don't clash on the session bus
    testLauncherTrays = {
      expr = failedAssertions (
        nixos (
          enabled
          // {
            tray = true;
            launchers.work.tray = true;
          }
        )
      );
      expected = [ ];
    };
    # Its own binds only: ~/.claude lives in its home
    testLauncherMcpRoots = {
      expr = alice.agent-sandbox.claude-desktop.launchers.work.mcpServers.filesystem.args;
      expected = [ "/srv/work" ];
    };
    testMcpRoots = {
      expr = lib.sort lib.lessThan alice.agent-sandbox.claude-desktop.mcpServers.filesystem.args;
      expected = [
        "/home/alice/.claude"
        "/srv/docs"
        "/srv/project"
      ];
    };
    # The sandbox's own, then programs.mcp.servers, in every launcher. Disabled ones left out
    testMcpServers = {
      expr = map (l: lib.attrNames l.mcpServers) [
        aliceMcp.agent-sandbox.claude-desktop
        aliceMcp.agent-sandbox.claude-desktop.launchers.work
      ];
      expected = lib.replicate 2 [
        "claude-code"
        "filesystem"
        "plain"
        "secret"
      ];
    };
    testMcpServersHmTransform = {
      expr =
        let
          s = aliceMcp.agent-sandbox.claude-desktop.mcpServers;
        in
        {
          inherit (s) plain;
          secretWrapped = s.secret.command != "/srv/bin/secret" && !(s.secret ? env);
        };
      expected = {
        plain.command = "/srv/bin/plain";
        secretWrapped = true;
      };
    };
    testMcpServersNeedMcpEnable = {
      expr =
        lib.attrNames
          (withMcp { servers.plain.command = "/srv/bin/plain"; }).agent-sandbox.claude-desktop.mcpServers;
      expected = [
        "claude-code"
        "filesystem"
      ];
    };
    testMcpServersAssertion = {
      expr = map (a: a.message) (
        lib.filter (a: !a.assertion)
          (withMcp {
            enable = true;
            servers = {
              remote.url = "https://example.com/mcp";
              filesystem.command = "/srv/bin/fs";
            };
          }).assertions
      );
      expected =
        map
          (
            n:
            "agent-sandbox.claude-desktop: programs.mcp.servers.${n} must be a local server (command) and not named filesystem or claude-code, which are the sandbox's own"
          )
          [
            "filesystem"
            "remote"
          ];
    };
  };
in
{
  tests = evalTests;

  checks = {
    inherit (self.packages.${pkgs.stdenv.hostPlatform.system}) netns-macvlan subid-broker;

    # nix-unit evaluates this flake again inside the build, which can't fetch, so every input (theirs too) comes from
    # the store
    claude-desktop-eval =
      let
        overrides =
          prefix: inputs':
          lib.concatLists (
            lib.mapAttrsToList (
              name: input:
              [
                "--override-input"
                "${prefix}${name}"
                "${input}"
              ]
              ++ overrides "${prefix}${name}/" (input.inputs or { })
            ) inputs'
          );
      in
      pkgs.runCommand "claude-desktop-eval" { nativeBuildInputs = [ pkgs.nix-unit ]; } ''
        export HOME=$PWD
        unset NIX_STORE
        export NIX_STORE_DIR=${builtins.storeDir} NIX_REMOTE=$HOME/storedata
        nix-unit --extra-experimental-features flakes ${
          lib.escapeShellArgs (overrides "" (removeAttrs inputs [ "self" ]))
        } --flake ${self}#tests.${pkgs.stdenv.hostPlatform.system}
        touch $out
      '';

    # Builds the sandboxed app (the patched asar and the scripts check themselves while building)
    # and checks what the sandbox gets from the config
    claude-desktop =
      pkgs.runCommand "claude-desktop-check"
        {
          nativeBuildInputs = [ pkgs.jq ];
          closure = pkgs.closureInfo { rootPaths = [ sandboxed ]; };
          workClosure = pkgs.closureInfo { rootPaths = [ work ]; };
          inherit work;
          customClosure = pkgs.closureInfo { rootPaths = [ customDoc ]; };
        }
        ''
          paths=$closure/store-paths
          doc=$(grep -- '-claude-environment\.md$' "$paths")
          # The static part is linked, so the sandbox needs it in its store. All of it without memo, markers dropped
          import=$(grep -oxP '@\K/nix/store/[^/]+-claude-desktop-environment/environment\.md' "$doc") || { echo "environment.md lacks the import" >&2; exit 1; }
          grep -qxF -- "''${import%/*}" "$paths" || { echo "$import is not in the closure" >&2; exit 1; }
          grep -qxF '# Your environment: the Claude Desktop sandbox' "$import" || { echo "$import is not the module's environment.md" >&2; exit 1; }
          grep -qxF '## Nix' "$import" || { echo "$import lacks the sections memo would load" >&2; exit 1; }
          ! grep -qF '<!-- memo' "$import" || { echo "$import keeps the memo markers" >&2; exit 1; }
          custom=$(grep -- '-claude-environment\.md$' "$customClosure/store-paths")
          grep -qxP '@/nix/store/[^/]+-custom-environment\.md' "$custom" || { echo "environmentFile is not imported" >&2; exit 1; }
          for line in \
            '- `/srv/project` (rw, MCP)' \
            '- `/srv/docs` (ro, MCP)' \
            '- `/home/alice/.claude` (rw, MCP, from `/srv/claude`)' \
            '- `/nix` (rw, from `/home/alice/.local/share/claude-desktop/nix`)' \
            '- `/tmp/claude-<uid>` (rw, from `/home/alice/.local/share/claude-desktop/tmp-scratchpad`): Claude Code'"'"'s temp dir with the session scratchpads' \
            '- `/dev/kvm` (dev)' \
            '`/srv/bin`, then the packages'; do
            grep -qxF -- "$line" "$doc" || { echo "environment.md lacks: $line" >&2; exit 1; }
          done
          ! grep -F /srv/hidden "$doc" || { echo "environment.md lists the non-MCP ro bind" >&2; exit 1; }
          grep -qE '^coreutils, .*, nix\.$' "$doc" || { echo "environment.md lacks the PATH packages" >&2; exit 1; }

          # The tray icon by the colour scheme, also on GNOME (an asar stores its files as they are)
          asar=$(grep -- '-claude-desktop-app\.asar$' "$paths")
          ! grep -qaE '\(\)==="gnome"\|\|[A-Za-z0-9_$.]+\.nativeTheme\.shouldUseDarkColors\?"TrayIconLinux-Dark\.png"' "$asar" ||
            { echo "the asar picks the white tray icon on GNOME" >&2; exit 1; }
          grep -qaF 'nativeTheme.shouldUseDarkColors?"TrayIconLinux-Dark.png":"TrayIconLinux.png"' "$asar" ||
            { echo "the asar lost the tray icon's colour scheme check" >&2; exit 1; }

          args=$(grep -- '-bwrap-args\.json$' "$paths")
          # The args as consecutive elements of bwrap's argv
          has() { jq -e '. as $a | $ARGS.positional as $p | any(range(length); $a[.:. + ($p | length)] == $p)' --args -- "$@" <"$args" >/dev/null; }
          need() { has "$@" || { echo "bwrap args lack: $*" >&2; exit 1; }; }
          need --unshare-net
          # nixpak adds it when pasta (the netns setup's slot) is off, and it wins over --unshare-net
          ! has --share-net || { echo "bwrap args share the host's network" >&2; exit 1; }
          need --bind-try /srv/project /srv/project
          need --ro-bind-try /srv/docs /srv/docs
          need --ro-bind-try /srv/hidden /srv/hidden
          need --bind-try /home/alice/.local/share/claude-desktop/nix /nix
          need --bind-try /srv/claude /home/alice/.claude
          need --dev-bind-try /dev/kvm /dev/kvm
          # After the /tmp tmpfs, the uid filled in by nixpak's launcher
          has --tmpfs /tmp || { echo "bwrap args lack the /tmp tmpfs" >&2; exit 1; }
          jq -e '. as $a | (index("--tmpfs") + 1) as $t | any(range($t; length); $a[.:. + 3] == ["--dev-bind-try",
            "/home/alice/.local/share/claude-desktop/tmp-scratchpad", {type: "concat", a: "/tmp/claude-", b: {type: "uid"}}])' \
            <"$args" >/dev/null || { echo "bwrap args lack the scratchpad bind after the /tmp tmpfs" >&2; exit 1; }

          # The files, in the FHS env's bwrap, the directory before the file in it. What they reference is in the closure
          fhs=$(grep -P -- '-claude-desktop-[^/]+-bwrap$' "$paths")
          dir=$(grep -nP -- '^\s*--ro-bind /nix/store/[^/ ]+-other /etc/agent-sandbox-test$' "$fhs") || { echo "the FHS env lacks the directory's bind" >&2; exit 1; }
          file=$(grep -nP -- '^\s*--ro-bind /nix/store/[^/ ]+-hello /etc/agent-sandbox-test/hello$' "$fhs") || { echo "the FHS env lacks the file's bind" >&2; exit 1; }
          (( ''${dir%%:*} < ''${file%%:*} )) || { echo "the file's bind comes before its directory's" >&2; exit 1; }
          hello=$(<"$(grep -oP -- '--ro-bind \K\S+' <<<"$file")")
          [[ $hello == ${lib.getExe pkgs.hello} ]] || { echo "the file holds $hello" >&2; exit 1; }
          grep -qxF -- "${pkgs.hello}" "$paths" || { echo "what the file references is not in the closure" >&2; exit 1; }
          ! grep -qF /srv/off "$fhs" || { echo "the FHS env binds the disabled file" >&2; exit 1; }

          # The work launcher: its own state dir, app ID and MAC, ~/.claude in its home, its own .desktop file
          [[ $(ls $work/bin) == claude-desktop-work ]] || { echo "work has more than its wrapper: $(ls $work/bin)" >&2; exit 1; }
          wrapper=$(readlink -f $work/bin/claude-desktop-work)
          for line in \
            "readonly APP_ID=com.nixpak.ClaudeDesktop.work" \
            "readonly DOT_CLAUDE=/home/alice/.local/share/claude-desktop-work/home/.claude" \
            "readonly CONFIG=/home/alice/.local/share/claude-desktop-work/home/.config/Claude/claude_desktop_config.json" \
            "readonly STORE_ROOTS_LINK=store-roots-work"; do
            grep -qxF -- "$line" "$wrapper" || { echo "work's wrapper lacks: $line" >&2; exit 1; }
          done
          # The name netns-macvlan salts the MAC with
          name() { grep -h '^readonly NAME=' "$(grep -- '-pasta$' "$1")/bin/pasta"; }
          [[ $(name "$paths") == "readonly NAME='''" && $(name "$workClosure/store-paths") == "readonly NAME=work" ]] ||
            { echo "pasta's NAME isn't empty for the default launcher and work for work" >&2; exit 1; }
          doc=$(grep -- '-claude-environment\.md$' "$workClosure/store-paths")
          for line in \
            '- `/srv/work` (rw, MCP)' \
            '- `/home/alice` (rw, from `/home/alice/.local/share/claude-desktop-work/home`)'; do
            grep -qxF -- "$line" "$doc" || { echo "work's environment.md lacks: $line" >&2; exit 1; }
          done
          ! grep -qF -e /srv/project -e /home/alice/.claude "$doc" || { echo "work's environment.md has the default launcher's binds" >&2; exit 1; }
          # work has memo: the part every session needs, the rest in the store, memo's config with the store after the
          # embedded ones
          import=$(grep -oxP '@\K/nix/store/[^/]+-claude-desktop-environment/core-environment\.md' "$doc") || { echo "work's environment.md lacks the core import" >&2; exit 1; }
          ! grep -qxF -e '## Nix' -e '## Home' "$import" || { echo "$import has the sections memo loads" >&2; exit 1; }
          grep -qF 'More loads through memo when the work touches it: Home (`topic=sandbox`)' "$import" || { echo "$import lacks the pointer to memo" >&2; exit 1; }
          fhs=$(grep -P -- '-claude-desktop-[^/]+-bwrap$' "$workClosure/store-paths")
          store=$(grep -oP -- '--ro-bind \K\S+(?= /etc/claude/environment\.memo$)' "$fhs") || { echo "work's FHS env lacks the store's bind" >&2; exit 1; }
          for line in '-- nix/pragmas --' 'filter=topic={nix,sandbox}' 'topic=sandbox # The sandbox you run in: its home, what survives a restart, its namespaces'; do
            grep -qxF -- "$line" "$store" || { echo "$store lacks: $line" >&2; exit 1; }
          done
          memo=$(grep -oP -- '--ro-bind \K\S+(?= /home/alice/\.config/agent-memos/config\.yaml$)' "$fhs") || { echo "work's FHS env lacks memo's config" >&2; exit 1; }
          stores=$(grep '^- ' "$memo" | tr '\n' ' ')
          [[ $stores == '- embed:core - embed:docs - /etc/claude/environment.memo - /srv/team.memo ' ]] ||
            { echo "memo's stores in the sandbox: $stores" >&2; exit 1; }
          d=$work/share/applications/claude-desktop-work.desktop
          for line in 'Name=Claude (work)' 'Exec=claude-desktop-work %U' 'Name=New shell'; do
            grep -qxF -- "$line" "$d" || { echo "$d lacks: $line" >&2; exit 1; }
          done
          ! grep -q -e '^MimeType=' -e '^Exec=claude-desktop ' "$d" || { echo "$d keeps the claude:// handler or the default Exec" >&2; exit 1; }
          touch $out
        '';

    vm = import ./vm.nix { inherit pkgs aliceModule; };

    scripts = pkgs.runCommand "scripts-check" { nativeBuildInputs = [ pkgs.shellcheck ]; } ''
      shellcheck ${../../scripts}/*.sh ${../home/claude-desktop}/*.sh
      touch $out
    '';
  };
}
