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
  };
  system = nixos enabled;
  alice = system.config.home-manager.users.alice;
  failedAssertions = sys: lib.filter (a: !a.assertion) sys.config.home-manager.users.alice.assertions;
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
    testMcpRoots = {
      expr = lib.sort lib.lessThan alice.agent-sandbox.claude-desktop.mcpServers.filesystem.args;
      expected = [
        "/home/alice/.claude"
        "/srv/docs"
        "/srv/project"
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
          customClosure = pkgs.closureInfo { rootPaths = [ customDoc ]; };
        }
        ''
          paths=$closure/store-paths
          doc=$(grep -- '-claude-environment\.md$' "$paths")
          # The static part is linked, so the sandbox needs it in its store
          import=$(grep -oxP '@\K/nix/store/[^/]+-environment\.md' "$doc") || { echo "environment.md lacks the import" >&2; exit 1; }
          grep -qxF -- "$import" "$paths" || { echo "$import is not in the closure" >&2; exit 1; }
          grep -qxF '# Your environment: the Claude Desktop sandbox' "$import" || { echo "$import is not the module's environment.md" >&2; exit 1; }
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
          touch $out
        '';

    vm = import ./vm.nix { inherit pkgs aliceModule; };

    scripts = pkgs.runCommand "scripts-check" { nativeBuildInputs = [ pkgs.shellcheck ]; } ''
      shellcheck ${../../scripts}/*.sh ${../home/claude-desktop}/*.sh
      touch $out
    '';
  };
}
