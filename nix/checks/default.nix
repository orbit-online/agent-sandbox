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
    ];
    system.stateVersion = "26.05";
    hardware.graphics.enable = true;
    users.users.alice.isNormalUser = true;
    home-manager.sharedModules = [ self.homeModules.claude-desktop ];
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
    binds = {
      "/srv/project".rw = true;
      "/srv/docs" = { };
      "/srv/hidden".mcp = false;
    };
  };
  system = nixos enabled;
  alice = system.config.home-manager.users.alice;
  failedAssertions = sys: lib.filter (a: !a.assertion) sys.config.home-manager.users.alice.assertions;
  sandboxed = lib.findFirst (p: p.name == "claude-desktop-sandboxed") null alice.home.packages;

  evalFailures = lib.runTests {
    testAssertionsHold = {
      expr = failedAssertions system;
      expected = [ ];
    };
    testWrapper = {
      expr = {
        inherit (system.config.security.wrappers.netns-macvlan) source capabilities;
      };
      expected = {
        source = lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.netns-macvlan;
        capabilities = "cap_net_admin+ep";
      };
    };
    testNoWrapperWhenDisabled = {
      expr = (nixos { }).config.security.wrappers ? netns-macvlan;
      expected = false;
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
  inherit (self.packages.${pkgs.stdenv.hostPlatform.system}) netns-macvlan;

  claude-desktop-eval =
    if evalFailures == [ ] then
      pkgs.emptyFile
    else
      throw "claude-desktop eval tests failed: ${lib.generators.toPretty { } evalFailures}";

  # Builds the sandboxed app (the patched asar and the scripts check themselves while building)
  # and checks what the sandbox gets from the config
  claude-desktop =
    pkgs.runCommand "claude-desktop-check"
      {
        nativeBuildInputs = [ pkgs.jq ];
        closure = pkgs.closureInfo { rootPaths = [ sandboxed ]; };
      }
      ''
        paths=$closure/store-paths
        doc=$(grep -- '-claude-environment\.md$' "$paths")
        # The static part is linked, so the sandbox needs it in its store
        import=$(grep -oxP '@\K/nix/store/[^/]+-environment\.md' "$doc") || { echo "environment.md lacks the import" >&2; exit 1; }
        grep -qxF -- "$import" "$paths" || { echo "$import is not in the closure" >&2; exit 1; }
        for line in \
          '- `/srv/project` (rw, MCP)' \
          '- `/srv/docs` (ro, MCP)' \
          '- `/home/alice/.claude` (rw, MCP)' \
          '- `/dev/kvm` (dev)'; do
          grep -qxF -- "$line" "$doc" || { echo "environment.md lacks: $line" >&2; exit 1; }
        done
        ! grep -F /srv/hidden "$doc" || { echo "environment.md lists the non-MCP ro bind" >&2; exit 1; }
        grep -qE '^coreutils, .*, nix$' "$doc" || { echo "environment.md lacks the PATH packages" >&2; exit 1; }

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
        need --dev-bind-try /dev/kvm /dev/kvm
        touch $out
      '';

  vm = import ./vm.nix { inherit pkgs aliceModule; };

  scripts = pkgs.runCommand "scripts-check" { nativeBuildInputs = [ pkgs.shellcheck ]; } ''
    shellcheck ${../../scripts}/*.sh ${../home/claude-desktop}/*.sh
    touch $out
  '';
}
