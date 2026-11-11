# The launcher's general options: the app, nixpak's extra config, binds, files, environment variables, devices and
# PATH. The features' own options are in their modules
{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  inherit (lib) mkOption types;
in
{
  options = {
    package =
      lib.mkPackageOption inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system} "claude-desktop"
        { pkgsText = "inputs.llm-agents.packages.\${system}"; };
    sandbox = mkOption {
      type = types.deferredModule;
      default = { };
      description = "Extra nixpak configuration.";
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
      description = "Host paths mounted in the sandbox, keyed by the path in the sandbox. A source that holds or lies in a launcher's state dir (outside its own `home/`, `nix/` and `tmp-scratchpad/`), or holds `$XDG_RUNTIME_DIR` or lies in its `.flatpak` or `claude-desktop` dir, fails an assertion.";
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
        libnotify
      ];
      description = "Packages on PATH for the app, its Code tab shells and the local MCP servers.";
    };
  };
}
