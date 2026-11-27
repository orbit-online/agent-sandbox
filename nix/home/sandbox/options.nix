# The launcher's general options: nixpak's extra config, files, environment variables, PATH and units of the sandbox's
# systemd --user, and of `permissions` the binds and devices. The features' own options are in their modules, the app's
# (its package among them) in the app's
{
  config,
  lib,
  pkgs,
  sl,
  ...
}:
let
  inherit (lib) mkOption types;
in
{
  options = {
    sandbox = mkOption {
      type = types.deferredModule;
      default = { };
      description = "Extra nixpak configuration.";
    };
    # What the sandbox reaches from its start, beside the session bus (dbus.nix) and the network (network.nix); what
    # it may ask for while it runs is permissions.nix's
    permissions = {
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
        description = "Host paths mounted in the sandbox, keyed by the path in the sandbox. A source is an absolute path in its clean form (no `.`, `..` or empty segments; one trailing slash is fine). One that holds or lies in a launcher's state dir (outside its own `home/`, `nix/` and `tmp-scratchpad/`), holds `$XDG_RUNTIME_DIR` or lies in its `.flatpak` or `agent-sandbox` dir, or is `/proc` or `/var/run` or lies in them fails an assertion. So does a source beneath the source of a read-write bind, the sandbox's home and scratchpad included: the sandbox could put a link in its place, which the next launch would follow. The assertions read the path as written: a source that is a link to one of these on the host gets past them.";
      };
      devices = mkOption {
        type = types.attrsOf (
          types.submodule {
            options.enable = mkOption {
              type = types.bool;
              default = true;
              description = "Mount the device node.";
            };
          }
        );
        default = { };
        example = lib.literalExpression ''
          {
            "/dev/nvidiactl" = { };
            "/dev/nvidia0" = { };
            "/dev/nvidia-modeset" = { };
          }
        '';
        description = ''
          Device nodes mounted in the sandbox, keyed by their path, each only if it exists on the host at launch. No
          globs. Exposes the driver's ioctl interface: a driver bug is a way out of the sandbox. Each is bound
          read-write from its own path, so the assertions on a bind's source hold for it too.
        '';
      };
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
    extraPath = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = lib.literalExpression ''[ "''${config.home.homeDirectory}/.claude/bin" ]'';
      description = "Directories on PATH ahead of `path`'s packages, for the app and what it runs (Claude Desktop: its Code tab shells and the claude-code MCP server).";
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
      description = "Packages on PATH for the app and what it runs (Claude Desktop: its Code tab shells and the local MCP servers).";
    };
    units = mkOption {
      type = types.attrsOf types.str;
      default = { };
      example = lib.literalExpression ''
        {
          "renew.service" = "[Service]\nType=oneshot\nExecStart=''${lib.getExe renew}";
          "renew.timer" = "[Timer]\nOnActiveSec=0\nOnUnitActiveSec=20min";
        }
      '';
      description = ''
        Units of the sandbox's systemd --user, by file name, each its text. A timer or path unit is wanted by
        timers.target or paths.target, so it runs while the sandbox does; a service starts from one of them. The
        names starting with `<app>-` (`claude-desktop-` for Claude Desktop) are the module's own.
      '';
    };
  };
  config.build = {
    userUnits = config.units;
    assertions = [
      {
        assertion = !lib.any (lib.hasPrefix "${sl.app.name}-") (lib.attrNames config.units);
        message = "agent-sandbox.${sl.app.name}: units starting with ${sl.app.name}- are the module's own: ${
          lib.concatStringsSep ", " (lib.filter (lib.hasPrefix "${sl.app.name}-") (lib.attrNames config.units))
        }";
      }
    ];
  };
}
