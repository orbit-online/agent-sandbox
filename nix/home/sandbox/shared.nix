# What every app's module shares, imported once however many apps a configuration has (its key): the modules that join
# every launcher of every app, and the sandboxes of all apps, which the NixOS module reads (journald namespaces, who
# enables a sandbox) and the apps' modules read for what must differ between any two sandboxes of the user (state dirs,
# the app's pid in its pid ns)
{ lib, config, ... }:
let
  inherit (lib) mkOption types;
  names = map (s: s.sandbox) config.agent-sandbox.sandboxes;
in
{
  key = "agent-sandbox/nix/home/sandbox/shared.nix";
  options.agent-sandbox = {
    launcherModules = mkOption {
      type = types.listOf types.deferredModule;
      default = [ ];
      description = ''
        Modules added to every launcher of every app, the default one and each of `launchers` (as
        `agent-sandbox.claude-desktop.launchers`), for options of their own next to the launcher's:
        `permissions.commands` from a plugin's settings, for one. Their arguments: the launcher's `config`,
        `launcherName` (null for the default launcher), Home Manager's config as `hm`, `pkgs`, `osConfig`, and the
        shared helpers of `lib.nix` as `sl`, `sl.app` the app's descriptor. A feature with options beside the ones every
        feature has is declared with `sl.feature`, under `options.features.<name>` as
        `types.submodule [ sl.feature { options = ...; } ]`, the way `request-send.nix` declares `request-send`.
      '';
    };
    sandboxes = mkOption {
      type = types.listOf (
        types.submodule {
          options = {
            sandbox = mkOption {
              type = types.str;
              description = "Its name, `<app>[-<launcher>]`: the base of its units, slice, journald namespaces and state dir, and what the privileged helpers know it by.";
            };
            app = mkOption { type = types.str; };
            index = mkOption {
              type = types.int;
              description = "Its place among its app's launchers, the default one 0.";
            };
            stateDir = mkOption { type = types.str; };
            journal = mkOption { type = types.str; };
            sandboxJournal = mkOption { type = types.str; };
            enable = mkOption {
              type = types.bool;
              description = "Whether its app is enabled.";
            };
          };
        }
      );
      internal = true;
      default = [ ];
      description = "Every sandbox of every app, enabled or not, by app and then launcher, each app's default launcher first.";
      apply = lib.sortOn (s: [
        s.app
        s.index
      ]);
    };
  };
  config.assertions = [
    {
      assertion = lib.length (lib.unique names) == lib.length names;
      message = "agent-sandbox: two sandboxes share a name, which their units, state dirs and the helpers' names would share too: ${
        lib.concatStringsSep ", " (lib.filter (n: lib.count (m: m == n) names > 1) (lib.unique names))
      }. A launcher's name joins its app's with a -, so rename the launcher";
    }
  ];
}
