# What the agent in the sandbox knows about it: its environment doc at the app's environmentPath
# (/etc/claude/environment.md for Claude Desktop), and with memo.enable Home Manager's memo with the sandbox's own store
{
  lib,
  pkgs,
  config,
  hm,
  hmOptions,
  sl,
  launcherName,
  ...
}:
let
  inherit (lib) mkOption types;
  ids = sl.idsOf launcherName;
  # Home Manager's memo, when imported
  memoCfg = hm.programs.agent-memos or { };
  # The environment doc, for the agent's user instructions to import (the user's CLAUDE.md): an import of
  # environmentFile (linked, so it's in the closure), the binds (minus the ro system ones), the features that are on and
  # PATH as configured, then environmentText. claude-env reads `environment:` from the frontmatter. Claude Code, for
  # one, follows imports four hops deep, and ~/.claude reaches this file in three (CLAUDE.md, the account's, the shared
  # one), so environmentFile is the last that loads
  environmentDoc = pkgs.writeText "sandbox-environment.md" ''
    ---
    environment: bwrap
    ---

    @${config.environmentFile}

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
              lib.filterAttrs (_: b: b.enable && (b.rw || b.mcp)) config.permissions.binds
            )
          )
        )
    }- `/tmp/claude-<uid>` (rw, from `${ids.scratchpad}`): Claude Code's temp dir with the session scratchpads
    ${lib.concatMapStrings (d: "- `${d}` (dev, if present)\n") config.build.devices}
    ${
      lib.optionalString (config.build.features != [ ]) ''
        ## Features

        Turned on in the configuration of the launcher. What each adds is among the binds above and the rest of this file.

        ${lib.concatMapStrings (
          f: "- `${f.name}`: ${f.description}${lib.optionalString (f.note != "") ". ${f.note}"}\n"
        ) config.build.features}
      ''
    }## PATH

    ${lib.concatMapStrings (d: "`${d}`, then ") config.extraPath}the packages
    ${lib.concatMapStringsSep ", " lib.getName (sl.sandboxPackagesOf config)}.
    ${config.environmentText}
  '';
in
{
  options = {
    environmentFile = mkOption {
      type = types.path;
      default = "${sl.environment}/${lib.optionalString config.memo.enable "core-"}environment.md";
      defaultText = lib.literalMD "`environment.md`, with `memo.enable` only the sections every session needs";
      description = "What the agent in the sandbox knows about it, imported by the sandbox's environment doc (`${sl.app.environmentPath}`). Replace it to describe a consumer's own setup.";
    };
    memo.enable = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Give the sandbox Home Manager's memo (`programs.agent-memos`): its package on PATH and its config. The
        sandbox's own store goes in that config right after the embedded stores, on the host too, so `memo` there
        answers as it does inside. That store holds the sections of `environment.md` that load by topic, and
        `environmentFile` keeps the rest.
      '';
    };
    environmentText = mkOption {
      type = types.lines;
      default = "";
      description = "Appended to the sandbox's environment doc (`${sl.app.environmentPath}`), which the agent loads every session: per-user notes, `@` imports and read-when triggers.";
    };
  };

  config = {
    build.fhsBwrapArgs = [ "--ro-bind ${environmentDoc} ${sl.app.environmentPath}" ];
    path = lib.mkIf config.memo.enable (lib.mkOptionDefault [ memoCfg.package ]);
    files = lib.mkIf config.memo.enable {
      "${hm.home.homeDirectory}/.config/agent-memos/config.yaml".source = memoCfg.configFile;
    };
    build.assertions = lib.optional config.memo.enable {
      assertion = hmOptions ? programs.agent-memos.package && memoCfg.enable;
      message = "${ids.opt}memo.enable needs Home Manager's memo: import agent-memos' module and set programs.agent-memos.enable";
    };
  };
}
