# What Claude in the sandbox knows about it: /etc/claude/environment.md, and with memo.enable Home Manager's memo with
# the sandbox's own store
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
  # /etc/claude/environment.md, for the user's CLAUDE.md to import: an import of environmentFile (linked, so it's in
  # the closure), the binds (minus the ro system ones) and PATH as configured, then environmentText. claude-env reads
  # `environment:` from the frontmatter. Claude Code follows imports four hops deep, and ~/.claude reaches this file
  # in three (CLAUDE.md, the account's, the shared one), so environmentFile is the last that loads
  environmentDoc = pkgs.writeText "claude-environment.md" ''
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
              lib.filterAttrs (_: b: b.enable && (b.rw || b.mcp)) config.binds
            )
          )
        )
    }- `/tmp/claude-<uid>` (rw, from `${ids.scratchpad}`): Claude Code's temp dir with the session scratchpads
    ${lib.concatMapStrings (d: "- `${d}` (dev, if present)\n") config.build.devices}
    ## PATH

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
      description = "What Claude in the sandbox knows about it, imported by `/etc/claude/environment.md`. Replace it to describe a consumer's own setup.";
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
      description = "Appended to the sandbox's `/etc/claude/environment.md`, which Claude loads every session: per-user notes, `@` imports and read-when triggers.";
    };
  };

  config = {
    build.fhsBwrapArgs = [ "--ro-bind ${environmentDoc} /etc/claude/environment.md" ];
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
