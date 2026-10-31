# The permissions broker's built-in type C plugin: folders from the host, read-only unless asked otherwise and the
# ceiling's source allows it. The broker checks the source against the ceiling and resolves it beneath its root
{
  jq,
  lib,
  writeShellApplication,
  writeTextDir,
}:
let
  resolve = writeShellApplication {
    name = "permissions-folders-resolve";
    runtimeInputs = [ jq ];
    text = "jq -c '{source: .params.path, ro: (.params.ro != false)}'";
  };
  list = writeShellApplication {
    name = "permissions-folders-list";
    runtimeInputs = [ jq ];
    text = "jq -c '[.ceiling.sources[]? | {path, rw: (.rw // false)}]'";
  };
in
writeTextDir "share/agent-sandbox/permissions/folders.json" (
  builtins.toJSON {
    name = "folders";
    capabilities = [
      {
        name = "folder";
        type = "C";
        description = "a folder from the host";
        params = {
          path = {
            type = "string";
            description = "the folder on the host: one list shows, or a folder beneath it";
          };
          ro = {
            type = "boolean";
            description = "read-only, unless false; only what list marks rw may be read-write";
          };
        };
        list = [ (lib.getExe list) ];
        resolve = [ (lib.getExe resolve) ];
      }
    ];
  }
)
