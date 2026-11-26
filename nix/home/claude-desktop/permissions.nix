# The permissions broker (docs/permissions.md): its switch and what it may grant while the sandbox runs, of the
# launcher's `permissions` options (those that apply from the start are options.nix's, dbus.nix's and network.nix's).
# permissions-broker.nix runs it, permissions-checks.nix checks its declarations at eval
{ lib, pkgs, ... }:
let
  inherit (lib) mkOption types;
in
{
  imports = [
    ./permissions-broker.nix
    ./permissions-checks.nix
  ];

  options = {
    permissions = {
      broker.enable = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Run the permissions broker (`docs/permissions.md`), which grants the sandbox outside access while it runs,
          asking the user each time. Binds its grant directory read-only at `/run/permissions`, with the socket
          requests go to, and adds the `permissions` MCP server.
        '';
      };
      commands = mkOption {
        type = types.attrsOf (
          types.submodule {
            options = {
              description = mkOption {
                type = types.str;
                description = "What a grant of the capability lets Claude do, for Claude: the MCP tools' descriptions name it.";
              };
              consent.title = mkOption {
                type = types.str;
                default = "";
                example = "control the Windows VM";
                description = ''
                  For the user: a short phrase completing "Claude wants to …", which the notification follows with the
                  bounding values and the lease. Required, one line of at most 80 characters.
                '';
              };
              bounding = mkOption {
                type = types.attrsOf (pkgs.formats.json { }).type;
                default = { };
                description = ''
                  Bounding arguments, every command's, as JSON Schema (`docs/permissions.md`): a grant fixes their
                  values. One may take `instances`, a glob with one `*` whose matches are its values. Only the
                  keywords of the broker's subset: it would ignore another, so one fails an assertion.
                '';
              };
              exclusive = mkOption {
                type = types.bool;
                default = false;
                description = "Whether an instance may be granted to one launcher at a time.";
              };
              commands = mkOption {
                type = types.attrsOf (
                  types.submodule {
                    options = {
                      description = mkOption {
                        type = types.str;
                        description = "What the command does, for Claude: its MCP tool's description.";
                      };
                      consent = mkOption {
                        type = types.str;
                        default = "";
                        example = "Take screenshots";
                        description = ''
                          For the user: what the command lets Claude do, in plain words for someone non-technical,
                          without ranges ("Take screenshots"). The consent shows it a line, commands with the same
                          phrase on one line, marked unrestricted when a free argument takes any text. Required, one
                          line of at most 80 characters.
                        '';
                      };
                      arguments = mkOption {
                        type = types.attrsOf (pkgs.formats.json { }).type;
                        default = { };
                        description = "Free arguments, as JSON Schema, each with a description: a grant covers any value they allow. Only the keywords of the broker's subset (`docs/permissions.md`): it would ignore another, so one fails an assertion.";
                      };
                      result = mkOption {
                        type = types.str;
                        default = "text";
                        description = "What it prints: `text`, or an image MIME type.";
                      };
                      run = mkOption {
                        type = types.listOf types.str;
                        description = "What runs on the host per call, with the call as JSON on stdin.";
                      };
                      timeout = mkOption {
                        type = types.str;
                        default = "PT1M";
                        description = "How long a call may run, as an ISO 8601 duration.";
                      };
                      maxValidity = mkOption {
                        type = types.nullOr types.str;
                        default = null;
                        description = "The longest validity a call is told, for commands issuing credentials.";
                      };
                    };
                  }
                );
                description = "The commands, by name: Claude sees each as the tool `<capability>_<command>`.";
              };
            };
          }
        );
        default = { };
        description = ''
          Host commands (`docs/permissions.md`): scripts run on the host per call, under a grant of their capability
          that the user gives or a standing grant. The `permissions` MCP server lists them from its start.
        '';
      };
      sockets = mkOption {
        type = types.attrsOf (
          types.submodule {
            options = {
              description = mkOption {
                type = types.str;
                description = "What a grant of the socket lets Claude do, for the consent.";
              };
              path = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = "The socket on the host, a clean path from `/`, `$XDG_RUNTIME_DIR` or `~/`, which the broker expands, and with no other variable; null with an instances glob.";
              };
              bounding = mkOption {
                type = types.attrsOf (pkgs.formats.json { }).type;
                default = { };
                description = ''
                  Without `path`, one bounding argument, a described string with `instances`: a glob with one `*`
                  whose matches are the sockets, each an instance reachable at its own address.
                '';
              };
            };
          }
        );
        default = { };
        example = lib.literalExpression ''{ ssh-agent = { description = "Sign with the keys in the host's SSH agent"; path = "$XDG_RUNTIME_DIR/ssh-agent.sock"; }; }'';
        description = ''
          Host sockets (`docs/permissions.md`): each reachable inside at `/run/permissions/sockets/<name>` (or
          `sockets/<name>/<instance>`) while a grant covers it, the broker copying bytes to the host socket. The
          service sees the broker as its peer, the host user unsandboxed: declare only sockets that authorize nothing by
          their peer. Never a D-Bus bus, `$XDG_RUNTIME_DIR` as a whole, or the launchers' own sockets.
        '';
      };
      grants = mkOption {
        type = types.attrsOf (
          types.submodule (
            { name, ... }:
            {
              options = {
                enable = mkOption {
                  type = types.bool;
                  default = true;
                  description = "Give the grant.";
                };
                capability = mkOption {
                  type = types.str;
                  default = name;
                  defaultText = lib.literalExpression "<name>";
                  description = "A capability of `permissions.commands` or `permissions.sockets`, or `port`.";
                };
                params = mkOption {
                  type = (pkgs.formats.json { }).type;
                  default = { };
                  description = "Its bounding arguments' values, as a request names them, each one its schema takes. A request or call with exactly these gets the grant.";
                };
              };
            }
          )
        );
        default = { };
        example = lib.literalExpression ''
          {
            windows-vm.params.vm = "win11";
            dev-server = { capability = "port"; params = { protocol = "tcp"; port = 3000; }; };
          }
        '';
        description = ''
          Standing grants, by a name of your choosing, which is the capability unless `capability` says another: the
          broker grants them at every start, without asking, in the order of their names, still within the
          capability's instances (one its capability doesn't take, or two of the same capability and params, stops
          the broker; an assertion catches both but for a value against a `pattern`). Revoked or released, one stays
          ended until the broker starts again. Host command calls under it run without asking, told their
          `maxValidity`. A `port` grant (`protocol` `tcp` or `udp`, `port`) lets the host reach that port of the
          sandbox (over UDP only from a connected socket: an unconnected `sendto` gets no reply). No folders: what
          should always be there is a bind (`permissions.binds`).
        '';
      };
      folders = mkOption {
        type = types.attrsOf (
          types.submodule {
            options = {
              enable = mkOption {
                type = types.bool;
                default = true;
                description = "Let the sandbox ask for the folder.";
              };
              rw = mkOption {
                type = types.bool;
                default = false;
                description = "Whether it may be granted read-write.";
              };
            };
          }
        );
        default = { };
        example = lib.literalExpression ''{ "/home/alice/notes".rw = true; }'';
        description = ''
          Host folders the sandbox may ask for while it runs, keyed by their path, each it or a folder beneath it, as
          the broker's `folders/folder` capability: one is mounted under `/run/permissions` once the user allows it.
          Never the launchers' state directories or `$XDG_RUNTIME_DIR`, nor a folder holding one.
        '';
      };
    };
  };
}
