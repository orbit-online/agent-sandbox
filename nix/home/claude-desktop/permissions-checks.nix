# What the permissions broker would refuse at its start, caught at eval: standing grants, host sockets and host
# commands
{
  lib,
  config,
  sl,
  launcherName,
  ...
}:
let
  ids = sl.idsOf launcherName;
  opt = "${ids.opt}permissions.grants";
in
{
  build.assertions =
    lib.optional (config.permissions.grants != [ ]) {
      assertion = config.permissions.enable;
      message = "${opt} needs permissions.enable";
    }
    ++ map (
      g:
      if g.capability == "folders/folder" then
        {
          assertion = false;
          message = "${opt}: folders get no standing grants, a folder that should always be there is a bind (binds)";
        }
      else if g.capability == "port" && !config.network.enable then
        {
          assertion = false;
          message = "${opt}: no port grants with network.enable off, the sandbox has no network";
        }
      else if g.capability == "port" then
        {
          # As the schema of the port capability in the broker (ports.go)
          assertion =
            lib.attrNames g.params == [
              "port"
              "protocol"
            ]
            && lib.elem g.params.protocol [
              "tcp"
              "udp"
            ]
            && lib.isInt g.params.port
            && g.params.port >= 1
            && g.params.port <= 65535;
          message = "${opt}: the params of a port grant are protocol (tcp or udp) and port (1 to 65535)";
        }
      else
        {
          assertion =
            config.permissions.commands ? ${g.capability} || config.permissions.sockets ? ${g.capability};
          message = "${opt}: no capability ${g.capability} in permissions.commands or permissions.sockets";
        }
    ) config.permissions.grants
    # The capability of that name built into the broker
    ++ [
      {
        assertion = !(config.permissions.commands ? port || config.permissions.sockets ? port);
        message = "${ids.opt}permissions: port is a capability built into the broker, not a host command or host socket name";
      }
    ]
    # Host sockets the broker would refuse, caught at eval: a name of its own that makes a file name, a path or
    # one instances glob, and nothing that would hand the sandbox the host user's standing (a D-Bus bus,
    # $XDG_RUNTIME_DIR as a whole, the launchers' own sockets)
    ++ lib.concatLists (
      lib.mapAttrsToList (
        sname: sock:
        let
          sopt = "${ids.opt}permissions.sockets.${sname}";
          args = lib.attrValues sock.bounding;
          globbed =
            sock.path == null
            && lib.length args == 1
            && (lib.head args).type or "" == "string"
            && (lib.head args).description or "" != ""
            && (lib.head args) ? instances;
          where = lib.replaceStrings [ "\${XDG_RUNTIME_DIR}" ] [ "$XDG_RUNTIME_DIR" ] (
            if sock.path != null then
              sock.path
            else if args == [ ] then
              ""
            else
              (lib.head args).instances or ""
          );
          # As the daemon's refusedSocket and refusedGlob: a clean path, nothing beneath a refused root
          # (/proc, /run/dbus, /var/run, the buses and launchers' entries in the runtime dir), nor the runtime
          # dir or what holds it, and a glob's * not within the depth of any of those
          segs = lib.splitString "/" where;
          normal =
            segs != [ "" ]
            && lib.elem (lib.head segs) [
              ""
              "$XDG_RUNTIME_DIR"
              "~"
            ]
            && !lib.any (
              seg:
              lib.elem seg [
                ""
                "."
                ".."
              ]
            ) (lib.tail segs);
          runtimes = [
            [ "\\$XDG_RUNTIME_DIR" ]
            [
              ""
              "run"
              "user"
              "[^/]+"
            ]
          ];
          own = [
            "bus"
            "systemd"
            "at-spi"
            "\\.dbus-proxy"
            "dbus-.*"
            "claude-desktop"
            "\\.flatpak"
            "agent-sandbox-permissions"
            "nixpak-.*"
          ];
          roots = [
            [
              ""
              "proc"
            ]
            [
              ""
              "run"
              "dbus"
            ]
            [
              ""
              "var"
              "run"
            ]
          ]
          ++ lib.concatMap (rt: map (o: rt ++ [ o ]) own) runtimes;
          starAt = lib.findFirst (i: lib.hasInfix "*" (lib.elemAt segs i)) (lib.length segs) (
            lib.range 0 (lib.length segs - 1)
          );
          literal = lib.take starAt segs;
          # p's first segments match root's, root's as regexes
          matches =
            p: root:
            lib.all (i: builtins.match (lib.elemAt root i) (lib.elemAt p i) != null) (
              lib.range 0 (lib.length root - 1)
            );
          beneath = p: root: lib.length p >= lib.length root && matches p root;
          within =
            root: lib.length literal < lib.length root && matches literal (lib.take (lib.length literal) root);
          refused =
            !normal
            || lib.any (root: beneath literal root || within root) roots
            || lib.any (
              rt: lib.length literal <= lib.length rt && matches literal (lib.take (lib.length literal) rt)
            ) runtimes;
        in
        [
          {
            assertion =
              builtins.match "[A-Za-z0-9-]+" sname != null
              && lib.stringLength sname <= 80
              && !(config.permissions.commands ? ${sname})
              && (sock.path != null && sock.bounding == { } || globbed);
            message = "${sopt}: a name of at most 80 letters, digits and - that no host commands have, and a path or one described string bounding argument with instances";
          }
          {
            assertion = !refused;
            message = "${sopt}: ${where} is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets";
          }
        ]
      ) config.permissions.sockets
    )
    # What the broker would refuse at start, caught at eval: MCP tool names, every argument described for the
    # consent, none named as the broker's own, a result it can wrap
    ++ lib.concatLists (
      lib.mapAttrsToList (
        cname: c:
        let
          copt = "${ids.opt}permissions.commands.${cname}";
          named = n: builtins.match "[A-Za-z0-9-]+" n != null;
          described = args: lib.all (a: a.description or "" != "") (lib.attrValues args);
          reserved =
            args:
            lib.any (n: args ? ${n}) [
              "reason"
              "lease"
            ];
          # A phrase the consent shows: one line of at most 80 characters, not blank
          phrase =
            p:
            builtins.match "[[:space:]]*" p == null
            && builtins.match ".*[[:cntrl:]].*" p == null
            && sl.utf8Length p <= 80;
        in
        [
          {
            assertion = named cname && c.commands != { };
            message = "${copt}: a name of letters, digits and -, and at least one command";
          }
          {
            assertion = phrase c.consent.title;
            message = "${copt}: consent.title, for the user, one line of at most 80 characters";
          }
          {
            assertion =
              described c.bounding
              && !reserved c.bounding
              && lib.all (a: a.type or "" != "array" && !(a.multiline or false)) (lib.attrValues c.bounding);
            message = "${copt}: every bounding argument needs a description, none may be named reason or lease, and none may be an array or multiline";
          }
        ]
        ++ lib.mapAttrsToList (n: cmd: {
          assertion = phrase cmd.consent;
          message = "${copt}.commands.${n}: consent, for the user, one line of at most 80 characters";
        }) c.commands
        ++ lib.mapAttrsToList (n: cmd: {
          assertion =
            named n
            && lib.stringLength "${cname}_${n}" <= 64
            && described cmd.arguments
            && !reserved cmd.arguments
            && lib.all (a: !(c.bounding ? ${a})) (lib.attrNames cmd.arguments)
            && (cmd.result == "text" || lib.hasPrefix "image/" cmd.result);
          message = "${copt}.commands.${n}: a name of letters, digits and - (${cname}_${n} at most 64 characters), every argument described, none named reason, lease or as a bounding one, and a result of text or image/*";
        }) c.commands
      ) config.permissions.commands
    );
}
