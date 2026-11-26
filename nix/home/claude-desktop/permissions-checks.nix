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
  # The keywords of the broker's schema subset (its schema package), all it reads of a schema: another one (const,
  # minLength, a misspelt maxlength) loads and restricts nothing, so the argument takes more than its declaration says.
  # And its types, which it refuses a schema without
  schemaKeys = [
    "type"
    "description"
    "opaque"
    "multiline"
    "maxLength"
    "pattern"
    "enum"
    "minimum"
    "maximum"
    "items"
    "maxItems"
    "instances"
  ];
  schemaTypes = [
    "string"
    "boolean"
    "integer"
    "number"
    "array"
  ];
  # What isn't the broker's of a schema: the keywords it doesn't read, and type when it isn't one of its types
  unknownKeys =
    a:
    if !lib.isAttrs a then
      [ "(not an object)" ]
    else
      lib.filter (k: !lib.elem k schemaKeys) (lib.attrNames a)
      ++ lib.optional (!lib.elem (a.type or null) schemaTypes) "type"
      ++ lib.optionals (a ? items) (map (k: "items.${k}") (unknownKeys a.items));
  # The same of each argument, as <argument>.<keyword>
  unknownIn =
    args: lib.concatLists (lib.mapAttrsToList (n: a: map (k: "${n}.${k}") (unknownKeys a)) args);
  unknownMessage =
    args:
    "a schema of the broker's has a type of ${lib.concatStringsSep ", " schemaTypes} and of keywords ${lib.concatStringsSep ", " schemaKeys} alone, any other it would ignore; not ${lib.concatStringsSep ", " (unknownIn args)}";
  # An instances glob as the broker takes one (checkBounding): one * and no ? or [, on a string
  globOk =
    a:
    lib.isString (a.instances or null)
    && lib.length (lib.splitString "*" a.instances) == 2
    && builtins.match ".*[?[].*" a.instances == null
    && a.type or "" == "string";
  # A standing grant's value against its bounding argument's schema, as far as eval can tell (the broker's CheckValue;
  # a pattern is the broker's to match): its type, one line of at most maxLength and 200 characters, within minimum
  # and maximum, one of enum
  valueOk =
    a: v:
    let
      type = a.type or "";
    in
    (
      if type == "string" then
        lib.isString v
        && builtins.match ".*[[:cntrl:]].*" v == null
        && sl.utf8Length v <= lib.min 200 (a.maxLength or 200)
      else if type == "boolean" then
        lib.isBool v
      else if type == "integer" then
        lib.isInt v
      else if type == "number" then
        lib.isInt v || lib.isFloat v
      else
        false
    )
    && (
      lib.elem type [
        "integer"
        "number"
      ]
      -> (a ? minimum -> v >= a.minimum) && (a ? maximum -> v <= a.maximum)
    )
    && (a ? enum -> lib.elem v a.enum);
  grants = map (g: { inherit (g) capability params; }) config.permissions.grants;
in
{
  build.assertions =
    lib.optional (config.permissions.grants != [ ]) {
      assertion = config.permissions.enable;
      message = "${opt} needs permissions.enable";
    }
    ++ lib.concatMap (
      g:
      let
        declared =
          config.permissions.commands.${g.capability} or config.permissions.sockets.${g.capability} or null;
        bounding = if declared == null then { } else declared.bounding;
        params = if lib.isAttrs g.params then g.params else { };
        undeclared = lib.filter (k: !(bounding ? ${k})) (lib.attrNames params);
        badValues = lib.filter (k: bounding ? ${k} && !valueOk bounding.${k} params.${k}) (
          lib.attrNames params
        );
      in
      if g.capability == "folders/folder" then
        [
          {
            assertion = false;
            message = "${opt}: folders get no standing grants, a folder that should always be there is a bind (binds)";
          }
        ]
      else if g.capability == "port" && !config.network.enable then
        [
          {
            assertion = false;
            message = "${opt}: no port grants with network.enable off, the sandbox has no network";
          }
        ]
      else if g.capability == "port" then
        [
          {
            # As the schema of the port capability in the broker (ports.go)
            assertion =
              lib.isAttrs g.params
              &&
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
        ]
      else
        [
          {
            assertion = declared != null;
            message = "${opt}: no capability ${g.capability} in permissions.commands or permissions.sockets";
          }
          {
            # As the broker's checkStanding: bounding values it doesn't take are a config error, and it doesn't start
            assertion = declared == null || lib.isAttrs g.params && undeclared == [ ] && badValues == [ ];
            message = "${opt}: the params of a ${g.capability} grant are values of its bounding arguments (${lib.concatStringsSep ", " (lib.attrNames bounding)}), each one its schema takes, not ${
              lib.concatStringsSep ", " (
                if lib.isAttrs g.params then undeclared ++ badValues else [ (builtins.toJSON g.params) ]
              )
            }";
          }
        ]
    ) config.permissions.grants
    # One listed twice stops the broker too
    ++ map (g: {
      assertion = lib.count (o: o == g) grants == 1;
      message = "${opt}: ${g.capability} ${builtins.toJSON g.params} is listed ${
        toString (lib.count (o: o == g) grants)
      } times";
    }) (lib.unique grants)
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
          # Past a leading $XDG_RUNTIME_DIR or ~/ no variable: the broker expands any its environment has and
          # checks what comes of it, which eval can't
          normal =
            segs != [ "" ]
            && segs != [ "~" ]
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
              || lib.hasInfix "$" seg
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
          {
            assertion = sock.description != "";
            message = "${sopt}: a description, which the consent names";
          }
          {
            assertion =
              sock.path != null || args == [ ] || !((lib.head args) ? instances) || globOk (lib.head args);
            message = "${sopt}: instances is a glob with one * and no ? or [, on a string";
          }
          {
            assertion = unknownIn sock.bounding == [ ];
            message = "${sopt}: ${unknownMessage sock.bounding}";
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
          {
            # As the broker's checkBounding
            assertion =
              let
                globs = lib.filter (a: a ? instances) (lib.attrValues c.bounding);
              in
              lib.length globs <= 1 && lib.all globOk globs;
            message = "${copt}: at most one bounding argument with instances, a glob with one * and no ? or [, on a string";
          }
          {
            assertion = unknownIn c.bounding == [ ];
            message = "${copt}: ${unknownMessage c.bounding}";
          }
        ]
        ++ lib.mapAttrsToList (n: cmd: {
          assertion =
            cmd.description != ""
            && cmd.run != [ ]
            && !lib.any (a: a ? instances) (lib.attrValues cmd.arguments);
          message = "${copt}.commands.${n}: a description, what it runs (run), and instances on bounding arguments only";
        }) c.commands
        ++ lib.mapAttrsToList (n: cmd: {
          assertion = unknownIn cmd.arguments == [ ];
          message = "${copt}.commands.${n}: ${unknownMessage cmd.arguments}";
        }) c.commands
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
