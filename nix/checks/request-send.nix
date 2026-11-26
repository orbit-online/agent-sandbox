# request-send's module (nix/home/claude-desktop/request-send.nix): nix-unit's `tests`, and `check`, which has the
# permissions broker load the declaration
{
  pkgs,
  nixos,
  requestSend,
  broker,
}:
let
  inherit (pkgs) lib;
  alice = cfg: (nixos cfg).config.home-manager.users.alice;
  failed = user: map (a: a.message) (lib.filter (a: !a.assertion) user.assertions);
  # The broker's config as the module writes its commands (commandsOf), for `permissions-broker serve` to load
  brokerConfig =
    lcfg:
    pkgs.writeText "permissions.json" (
      builtins.toJSON {
        commands = lib.mapAttrsToList (name: c: {
          inherit name;
          inherit (c)
            description
            consent
            bounding
            exclusive
            ;
          commands = lib.mapAttrs (_: cmd: {
            inherit (cmd)
              description
              consent
              arguments
              result
              timeout
              run
              ;
          }) c.commands;
        }) lcfg.permissions.commands;
      }
    );
  # The default launcher for a production and a staging origin, work for its own
  rs = alice {
    enable = true;
    permissions.broker.enable = true;
    features.request-send = {
      enable = true;
      origins = {
        "https://helpdesk.example.com" = {
          proxy = "https://localhost:8090";
          ca = "/var/lib/local-ca/ca.crt";
        };
        "https://wiki.example.com" = {
          proxy = "https://127.0.0.1:8092";
          ca = "/etc/ssl/proxy-ca.crt";
        };
      };
    };
    launchers.work = {
      permissions.broker.enable = true;
      features.request-send = {
        enable = true;
        origins."https://helpdesk.example.com:8443" = {
          proxy = "https://proxy.example.com:3128";
          ca = "/etc/ssl/helpdesk.crt";
        };
      };
    };
    launchers.plain.permissions.broker.enable = true;
  };
  cd = rs.agent-sandbox.claude-desktop;
  broken = brokerConfig (
    lib.recursiveUpdate cd {
      permissions.commands.request-send-write.commands.send.arguments.body.description = "";
    }
  );
  # Whether a configuration's capabilities fail to evaluate
  fails =
    cfg:
    !(builtins.tryEval (builtins.toJSON (alice cfg).agent-sandbox.claude-desktop.permissions.commands)).success;
  withOrigins = origins: {
    enable = true;
    permissions.broker.enable = true;
    features.request-send = {
      enable = true;
      origins = lib.genAttrs origins (_: {
        proxy = "https://localhost:8090";
        ca = "/etc/ssl/ca.crt";
      });
    };
  };
  withProxy = proxy: {
    enable = true;
    permissions.broker.enable = true;
    features.request-send = {
      enable = true;
      origins."https://helpdesk.example.com" = {
        inherit proxy;
        ca = "/etc/ssl/ca.crt";
      };
    };
  };
in
{
  # A launcher gets both capabilities when it enables them, each bounded by its origins and run with their proxies and
  # CAs; origins that aren't https origins, or none, and proxies that aren't https://host[:port] don't evaluate
  tests = {
    testRequestSendAssertionsHold = {
      expr = failed rs;
      expected = [ ];
    };
    testRequestSendCapabilities = {
      expr = {
        default = lib.attrNames cd.permissions.commands;
        work = lib.attrNames cd.launchers.work.permissions.commands;
        plain = lib.attrNames cd.launchers.plain.permissions.commands;
      };
      expected = {
        default = [
          "request-send"
          "request-send-write"
        ];
        work = [
          "request-send"
          "request-send-write"
        ];
        plain = [ ];
      };
    };
    testRequestSendWork = {
      expr = {
        origins = cd.launchers.work.permissions.commands.request-send-write.bounding.origin.enum;
        inherit (cd.launchers.work.permissions.commands.request-send-write.commands.send) run;
      };
      expected = {
        origins = [ "https://helpdesk.example.com:8443" ];
        run = [
          (lib.getExe requestSend)
          "send"
          "--scope=write"
          "--origin=https://helpdesk.example.com:8443"
          "--proxy=https://proxy.example.com:3128"
          "--ca=/etc/ssl/helpdesk.crt"
        ];
      };
    };
    testRequestSendAssertion = {
      expr = failed (alice {
        enable = true;
        launchers.work.features.request-send = {
          enable = true;
          origins."https://helpdesk.example.com" = {
            proxy = "https://localhost:8090";
            ca = "/etc/ssl/ca.crt";
          };
        };
      });
      expected = [
        "agent-sandbox.claude-desktop: launchers.work.features.request-send needs permissions.broker.enable"
      ];
    };
    testRequestSendOrigins = {
      expr = {
        http = fails (withOrigins [ "http://helpdesk.example.com" ]);
        withPath = fails (withOrigins [ "https://helpdesk.example.com/api" ]);
        none = fails (withOrigins [ ]);
        good = fails (withOrigins [ "https://helpdesk.example.com" ]);
      };
      expected = {
        http = true;
        withPath = true;
        none = true;
        good = false;
      };
    };
    testRequestSendProxies = {
      expr = lib.mapAttrs (_: proxy: fails (withProxy proxy)) {
        http = "http://localhost:8090";
        withPath = "https://localhost:8090/";
        withUser = "https://user@localhost:8090";
        good = "https://localhost:8090";
      };
      expected = {
        http = true;
        withPath = true;
        withUser = true;
        good = false;
      };
    };
  };

  check =
    pkgs.runCommand "request-send-check"
      {
        nativeBuildInputs = [
          pkgs.jq
          broker
        ];
      }
      ''
        cfg=${brokerConfig cd}
        jq -e --arg bin "${lib.getExe requestSend}" '(.commands | map(.name)) == ["request-send", "request-send-write"]
          and all(.commands[]; (.exclusive | not) and (.commands | keys) == ["send"]
            and .bounding == {origin: {type: "string", description: "the service the request goes to",
              enum: ["https://helpdesk.example.com", "https://wiki.example.com"]}}
            and .commands.send.arguments.path == {type: "string", pattern: "/[!-~]*", maxLength: 2048,
              description: "the request'"'"'s path and query, any on that service"})
          and ((.commands | map({title: .consent.title, send: .commands.send.consent})) == [
            {title: "read from a service as you", send: "Read what you can see there"},
            {title: "read and write at a service as you",
              send: "Read what you can see there, and change it in your name"}])
          and (.commands[0].commands.send | (.arguments | keys) == ["method", "path"]
            and .arguments.method.enum == ["GET"]
            and .run[:3] == [$bin, "send", "--scope=read"])
          and (.commands[1].commands.send | (.arguments | keys) == ["body", "method", "path"]
            and .arguments.method.enum == ["GET", "POST"] and .arguments.body.multiline
            and .run[:3] == [$bin, "send", "--scope=write"])
          and all(.commands[].commands.send.run; .[3:] == ["--origin=https://helpdesk.example.com",
              "--proxy=https://localhost:8090", "--ca=/var/lib/local-ca/ca.crt", "--origin=https://wiki.example.com",
              "--proxy=https://127.0.0.1:8092", "--ca=/etc/ssl/proxy-ca.crt"])' \
          "$cfg" >/dev/null || { echo "The broker's config: $(<"$cfg")" >&2; exit 1; }
        # The broker loads the declaration and goes on to look for its sandbox, which isn't there
        export XDG_RUNTIME_DIR=$TMPDIR HOME=$TMPDIR
        ! permissions-broker serve "$cfg" 2>err
        cat err
        ! grep -q 'Host commands' err || { echo "The broker refused the declaration" >&2; exit 1; }
        # As it does one it refuses
        ! permissions-broker serve ${broken} 2>err
        grep -q 'Host commands request-send-write' err || { echo "The broker took a broken declaration: $(<err)" >&2; exit 1; }
        touch $out
      '';
}
