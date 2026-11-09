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
    permissions = {
      enable = true;
      request-send = {
        enable = true;
        origins = {
          "https://support-staff.org-production.orbit.dev" = {
            env = "production";
            ca = "/etc/ssl/machines-ca-production.crt";
          };
          "https://support-staff.org-staging.orbit.dev" = {
            env = "staging";
            ca = "/etc/ssl/machines-ca-staging.crt";
          };
        };
      };
    };
    launchers.work.permissions = {
      enable = true;
      request-send = {
        enable = true;
        origins."https://helpdesk.example.com:8443" = {
          env = "staging";
          ca = "/etc/ssl/helpdesk.crt";
        };
        step = "/run/current-system/sw/bin/step";
      };
    };
    launchers.plain.permissions.enable = true;
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
    permissions = {
      enable = true;
      request-send = {
        enable = true;
        origins = lib.genAttrs origins (_: {
          env = "production";
          ca = "/etc/ssl/ca.crt";
        });
      };
    };
  };
in
{
  # A launcher gets both capabilities when it enables them, each bounded by its origins and run with its env, CA and
  # step; origins that aren't https origins, or none, don't evaluate
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
          "--step=/run/current-system/sw/bin/step"
          "--origin=https://helpdesk.example.com:8443"
          "--env=staging"
          "--ca=/etc/ssl/helpdesk.crt"
        ];
      };
    };
    testRequestSendAssertion = {
      expr = failed (alice {
        enable = true;
        launchers.work.permissions.request-send = {
          enable = true;
          origins."https://support-staff.org-production.orbit.dev" = {
            env = "production";
            ca = "/etc/ssl/ca.crt";
          };
        };
      });
      expected = [
        "agent-sandbox.claude-desktop: launchers.work.permissions.request-send needs permissions.enable"
      ];
    };
    testRequestSendOrigins = {
      expr = {
        http = fails (withOrigins [ "http://support-staff.org-production.orbit.dev" ]);
        withPath = fails (withOrigins [ "https://support-staff.org-production.orbit.dev/api" ]);
        none = fails (withOrigins [ ]);
        good = fails (withOrigins [ "https://support-staff.org-production.orbit.dev" ]);
      };
      expected = {
        http = true;
        withPath = true;
        none = true;
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
              enum: ["https://support-staff.org-production.orbit.dev", "https://support-staff.org-staging.orbit.dev"]}}
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
          and all(.commands[].commands.send.run; (.[3] | test("^--step=/nix/store/.*-step$"))
            and .[4:] == ["--origin=https://support-staff.org-production.orbit.dev", "--env=production",
              "--ca=/etc/ssl/machines-ca-production.crt", "--origin=https://support-staff.org-staging.orbit.dev",
              "--env=staging", "--ca=/etc/ssl/machines-ca-staging.crt"])' \
          "$cfg" >/dev/null || { echo "The broker's config: $(<"$cfg")" >&2; exit 1; }
        # The default step finds step-kms-plugin
        step=$(jq -r '.commands[0].commands.send.run[3] | ltrimstr("--step=")' "$cfg")
        grep -q '${pkgs.step-kms-plugin}/bin' "$step" || { echo "$step has no step-kms-plugin: $(<"$step")" >&2; exit 1; }
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
