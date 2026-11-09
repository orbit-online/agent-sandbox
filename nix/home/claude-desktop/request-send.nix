# request-send as host commands of the permissions broker: `permissions.request-send` on the default launcher and on
# each of `launchers.<name>`. Enabled, it declares the capabilities request-send, which sends GET requests, and
# request-send-write, which sends GET and POST requests, in that launcher's `permissions.commands`, each to the
# configured origins
{ inputs }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.agent-sandbox.claude-desktop;
  bin = lib.getExe inputs.self.packages.${pkgs.stdenv.hostPlatform.system}.request-send;
  # step finds its plugins on PATH
  stepWithKms = pkgs.writeShellScript "step" ''
    PATH=${pkgs.step-kms-plugin}/bin''${PATH:+:$PATH} exec ${lib.getExe pkgs.step-cli} "$@"
  '';

  options = {
    enable = lib.mkEnableOption "the host commands request-send and request-send-write, which send HTTP requests for Claude with your users CA certificate and its TPM key";
    origins = mkOption {
      type = types.attrsOf (
        types.submodule {
          options = {
            env = mkOption {
              type = types.enum [
                "production"
                "staging"
              ];
              description = "Which users CA certificate requests to the origin present: `~/.step/certs/cloud-<env>.crt`, with the TPM key `tpmkms:name=cloud-<env>`.";
            };
            ca = mkOption {
              type = types.strMatching "/.+";
              description = "A PEM file of the CAs the origin's server certificate must chain to, and the only ones its requests trust.";
            };
          };
        }
      );
      example = lib.literalExpression ''
        {
          "https://support-staff.org-production.orbit.dev" = { env = "production"; ca = orbit-cas.production.machines_ca; };
          "https://support-staff.org-staging.orbit.dev" = { env = "staging"; ca = orbit-cas.staging.machines_ca; };
        }
      '';
      description = "Where Claude may have requests sent, by origin (`https://host[:port]`), and nowhere else, each with the certificate it presents and the CAs it trusts.";
    };
    step = mkOption {
      type = types.strMatching "/.+";
      default = "${stepWithKms}";
      defaultText = lib.literalMD "step from `pkgs.step-cli`, with `pkgs.step-kms-plugin` on its PATH";
      description = "The step binary the calls run, which must find step-kms-plugin.";
    };
  };

  # The origins, which must be some and be https origins
  originsOf =
    o:
    let
      names = lib.attrNames o.origins;
      bad = lib.filter (n: builtins.match "https://[^/?#@]+" n == null) names;
    in
    if names == [ ] then
      throw "permissions.request-send.origins: none"
    else if bad != [ ] then
      throw "permissions.request-send.origins: not https origins: ${toString bad}"
    else
      names;
  origin = o: {
    type = "string";
    enum = originsOf o;
    description = "the service the request goes to";
  };
  path = {
    type = "string";
    pattern = "/[!-~]*";
    maxLength = 2048;
    description = "the request's path and query, any on that service";
  };
  oneRequest = "It goes out as the user, with their certificate, and Claude gets the answer";

  run =
    o: scope:
    [
      bin
      "send"
      "--scope=${scope}"
      "--step=${o.step}"
    ]
    ++ lib.concatMap (u: [
      "--origin=${u}"
      "--env=${o.origins.${u}.env}"
      "--ca=${o.origins.${u}.ca}"
    ]) (originsOf o);

  capabilities = o: {
    request-send = {
      description = "Send GET requests to ${lib.concatStringsSep ", " (originsOf o)} as you, with your users CA certificate, for reading";
      # The consent's words, for the user
      consent.title = "read from a service as you";
      bounding.origin = origin o;
      commands.send = {
        description = "Send one GET request, for reading. ${oneRequest}";
        consent = "Read what you can see there";
        arguments = {
          method = {
            type = "string";
            enum = [ "GET" ];
            description = "the request's method";
          };
          inherit path;
        };
        run = run o "read";
      };
    };
    request-send-write = {
      description = "Send GET and POST requests to ${lib.concatStringsSep ", " (originsOf o)} as you, with your users CA certificate, for writing: what a POST does there is done as you";
      consent.title = "read and write at a service as you";
      bounding.origin = origin o;
      commands.send = {
        description = "Send one GET or POST request, for writing. ${oneRequest}";
        consent = "Read what you can see there, and change it in your name";
        arguments = {
          method = {
            type = "string";
            enum = [
              "GET"
              "POST"
            ];
            description = "the request's method";
          };
          inherit path;
          body = {
            type = "string";
            multiline = true;
            maxLength = 262144;
            description = "the request's body, sent as application/json, empty for a GET";
          };
        };
        run = run o "write";
      };
    };
  };

  launcherModule =
    { config, ... }:
    {
      options.permissions.request-send = options;
      config.permissions.commands = lib.mkIf config.permissions.request-send.enable (
        capabilities config.permissions.request-send
      );
    };
in
{
  options.agent-sandbox.claude-desktop = {
    permissions.request-send = options;
    launchers = mkOption {
      type = types.attrsOf (types.submodule launcherModule);
    };
  };

  config = {
    agent-sandbox.claude-desktop.permissions.commands = lib.mkIf cfg.permissions.request-send.enable (
      capabilities cfg.permissions.request-send
    );
    assertions =
      lib.mapAttrsToList
        (name: lcfg: {
          assertion = !lcfg.permissions.request-send.enable || lcfg.permissions.enable;
          message = "agent-sandbox.claude-desktop: ${
            lib.optionalString (name != "") "launchers.${name}."
          }permissions.request-send needs permissions.enable";
        })
        (
          {
            "" = cfg;
          }
          // cfg.launchers
        );
  };
}
