# request-send as host commands of the permissions broker: the feature `features.request-send` on every launcher,
# with an option of its own, `origins`. On, its body declares the capabilities request-send, which sends GET requests,
# and request-send-write, which sends GET and POST requests, in that launcher's `permissions.commands`, each to the
# configured origins through their proxies
{
  config,
  lib,
  sl,
  launcherName,
  ...
}:
let
  inherit (lib) mkOption types;
  bin = lib.getExe sl.packages.request-send;

  cfg = config.features.request-send;

  options = {
    origins = mkOption {
      type = types.attrsOf (
        types.submodule {
          options = {
            proxy = mkOption {
              type = types.strMatching "https://[^/?#@]+";
              description = "The HTTPS proxy (`https://host[:port]`) requests to the origin go through, which authenticates them as you, such as kmsproxy presenting your client certificate.";
            };
            ca = mkOption {
              type = types.strMatching "/.+";
              description = "A PEM file of the CAs the proxy's certificate and the origin's, as the proxy presents it, must chain to, and the only ones its requests trust.";
            };
          };
        }
      );
      example = lib.literalExpression ''
        {
          "https://helpdesk.example.com" = { proxy = "https://localhost:8090"; ca = "/var/lib/local-ca/ca.crt"; };
        }
      '';
      description = "Where Claude may have requests sent, by origin (`https://host[:port]`), and nowhere else, each with the proxy it goes through and the CAs it trusts.";
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
      throw "features.request-send.origins: none"
    else if bad != [ ] then
      throw "features.request-send.origins: not https origins: ${toString bad}"
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
  oneRequest = "It goes out as the user, through their proxy, and Claude gets the answer";

  run =
    o: scope:
    [
      bin
      "send"
      "--scope=${scope}"
    ]
    ++ lib.concatMap (u: [
      "--origin=${u}"
      "--proxy=${o.origins.${u}.proxy}"
      "--ca=${o.origins.${u}.ca}"
    ]) (originsOf o);

  capabilities = o: {
    request-send = {
      description = "Send GET requests to ${lib.concatStringsSep ", " (originsOf o)} as you, through your authenticating proxy, for reading";
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
      description = "Send GET and POST requests to ${lib.concatStringsSep ", " (originsOf o)} as you, through your authenticating proxy, for writing: what a POST does there is done as you";
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

in
{
  # Declared, for its own option beside a feature's (features.nix takes every other name as a feature)
  options.features = mkOption {
    type = types.submodule {
      options.request-send = mkOption {
        type = types.submodule [
          sl.feature
          { inherit options; }
        ];
        default = { };
        description = "The host commands request-send and request-send-write, which send HTTP requests for Claude through a proxy that authenticates them as you. Needs the permissions broker.";
      };
    };
  };
  config = {
    features.request-send = {
      description = "The host commands request-send and request-send-write: HTTP requests sent on the host through a proxy that authenticates them as the user, to the origins the configuration names";
      note = "Each needs a grant, which the user gives per origin: reading with request-send, reading and writing with request-send-write.";
      permissions.commands = capabilities cfg;
    };
    build.assertions = [
      {
        assertion = !cfg.enable || config.permissions.broker.enable;
        message = "${(sl.idsOf launcherName).opt}features.request-send needs permissions.broker.enable";
      }
    ];
  };
}
