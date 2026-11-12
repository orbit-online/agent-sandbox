# What the app reaches on the session bus, through the Go D-Bus proxy that nixpak runs in xdg-dbus-proxy's place
# (core.nix, nixpakPkgs), and the tray
{
  lib,
  pkgs,
  config,
  sl,
  launcherName,
  ...
}:
let
  inherit (lib) mkOption types;
  ids = sl.idsOf launcherName;
  # The D-Bus proxy's config (dbus-proxy --help): dbus without what's unset
  dbusRules = lib.mapAttrs (_: lib.filterAttrs (_: v: v != null && v != [ ])) config.dbus;
  dbusArgs = [
    "--config=${pkgs.writeText "dbus-proxy${ids.suffix}.json" (builtins.toJSON dbusRules)}"
  ];
  # A rule the D-Bus proxy takes (its rules package's parseRule): [METHOD][@PATH], not empty. METHOD `*`, `IFACE.*`
  # or `IFACE.MEMBER`, split at the last dot, the interface of two elements or more and at most 255 bytes as the
  # member; PATH an object path, or one ending in `/*` for its subtree too, `/*` for any
  dbusRuleOk =
    rule:
    let
      elem = "[A-Za-z_][A-Za-z0-9_]*";
      parts = builtins.match "([^@]*)(@(.*))?" rule;
      method = lib.elemAt parts 0;
      path = lib.elemAt parts 2;
      dotted = builtins.match "(${elem}(\\.${elem})+)\\.(\\*|${elem})" method;
      methodOk =
        method == "*"
        || method == "" && path != null
        ||
          dotted != null
          && lib.stringLength (lib.elemAt dotted 0) <= 255
          && lib.stringLength (lib.elemAt dotted 2) <= 255;
      pathOk = path == null || path == "/*" || builtins.match "/|(/[A-Za-z0-9_]+)+(/\\*)?" path != null;
    in
    methodOk && pathOk;
  # The proxy's caps on its config (MaxNames, MaxRules and MaxConfig there)
  maxNames = 64;
  maxRules = 64;
  maxConfig = 64 * 1024;
  nixpakDbus = config.build.sandboxed.config.dbus;
in
{
  options = {
    tray = mkOption {
      type = types.bool;
      default = false;
      description = "Show a tray icon. Closing the window then hides the app instead of quitting it.";
    };
    dbus = mkOption {
      type = types.attrsOf (
        types.submodule {
          options = {
            policy = mkOption {
              type = types.nullOr (
                types.enum [
                  "see"
                  "talk"
                  "own"
                ]
              );
              default = null;
              description = "`see`: the name is visible. `talk`: any call to it and all its signals. `own`: the app may take the name.";
            };
            call = mkOption {
              type = types.listOf types.str;
              default = [ ];
              description = "Calls the app may make, each `[METHOD][@PATH]`: METHOD `*`, `IFACE.*` or `IFACE.MEMBER`, PATH an object path, ending in `/*` for its subtree too.";
            };
            broadcast = mkOption {
              type = types.listOf types.str;
              default = [ ];
              description = "Broadcasts the app may receive, each a rule as `call`'s. Any rule also makes the name visible, as xdg-dbus-proxy's `--broadcast` does.";
            };
          };
        }
      );
      defaultText = lib.literalMD "the portal's OpenURI, Settings and Notification, and with `tray` the tray's registration and the tray item's name";
      description = ''
        What the app reaches on the session bus through the D-Bus proxy (`dbus-proxy --help`), by well-known name,
        exact: a policy, call and broadcast rules, or both. Any rule also makes the name visible. A call rule passes
        no broadcasts: those need a broadcast rule, or talk or own. Talk reaches every object the name's owner exports,
        so prefer call and broadcast rules.
      '';
    };
    build.dbusRules = mkOption {
      type = types.raw;
      internal = true;
      readOnly = true;
      default = dbusRules;
      description = "The proxy's rules, for the Permissions window's overview.";
    };
  };

  config = {
    # libnotify (Electron's notifications) through the portal: it only finds a sandbox by /.flatpak-info, which the
    # app's root lacks. See patch-asar.sh for the app's own backend
    env.NOTIFY_FORCE_PORTAL = "1";
    # Calls only, never "talk": the proxy filters by name, and talk reaches every object the name's owner exports
    # (plasmashell: the clipboard, PlasmaShell.evaluateScript, quit). A call rule also lets the app see the name and
    # get replies and signals sent to the app (the portal's ActionInvoked) unfiltered; broadcasts pass only by a
    # broadcast rule (Settings' SettingChanged). The tray needs none: Chromium's StatusIconLinuxDbus subscribes to no
    # signal. The proxy checks a call to the owner's unique name
    # against the rules of every name it holds, so no other name may get talk where one of these owners holds it. No
    # org.freedesktop.Notifications: notifications go through the portal, which keys them by app ID, so the app
    # can't replace or close another's (the permissions broker's), nor reach plasmashell
    dbus = lib.mkMerge [
      {
        "org.freedesktop.portal.Desktop" = {
          call = [
            "org.freedesktop.portal.OpenURI.OpenURI@/org/freedesktop/portal/desktop"
            "org.freedesktop.portal.Settings.*@/org/freedesktop/portal/desktop"
            # libnotify with NOTIFY_FORCE_PORTAL; its GDBusProxy loads the interface's version with GetAll
            "org.freedesktop.portal.Notification.*@/org/freedesktop/portal/desktop"
            "org.freedesktop.DBus.Properties.GetAll@/org/freedesktop/portal/desktop"
            # Chromium >= 153 reads Settings' color-scheme only once Get of FileChooser's version succeeds; without it,
            # its GTK fallback lags one switch behind
            "org.freedesktop.DBus.Properties.Get@/org/freedesktop/portal/desktop"
          ];
          # Chromium follows the color scheme and accent color by it (ui/linux/portal_settings_linux.cc)
          broadcast = [ "org.freedesktop.portal.Settings.SettingChanged@/org/freedesktop/portal/desktop" ];
        };
      }
      (lib.mkIf config.tray {
        # Chromium names it StatusNotifierItem-<pid>-<n>
        "org.freedesktop.StatusNotifierItem-${toString ids.appPid}-1".policy = "own";
        # What Chromium's StatusIconLinuxDbus calls
        "org.kde.StatusNotifierWatcher".call = [
          "org.kde.StatusNotifierWatcher.RegisterStatusNotifierItem@/StatusNotifierWatcher"
          "org.freedesktop.DBus.Properties.Get@/StatusNotifierWatcher"
        ];
      })
    ];
    # The proxy's rules, from dbus; nixpak's dbus.policies and dbus.rules would be its argv rules, which it doesn't take
    build.nixpak = [ { dbus.args = dbusArgs; } ];
    build.assertions = [
      {
        assertion =
          nixpakDbus.policies == { }
          && nixpakDbus.rules.call == { }
          && nixpakDbus.rules.broadcast == { }
          && nixpakDbus.args == dbusArgs;
        message = "${ids.opt}sandbox must not set dbus.policies, dbus.rules or dbus.args, which the D-Bus proxy doesn't take; its rules go in ${
          lib.optionalString (launcherName != null) "launchers.${launcherName}."
        }dbus";
      }
    ]
    ++ lib.mapAttrsToList (n: r: {
      # The rest the proxy checks when it starts
      assertion =
        lib.stringLength n <= 255
        && n != "org.freedesktop.DBus"
        && builtins.match "[A-Za-z_-][A-Za-z0-9_-]*(\\.[A-Za-z_-][A-Za-z0-9_-]*)+" n != null
        && (r.policy != null || r.call != [ ] || r.broadcast != [ ]);
      message = "${ids.opt}dbus.\"${n}\": a well-known bus name, exact and not the bus driver's, with a policy or a rule";
    }) config.dbus
    ++ lib.mapAttrsToList (
      n: r:
      let
        bad = lib.filter (rule: !dbusRuleOk rule) (r.call ++ r.broadcast);
      in
      {
        assertion = bad == [ ] && lib.length r.call <= maxRules && lib.length r.broadcast <= maxRules;
        message = "${ids.opt}dbus.\"${n}\": at most ${toString maxRules} call and ${toString maxRules} broadcast rules, each [METHOD][@PATH] as dbus-proxy --help says${
          lib.optionalString (bad != [ ]) ", not ${lib.concatMapStringsSep ", " builtins.toJSON bad}"
        }";
      }
    ) config.dbus
    ++ [
      {
        assertion =
          lib.length (lib.attrNames dbusRules) <= maxNames
          && lib.stringLength (builtins.toJSON dbusRules) <= maxConfig;
        message = "${ids.opt}dbus: at most ${toString maxNames} names and ${toString maxConfig} bytes of JSON, the D-Bus proxy's caps; it has ${toString (lib.length (lib.attrNames dbusRules))} and ${toString (lib.stringLength (builtins.toJSON dbusRules))}";
      }
    ];
  };
}
