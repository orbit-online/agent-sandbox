# Features (docs/permissions.md, Features): named bundles of `permissions` entries behind a switch, each with a
# description and a note. The module's own are declared here, with their bodies where they have one in `permissions`
# options: the tray's is dbus.nix's, request-send is request-send.nix's. Those that are on show in the Permissions
# window's overview (permissions-broker.nix) and in the sandbox's environment doc (environment.nix)
{
  lib,
  config,
  sl,
  launcherName,
  ...
}:
let
  inherit (lib) mkOption types;
  ids = sl.idsOf launcherName;
  on = lib.filterAttrs (_: f: f.enable) config.features;
  # One line, as the window and environment.md show it
  line = s: builtins.match ".*[[:cntrl:]].*" s == null;
in
{
  options.features = mkOption {
    # The module's own that have options of their own are declared (request-send.nix); every other name is a feature
    type = types.submodule { freeformType = types.attrsOf (types.submodule sl.feature); };
    default = { };
    example = lib.literalExpression ''
      {
        kvm.enable = true;
        notes = {
          enable = true;
          description = "The notes folder, read-only, and its sync socket on request";
          permissions = {
            binds."/home/alice/notes" = { };
            sockets.notes-sync = { description = "Sync the notes"; path = "$XDG_RUNTIME_DIR/notes-sync.sock"; };
          };
        };
      }
    '';
    description = ''
      Features: each bundles entries of `permissions` behind `enable`, with a `description` and a `note` that the
      Permissions window and the sandbox's environment doc (`/etc/claude/environment.md` for Claude Desktop) show
      while it is on. The module's own, all off: `kvm`, `audio`, `tray`, `keep-awake` and `request-send`. Add your
      own by name, with a body in `permissions`, written in the launcher's `permissions` options.
    '';
  };
  # The features that are on, by name, as the window's overview and environment.md list them
  options.build.features = mkOption {
    type = types.raw;
    internal = true;
    visible = false;
    readOnly = true;
    default = lib.mapAttrsToList (name: f: {
      inherit name;
      inherit (f) description note;
    }) on;
  };

  config = {
    features = {
      kvm = {
        description = "/dev/kvm, for VMs and NixOS tests in the sandbox";
        note = "Exposes the KVM interface of the host kernel: a KVM bug is a way out of the sandbox.";
        permissions.devices."/dev/kvm" = { };
      };
      # Its sockets sit in $XDG_RUNTIME_DIR, which no bind names (a bind's source is a path as written, and that one
      # is known at launch alone), so core.nix has nixpak bind them and fhs.nix takes /etc/alsa: no body here
      audio = {
        description = "The PipeWire and PulseAudio sockets of the session, and /etc/alsa";
        note = "Unmediated access: microphone, camera and screen-cast streams included.";
      };
      keep-awake = {
        description = "Lets the app keep the machine awake while a session works, through PowerManagement's Inhibit on the session bus";
        # PowerDevil (Plasma 6.6, daemon/powerdevilpolicyagent.cpp) releases any cookie for any caller, from one
        # counter. The proxy filters by method and path and tracks no cookies
        note = "UnInhibit takes a cookie, and Plasma releases any cookie for any caller: a process in the sandbox can drop the holds of other apps.";
        # Chromium's power save blocker asks the bus whether the name has an owner, then calls these two. Suspend and
        # Hibernate on the same object stay refused
        permissions.bus."org.freedesktop.PowerManagement".call = [
          "org.freedesktop.PowerManagement.Inhibit.Inhibit@/org/freedesktop/PowerManagement/Inhibit"
          "org.freedesktop.PowerManagement.Inhibit.UnInhibit@/org/freedesktop/PowerManagement/Inhibit"
        ];
      };
    };
    # The bodies of the features that are on
    permissions = lib.mkMerge (
      lib.mapAttrsToList (_: f: lib.mkIf f.enable f.permissions) config.features
    );
    build.assertions = lib.mapAttrsToList (name: f: {
      assertion =
        builtins.match "[A-Za-z0-9][A-Za-z0-9-]*" name != null
        && builtins.match "[[:space:]]*" f.description == null
        && line f.description
        && line f.note;
      message = "${ids.opt}features.${name}: a name of letters, digits and -, a description of one line, and a note of one line or none";
    }) on;
  };
}
