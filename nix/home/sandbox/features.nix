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
      while it is on. The module's own, all off: `kvm`, `audio`, `gpu`, `cuda`, `tray`, `keep-awake` and
      `request-send`. Add your own by name, with a body in `permissions`, written in the launcher's `permissions`
      options.

      `gpu` widens the sandbox a lot. It binds `/dev/dri`, primary and render nodes, and where they exist NVIDIA's
      `/dev/nvidiactl`, `/dev/nvidia0` and `/dev/nvidia-modeset`: the ioctl interfaces of the host's GPU drivers,
      among the largest in the kernel, within reach of everything in the sandbox, so a driver bug is a way out.
      Without it the app renders in software, with no WebGL. For less, leave it off and list the nodes you want in
      `permissions.devices`.

      `cuda` adds NVIDIA's `/dev/nvidia-uvm` where it exists, which CUDA opens at `cuInit` beside the nodes `gpu`
      binds, and needs `gpu` on: the unified memory driver's ioctl interface, one more way out.
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
      # nixpak's gpu, switched in core.nix: /dev/dri, the PCI devices in /sys and the host's graphics drivers at
      # /run/opengl-driver. NVIDIA's driver needs its own nodes beside /dev/dri; bound if present, so a Mesa machine
      # gets /dev/dri alone
      gpu = {
        description = "/dev/dri and the host's graphics drivers, and NVIDIA's device nodes where they exist";
        note = "Exposes the ioctl interfaces of the host's GPU drivers: a driver bug is a way out of the sandbox.";
        permissions.devices = {
          "/dev/nvidiactl" = { };
          "/dev/nvidia0" = { };
          "/dev/nvidia-modeset" = { };
        };
      };
      # CUDA on NVIDIA: libcuda from gpu's drivers, nvidiactl and nvidia0 from its nodes, and the unified memory
      # driver's node, without which cuInit fails (CUDA_ERROR_UNKNOWN). Not /dev/nvidia-uvm-tools, which only the
      # profilers' unified memory counters open
      cuda = {
        description = "NVIDIA's /dev/nvidia-uvm where it exists, for CUDA beside the gpu feature";
        note = "Exposes the ioctl interface of NVIDIA's unified memory driver: a driver bug is a way out of the sandbox.";
        permissions.devices."/dev/nvidia-uvm" = { };
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
    build.assertions = [
      {
        assertion = !config.features.cuda.enable || config.features.gpu.enable;
        message = "${ids.opt}features.cuda: needs features.gpu, which brings the drivers and NVIDIA's nodes CUDA opens";
      }
    ]
    ++ lib.mapAttrsToList (name: f: {
      assertion =
        builtins.match "[A-Za-z0-9][A-Za-z0-9-]*" name != null
        && builtins.match "[[:space:]]*" f.description == null
        && line f.description
        && line f.note;
      message = "${ids.opt}features.${name}: a name of letters, digits and -, a description of one line, and a note of one line or none";
    }) on;
  };
}
