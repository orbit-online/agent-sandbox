{
  self,
  inputs,
  pkgs,
}:
let
  inherit (pkgs) lib;
  # Both modules and a user alice, who sets claude-desktop to `cfg`
  aliceModule = cfg: {
    imports = [
      inputs.home-manager.nixosModules.home-manager
      self.nixosModules.claude-desktop
      # Twice, as when another flake's module imports it too
      self.nixosModules.claude-desktop
    ];
    system.stateVersion = "26.05";
    hardware.graphics.enable = true;
    users.users.alice.isNormalUser = true;
    home-manager.sharedModules = [
      self.homeModules.claude-desktop
      self.homeModules.claude-desktop
    ];
    home-manager.users.alice = {
      home.stateVersion = "26.05";
      agent-sandbox.claude-desktop = cfg;
    };
  };
  nixos =
    cfg:
    inputs.nixpkgs.lib.nixosSystem {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules = [
        (aliceModule cfg)
        {
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "none";
            fsType = "tmpfs";
          };
        }
      ];
    };
  enabled = {
    enable = true;
    kvm = true;
    # /dev/kvm again, bound once
    permissions.devices = {
      "/dev/nvidiactl" = { };
      "/dev/kvm" = { };
    };
    extraPath = [ "/srv/bin" ];
    permissions.binds = {
      "/srv/project".rw = true;
      "/srv/docs" = { };
      "/srv/hidden".mcp = false;
      # A module default, overridden by its sandbox path
      "/home/alice/.claude".src = "/srv/claude";
    };
    files = {
      "/etc/agent-sandbox-test/hello".text = lib.getExe pkgs.hello;
      "/etc/agent-sandbox-test".source = pkgs.writeTextDir "other" "";
      "/srv/off" = {
        enable = false;
        text = "off";
      };
    };
    units = {
      "agent-sandbox-test.service" = "[Service]\nType=oneshot\nExecStart=${lib.getExe pkgs.hello}";
      "agent-sandbox-test.timer" = "[Timer]\nOnActiveSec=0";
    };
    launchers.work.permissions.binds."/srv/work".rw = true;
  };
  system = nixos enabled;
  launcherNameMax = lib.toInt (
    builtins.head (
      builtins.match ".*\nconst launcherNameMax = ([0-9]+)\n.*" (
        builtins.readFile ../../cmd/permissions-broker/socketpath_test.go
      )
    )
  );
  alice = system.config.home-manager.users.alice;
  failedAssertions = sys: lib.filter (a: !a.assertion) sys.config.home-manager.users.alice.assertions;
  # alice's programs.mcp set to `mcp`
  withMcp =
    mcp:
    (system.extendModules { modules = [ { home-manager.users.alice.programs.mcp = mcp; } ]; })
    .config.home-manager.users.alice;
  aliceMcp = withMcp {
    enable = true;
    servers = {
      plain.command = "/srv/bin/plain";
      secret = {
        command = "/srv/bin/secret";
        env.TOKEN.file = "/run/secrets/token";
      };
      off = {
        command = "/srv/bin/off";
        enabled = false;
      };
    };
  };
  # alice in a group of her own, not in users
  ownGroup = system.extendModules {
    modules = [
      {
        users.users.alice.group = "alice";
        users.groups.alice = { };
      }
    ];
  };
  sandboxedOf =
    sys:
    lib.findFirst (
      p: p.name == "claude-desktop-sandboxed"
    ) null sys.config.home-manager.users.alice.home.packages;
  sandboxed = sandboxedOf system;
  dbusProxy = self.packages.${pkgs.stdenv.hostPlatform.system}.dbus-proxy;
  # patch-asar.sh on stub asars: the tray icon picker with and without its GNOME case, the app's notification backend
  # choice as 4.x has it (the app the checks build predates it) made false, and the sessions' MCP clients and the way
  # to the session manager as 4.23118 and 5.1231 have them, with channels.js hooked into the clients; the build refusing
  # an app with two of either place
  asarPatch =
    pkgs.runCommand "claude-desktop-asar-patch"
      {
        nativeBuildInputs = [
          pkgs.asar
          pkgs.jq
          pkgs.nodejs
        ];
      }
      ''
        pick='(Mx(iJr,!0)&&await nJr.probe()&&(this.backend=nJr),P.info("NotificationService initialized"))'
        client='p=new t.vct({name:`local-agent-mode-''${e}`,version:"1.0.0"},{capabilities:C}),b&&p.setRequestHandler("roots/list",(async()=>({roots:[]})))'
        # The tray icon picker before 5.1231, with its GNOME case, and from 5.1231, without
        gnome='e||rk()==="gnome"||a.nativeTheme.shouldUseDarkColors?'
        dark='e||a.nativeTheme.shouldUseDarkColors?'
        manager='let{claudeCodeSessionManager:s}=await Promise.resolve().then((()=>require("./index.chunk-m.js"))).then((e=>e.t))'
        # From 5.1231 the chunk exports the manager itself
        direct='let{claudeCodeSessionManager:s}=await Promise.resolve().then((()=>require("./index.chunk-m.js")))'
        app() {
          mkdir -p "$1/.vite/build"
          echo '{"main": "main.js"}' >"$1/package.json"
          echo '"use strict";' >"$1/main.js"
          echo "function c(e){return $4\"TrayIconLinux-Dark.png\":\"TrayIconLinux.png\"}" >>"$1/main.js"
          echo "nJr=new class{constructor(){this.telemetryName=\"freedesktop\"}};async function i(){$2}" \
            >"$1/.vite/build/index.chunk-x.js"
          echo "async function c(e,t,b){$3}" >"$1/.vite/build/index.chunk-c.js"
          echo 'exports.t={claudeCodeSessionManager:{}};exports.claudeCodeSessionManager={}' >"$1/.vite/build/index.chunk-m.js"
          touch "$1/stub.node"
          asar pack "$1" "$1.asar" --unpack '*.node'
        }
        patch() {
          rm -rf app app.asar app.asar.unpacked
          ASAR=$PWD/$1.asar DESKTOP_NAME=x.desktop READY=ready CHANNELS=$2 CHANNELS_JS=${../home/claude-desktop/channels.js} \
            out=$PWD/$1-patched.asar bash -euo pipefail ${../home/claude-desktop/patch-asar.sh}
        }
        app one "$pick" "$client;$manager" "$gnome"
        patch one '[]'
        ! grep -qaF '"gnome"' one-patched.asar || { echo "the tray icon still picks white on GNOME" >&2; exit 1; }
        grep -qaF '(!1&&Mx(iJr,!0)&&await nJr.probe()&&(this.backend=nJr),' one-patched.asar ||
          { echo "the native notification backend can still be picked" >&2; exit 1; }
        ! grep -qaF agent-sandbox-channels one-patched.asar || { echo "channels.js hooked in without channels" >&2; exit 1; }
        patch one '["osticket"]'
        asar extract one-patched.asar one-out
        grep -qF '{capabilities:C}),require("./agent-sandbox-channels.js")(p,e),b&&p.setRequestHandler' \
          one-out/.vite/build/index.chunk-c.js || { echo "channels.js isn't hooked into the MCP client" >&2; exit 1; }
        grep -qF 'new Set(["osticket"])' one-out/.vite/build/agent-sandbox-channels.js
        grep -qF 'require("./index.chunk-m.js").t.claudeCodeSessionManager' one-out/.vite/build/agent-sandbox-channels.js
        node --check one-out/.vite/build/agent-sandbox-channels.js
        node --check one-out/.vite/build/index.chunk-c.js
        app two "$pick;$pick" "" "$gnome"
        if patch two '[]'; then
          echo "patch-asar.sh took an app with two places picking the notification backend" >&2
          exit 1
        fi
        app three "$pick" "$client;$client;$manager" "$gnome"
        if patch three '["osticket"]'; then
          echo "patch-asar.sh took an app with two places making the sessions' MCP clients" >&2
          exit 1
        fi
        app four "$pick" "$client;$direct" "$dark"
        patch four '[]'
        grep -qaF 'e||a.nativeTheme.shouldUseDarkColors?"TrayIconLinux-Dark.png"' four-patched.asar ||
          { echo "the tray icon picker of an app without a GNOME case changed" >&2; exit 1; }
        patch four '["osticket"]'
        asar extract four-patched.asar four-out
        grep -qF 'require("./index.chunk-m.js").claudeCodeSessionManager' four-out/.vite/build/agent-sandbox-channels.js
        node --check four-out/.vite/build/agent-sandbox-channels.js
        touch $out
      '';
  # A stand-in for agent-memos' Home Manager module, with the options this module reads
  memoStub =
    { config, lib, ... }:
    {
      options.programs.agent-memos = {
        enable = lib.mkEnableOption "memo";
        package = lib.mkOption {
          type = lib.types.package;
          default = pkgs.hello;
        };
        embeds = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [
            "core"
            "docs"
          ];
        };
        settings = lib.mkOption {
          inherit ((pkgs.formats.yaml { })) type;
          default = { };
        };
        configFile = lib.mkOption {
          type = lib.types.path;
          default = (pkgs.formats.yaml { }).generate "config.yaml" config.programs.agent-memos.settings;
        };
      };
      config.programs.agent-memos.settings.stores = lib.mkBefore (
        map (s: "embed:${s}") config.programs.agent-memos.embeds
      );
    };
  # alice with memo and the permissions broker, given to the work launcher
  aliceMemo =
    (system.extendModules {
      modules = [
        {
          home-manager.users.alice = {
            imports = [ memoStub ];
            programs.agent-memos = {
              enable = true;
              settings.stores = [ "/srv/team.memo" ];
            };
            agent-sandbox.claude-desktop.launchers.work = {
              memo.enable = true;
              permissions = {
                broker.enable = true;
                folders."/srv/notes" = { };
                # Off: not in the broker's config
                folders."/srv/off".enable = false;
                sockets.agent = {
                  description = "an agent";
                  path = "$XDG_RUNTIME_DIR/agent.sock";
                };
                commands.vm = {
                  description = "a VM";
                  consent.title = "use the VM";
                  bounding.vm = {
                    type = "string";
                    description = "the VM";
                  };
                  commands.shot = {
                    description = "a screenshot";
                    consent = "Take screenshots";
                    result = "image/png";
                    run = [ "/srv/shot" ];
                  };
                };
                # By name, the capability unless it says another
                grants = {
                  agent = { };
                  vm.params.vm = "win11";
                  web = {
                    capability = "port";
                    params = {
                      protocol = "tcp";
                      port = 8081;
                    };
                  };
                  off = {
                    enable = false;
                    capability = "vm";
                    params.vm = "win10";
                  };
                };
              };
            };
          };
        }
      ];
    }).config.home-manager.users.alice;
  work = lib.findFirst (p: p.name == "claude-desktop-work-sandboxed") null aliceMemo.home.packages;
  # Another environmentFile, the rest as in enabled
  customDoc = sandboxedOf (
    nixos (enabled // { environmentFile = pkgs.writeText "custom-environment.md" "custom"; })
  );

  # Run by nix-unit through the flake's tests output, see claude-desktop-eval
  evalTests = {
    testAssertionsHold = {
      expr = failedAssertions system;
      expected = [ ];
    };
    testMemoAssertionsHold = {
      expr = lib.filter (a: !a.assertion) aliceMemo.assertions;
      expected = [ ];
    };
    # memo's config on the host lists the sandbox's store too, right after the embedded ones
    testMemoStores = {
      expr = map (
        s: if lib.hasSuffix "-claude-desktop-environment/environment.memo" s then "environment.memo" else s
      ) aliceMemo.programs.agent-memos.settings.stores;
      expected = [
        "embed:core"
        "embed:docs"
        "environment.memo"
        "/srv/team.memo"
      ];
    };
    testMemoAssertion = {
      expr = map (a: a.message) (failedAssertions (nixos (enabled // { memo.enable = true; })));
      expected = [
        "agent-sandbox.claude-desktop: memo.enable needs Home Manager's memo: import agent-memos' module and set programs.agent-memos.enable"
      ];
    };
    # The work launcher gets memo's package, its config and the sandbox's store, and the part of environment.md every
    # session needs. The default launcher none of it
    testMemo = {
      expr =
        map
          (l: {
            files = lib.attrNames l.files;
            hello = lib.elem pkgs.hello l.path;
            environmentFile = baseNameOf l.environmentFile;
          })
          [
            aliceMemo.agent-sandbox.claude-desktop
            aliceMemo.agent-sandbox.claude-desktop.launchers.work
          ];
      expected = [
        {
          files = [
            "/etc/agent-sandbox-test"
            "/etc/agent-sandbox-test/hello"
            "/srv/off"
          ];
          hello = false;
          environmentFile = "environment.md";
        }
        {
          files = [ "/home/alice/.config/agent-memos/config.yaml" ];
          hello = true;
          environmentFile = "core-environment.md";
        }
      ];
    };
    testWrapper = {
      expr = {
        inherit (system.config.security.wrappers.netns-netkit)
          source
          capabilities
          owner
          group
          permissions
          ;
      };
      expected = {
        source = lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.netns-netkit;
        capabilities = "cap_net_admin,cap_bpf+ep";
        owner = "root";
        group = "sandbox-uplink";
        permissions = "u+rx,g+xs,o+x";
      };
    };
    testNoWrapperWhenDisabled = {
      expr = (nixos { }).config.security.wrappers ? netns-netkit;
      expected = false;
    };
    # The host side of the sandbox network comes with the sandbox, and only then
    testNetwork = {
      expr = {
        on =
          system.config.systemd.services ? sandbox-einat && system.config.systemd.services ? sandbox-uplink;
        off = (nixos { }).config.systemd.services ? sandbox-einat;
        inherit (system.config.networking.dhcpcd) denyInterfaces;
        inherit (system.config.networking.networkmanager) unmanaged;
      };
      expected = {
        on = true;
        off = false;
        denyInterfaces = [ "sbx-*" ];
        unmanaged = [ "interface-name:sbx-*" ];
      };
    };
    # Named uplinks reach both units and the udev rule
    testUplinks =
      let
        c =
          (system.extendModules { modules = [ { agent-sandbox.network.uplinks = [ "eth1" ]; } ]; }).config;
      in
      {
        expr = {
          einat = lib.hasInfix "--uplink=eth1" c.systemd.services.sandbox-einat.serviceConfig.ExecCondition;
          uplink = lib.hasInfix "--uplink=eth1" c.systemd.services.sandbox-uplink.serviceConfig.ExecStart;
          udev = lib.hasInfix ''NAME=="eth1"'' c.services.udev.extraRules;
        };
        expected = {
          einat = true;
          uplink = true;
          udev = true;
        };
      };
    # agent-sandbox.hooks: their config and the wrapper with the union of their capabilities, setgid sandbox-hooks, only
    # with hooks and a sandbox user, the group with a sandbox user alone; store paths and capabilities that exist alone
    testHooks =
      let
        hook = lib.getExe pkgs.hello;
        with' = sys: hooks: (sys.extendModules { modules = [ { agent-sandbox.hooks = hooks; } ]; }).config;
        c = with' system {
          start = [
            {
              path = hook;
              capabilities = [ "CAP_NET_ADMIN" ];
            }
            {
              path = hook;
              capabilities = [
                "CAP_BPF"
                "CAP_NET_ADMIN"
              ];
            }
          ];
          stop = [ { path = hook; } ];
        };
        fails =
          hooks: !(builtins.tryEval (builtins.deepSeq (with' system hooks).environment.etc true)).success;
      in
      {
        expr = {
          none =
            system.config.environment.etc ? "agent-sandbox/hooks.json"
            || system.config.security.wrappers ? sandbox-hooks;
          noUser = (with' (nixos { }) { stop = [ { path = hook; } ]; }).security.wrappers ? sandbox-hooks;
          # The group with the sandbox, hooks or not, for files a hook reads
          group = system.config.users.groups ? sandbox-hooks;
          noUserGroup = (nixos { }).config.users.groups ? sandbox-hooks;
          config = builtins.fromJSON (
            builtins.unsafeDiscardStringContext c.environment.etc."agent-sandbox/hooks.json".text
          );
          wrapper = {
            inherit (c.security.wrappers.sandbox-hooks)
              source
              capabilities
              owner
              group
              permissions
              ;
          };
          noCaps =
            (with' system { stop = [ { path = hook; } ]; }).security.wrappers.sandbox-hooks.capabilities;
          outside = fails { start = [ { path = "/usr/local/bin/hook"; } ]; };
          unknownCap = fails {
            start = [
              {
                path = hook;
                capabilities = [ "CAP_EVERYTHING" ];
              }
            ];
          };
        };
        expected = {
          none = false;
          noUser = false;
          group = true;
          noUserGroup = false;
          config = {
            start = [
              {
                path = hook;
                capabilities = [ "CAP_NET_ADMIN" ];
              }
              {
                path = hook;
                capabilities = [
                  "CAP_BPF"
                  "CAP_NET_ADMIN"
                ];
              }
            ];
            stop = [
              {
                path = hook;
                capabilities = [ ];
              }
            ];
          };
          wrapper = {
            source = lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.sandbox-hooks;
            capabilities = "cap_net_admin,cap_bpf+ep";
            owner = "root";
            group = "sandbox-hooks";
            permissions = "u+rx,g+xs,o+x";
          };
          noCaps = "";
          outside = true;
          unknownCap = true;
        };
      };
    # The launchers get --hooks only with start hooks, and run the stop hooks when any hooks are there; a launcher's
    # permissions.network.hooks reach its helper's --net, of that launcher alone
    testLauncherHooks =
      let
        hook = lib.getExe pkgs.hello;
        sys =
          hooks:
          (nixos (lib.recursiveUpdate enabled { permissions.network.hooks.test = hook; })).extendModules {
            modules = [ { agent-sandbox.hooks = hooks; } ];
          };
        of =
          hooks:
          let
            c = (sys hooks).config.home-manager.users.alice.agent-sandbox.claude-desktop;
            roots = l: lib.concatMapStrings (r: r.text or "") l.build.storeRoots;
            pick = l: {
              start = lib.hasInfix "'--hooks=" (roots l);
              named = lib.hasInfix ''"name":"work"'' (roots l) && lib.hasInfix "sandbox-hooks" (roots l);
              stop = l.build.launcherConfig.hooks;
              net = lib.hasInfix (builtins.unsafeDiscardStringContext ''"hooks":["${hook}"]'') (roots l);
            };
          in
          {
            default = pick c;
            work = pick c.launchers.work;
          };
      in
      {
        expr = {
          none = of { };
          stop = of { stop = [ { path = hook; } ]; };
          start = of { start = [ { path = hook; } ]; };
        };
        expected =
          let
            both = start: stop: {
              default = {
                inherit start stop;
                named = false;
                net = true;
              };
              work = {
                inherit start stop;
                named = start;
                net = false;
              };
            };
          in
          {
            none = both false false;
            stop = both false true;
            start = both true true;
          };
      };
    # permissions.network.hooks reach the helper in the order of their names, whatever order they were written in
    testNetworkHooksOrder =
      let
        first = lib.getExe pkgs.hello;
        second = "${pkgs.coreutils}/bin/true";
        c =
          (nixos (
            lib.recursiveUpdate enabled {
              permissions.network.hooks = {
                "20-routes" = second;
                "10-addresses" = first;
              };
            }
          )).config.home-manager.users.alice.agent-sandbox.claude-desktop;
      in
      {
        expr = lib.any (
          r:
          lib.hasInfix (builtins.unsafeDiscardStringContext ''"hooks":["${first}","${second}"]'') (r.text or "")
        ) c.build.storeRoots;
        expected = true;
      };
    # systemd-networkd leaves the netkit primaries alone
    testNetworkd = {
      expr = {
        networkd =
          let
            n =
              (system.extendModules { modules = [ { systemd.network.enable = true; } ]; })
              .config.systemd.network.networks."10-sandbox-primaries";
          in
          {
            inherit (n.matchConfig) Name;
            inherit (n.linkConfig) Unmanaged;
          };
        off = system.config.systemd.network.networks ? "10-sandbox-primaries";
      };
      expected = {
        networkd = {
          Name = "sbx-*";
          Unmanaged = true;
        };
        off = false;
      };
    };
    testKernelAssertion = {
      expr = map (a: a.message) (
        lib.filter (a: !a.assertion)
          (system.extendModules { modules = [ { boot.kernelPackages = pkgs.linuxPackages_6_6; } ]; })
          .config.assertions
      );
      expected = [
        "agent-sandbox: the sandbox network needs Linux 6.8 or later, this machine has ${pkgs.linuxPackages_6_6.kernel.version}."
      ];
    };
    testGraphicsAssertion = {
      expr = map (a: a.message) (
        failedAssertions (
          system.extendModules { modules = [ { hardware.graphics.enable = lib.mkForce false; } ]; }
        )
      );
      expected = [
        "agent-sandbox.claude-desktop: the sandbox uses the host's graphics drivers, but hardware.graphics.enable is off on this machine. Enable it there if this is a desktop; the module doesn't, so it never pulls a graphics stack onto a server."
      ];
    };
    testUsersGroupAssertion = {
      expr = map (a: a.message) (lib.filter (a: !a.assertion) ownGroup.config.assertions);
      expected = [
        "agent-sandbox.claude-desktop: alice enables the sandbox but isn't in group users, which netns-netkit is limited to. Add users to users.users.alice.extraGroups."
      ];
    };
    testSubIdsAssertion = {
      expr = map (a: a.message) (
        lib.filter (a: !a.assertion)
          (system.extendModules {
            modules = [ { users.users.alice.autoSubUidGidRange = lib.mkForce false; } ];
          }).config.assertions
      );
      expected = [
        "agent-sandbox.claude-desktop: alice enables the sandbox but has no subordinate uid and gid range, which the sandbox maps into its user namespace. Set users.users.alice.autoSubUidGidRange, or subUidRanges and subGidRanges."
      ];
    };
    # The module mkForces them, so only a higher priority gets past it
    testNetnsAssertionNetwork = {
      expr = lib.length (
        failedAssertions (nixos (enabled // { sandbox.bubblewrap.network = lib.mkOverride 10 false; }))
      );
      expected = 1;
    };
    testNetnsAssertionPasta = {
      expr = lib.length (
        failedAssertions (nixos (enabled // { sandbox.pasta.package = lib.mkOverride 10 pkgs.passt; }))
      );
      expected = 1;
    };
    testNameserversAssertion = {
      expr = map (a: a.message) (
        failedAssertions (
          nixos (
            enabled
            // {
              nameservers = [
                "192.168.1.1"
                "fd00::53"
              ];
              launchers.work.nameservers = [
                "9.9.9.9"
                "256.1.1.1"
                "10.0.0.1\nsearch evil"
                "fd00::/64"
              ];
            }
          )
        )
      );
      expected = [
        ''agent-sandbox.claude-desktop: launchers.work.nameservers must be IP addresses: "9.9.9.9", "256.1.1.1", "10.0.0.1\nsearch evil", "fd00::/64"''
      ];
    };
    # A launcher with permissions.network.enable off: its netns without a netkit pair (no --net for the bwrap of nixpak) and no DNS
    # followed (the launcher config), the default launcher with both, the assertions holding
    testNetworkOff =
      let
        sys = nixos (lib.recursiveUpdate enabled { launchers.work.permissions.network.enable = false; });
        c = sys.config.home-manager.users.alice.agent-sandbox.claude-desktop;
        of = l: {
          net = lib.any (r: lib.hasInfix "'--net=" (r.text or "")) l.build.storeRoots;
          inherit (l.build.launcherConfig) network;
        };
      in
      {
        expr = {
          default = of c;
          work = of c.launchers.work;
          failed = failedAssertions sys;
        };
        expected = {
          default = {
            net = true;
            network = true;
          };
          work = {
            net = false;
            network = false;
          };
          failed = [ ];
        };
      };
    # No standing port grant without a network
    testNetworkOffPortGrant = {
      expr = map (a: a.message) (
        failedAssertions (
          nixos (
            lib.recursiveUpdate enabled {
              launchers.work.permissions = {
                network.enable = false;
                broker.enable = true;
                grants.web = {
                  capability = "port";
                  params = {
                    protocol = "tcp";
                    port = 8080;
                  };
                };
              };
            }
          )
        )
      );
      expected = [
        "agent-sandbox.claude-desktop: launchers.work.permissions.grants.web: no port grants with permissions.network.enable off, the sandbox has no network"
      ];
    };
    testExtraPath = {
      expr = lib.head (
        lib.splitString ":" alice.agent-sandbox.claude-desktop.mcpServers.claude-code.env.PATH
      );
      expected = "/srv/bin";
    };
    testLaunchers = {
      expr = map (p: p.name) (lib.filter (p: lib.hasPrefix "claude-desktop" p.name) alice.home.packages);
      expected = [
        "claude-desktop-sandboxed"
        "claude-desktop-work-sandboxed"
      ];
    };
    # S14: no bind reaches a launcher's state or the runtime dir
    testStateBinds = {
      expr = map (a: a.message) (
        failedAssertions (
          nixos (
            lib.recursiveUpdate enabled {
              permissions.binds."/srv/local".src = "/home/alice/.local/";
              permissions.binds."/srv/run".src = "/run/user/1000";
              permissions.binds."/srv/sock".src = "/run/user/1000/claude-desktop/permissions-control.sock";
              # Another socket there is the user's call
              permissions.binds."/srv/agent".src = "/run/user/1000/ssh-agent.sock";
              launchers.work.permissions.binds."/srv/other".src = "/home/alice/.local/share/claude-desktop/home";
              launchers.work.permissions.binds."/srv/store".src =
                "/home/alice/.local/share/claude-desktop-work/nix-store.id";
            }
          )
        )
      );
      expected =
        map
          (
            b:
            "agent-sandbox.claude-desktop: ${b}, which holds or lies in a launcher's state dir, or holds $XDG_RUNTIME_DIR or lies in its .flatpak or claude-desktop dir; no sandbox may reach those"
          )
          [
            ''permissions.binds."/srv/local" binds /home/alice/.local/''
            ''permissions.binds."/srv/run" binds /run/user/1000''
            ''permissions.binds."/srv/sock" binds /run/user/1000/claude-desktop/permissions-control.sock''
            ''launchers.work.permissions.binds."/srv/other" binds /home/alice/.local/share/claude-desktop/home''
            ''launchers.work.permissions.binds."/srv/store" binds /home/alice/.local/share/claude-desktop-work/nix-store.id''
          ];
    };
    # L10: no bind's source lies where the sandbox can put a link, which bwrap would follow at the next launch
    testNestedBinds = {
      expr = map (a: a.message) (
        failedAssertions (
          nixos (
            lib.recursiveUpdate enabled {
              # Beneath a read-write bind, under its own path and under another, read-only or not
              permissions.binds."/srv/project/vendor" = { };
              permissions.binds."/srv/elsewhere" = {
                src = "/srv/project/secrets/";
                rw = true;
              };
              # Beneath the sandbox's home and its scratchpad, which it writes as well
              permissions.binds."/srv/own".src = "/home/alice/.local/share/claude-desktop/home/notes";
              permissions.binds."/srv/scratch".src = "/home/alice/.local/share/claude-desktop/tmp-scratchpad/x";
              # A device beneath a read-write bind, and one that isn't
              permissions.devices = {
                "/srv/project/dev/node" = { };
                "/dev/fuse" = { };
                # Not bound
                "/srv/project/dev/off".enable = false;
              };
              # Fine: beneath a read-only bind, the same source as a read-write one, one that merely starts like it,
              # beneath one that is off, and beneath another launcher's read-write bind
              permissions.binds."/srv/docs/api" = { };
              permissions.binds."/srv/again".src = "/srv/project";
              permissions.binds."/srv/project-old" = { };
              permissions.binds."/srv/off" = {
                enable = false;
                rw = true;
              };
              permissions.binds."/srv/off/inner" = { };
              permissions.binds."/srv/work/inner" = { };
              launchers.work.permissions.binds."/srv/project/inner" = { };
            }
          )
        )
      );
      expected = map (
        b:
        "agent-sandbox.claude-desktop: ${b}, a directory the sandbox writes: it can put a link in its place, which the next launch would follow to anything you reach. Bind it from somewhere the sandbox can't write, or leave it to the bind that holds it"
      ) [
        ''permissions.binds."/srv/elsewhere" binds /srv/project/secrets/, which lies beneath /srv/project''
        ''permissions.binds."/srv/own" binds /home/alice/.local/share/claude-desktop/home/notes, which lies beneath /home/alice/.local/share/claude-desktop/home''
        ''permissions.binds."/srv/project/vendor" binds /srv/project/vendor, which lies beneath /srv/project''
        ''permissions.binds."/srv/scratch" binds /home/alice/.local/share/claude-desktop/tmp-scratchpad/x, which lies beneath /home/alice/.local/share/claude-desktop/tmp-scratchpad''
        ''permissions.devices."/srv/project/dev/node", which lies beneath /srv/project''
      ];
    };
    testUnitsOwnNames = {
      expr = map (a: a.message) (
        failedAssertions (nixos (enabled // { units."claude-desktop-store-gc.timer" = "[Timer]"; }))
      );
      expected = [
        "agent-sandbox.claude-desktop: units starting with claude-desktop- are the module's own: claude-desktop-store-gc.timer"
      ];
    };
    # The timers' frequencies: the defaults on the default launcher, on work a calendar spec of its own and the prune's
    # timer left out (the GC's path unit and both services stay), a value of two lines refused
    testTimerFrequencies =
      let
        c =
          (nixos (
            lib.recursiveUpdate enabled {
              launchers.work = {
                storeGc.frequency = "Mon *-*-* 04:00";
                scratchpadPrune.frequency = null;
              };
            }
          )).config.home-manager.users.alice.agent-sandbox.claude-desktop;
        of = l: lib.filterAttrs (n: _: lib.hasPrefix "claude-desktop-" n) l.build.userUnits;
        timer = spec: "[Timer]\nOnCalendar=${spec}\nPersistent=true\n";
      in
      {
        expr = {
          default = lib.mapAttrs (n: v: if lib.hasSuffix ".timer" n then v else true) (of c);
          work = lib.mapAttrs (n: v: if lib.hasSuffix ".timer" n then v else true) (of c.launchers.work);
          twoLines =
            (builtins.tryEval (
              builtins.deepSeq
                (nixos (enabled // { storeGc.frequency = "weekly\nOnCalendar=minutely"; }))
                .config.home-manager.users.alice.agent-sandbox.claude-desktop.build.userUnits
                true
            )).success;
        };
        expected = {
          default = {
            "claude-desktop-store-gc.service" = true;
            "claude-desktop-store-gc.path" = true;
            "claude-desktop-store-gc.timer" = timer "weekly";
            "claude-desktop-scratchpad-prune.service" = true;
            "claude-desktop-scratchpad-prune.timer" = timer "daily";
          };
          work = {
            "claude-desktop-store-gc.service" = true;
            "claude-desktop-store-gc.path" = true;
            "claude-desktop-store-gc.timer" = timer "Mon *-*-* 04:00";
            "claude-desktop-scratchpad-prune.service" = true;
          };
          twoLines = false;
        };
      };
    testLauncherName = {
      expr = map (a: a.message) (failedAssertions (nixos (enabled // { launchers.Work = { }; })));
      expected = [ "agent-sandbox.claude-desktop: launcher name Work must match [a-z][a-z0-9-]*" ];
    };
    # At the cap on a launcher name's length, and past it. The cap is the Go tests', which bind the sockets at it, so
    # the module's has to agree
    testLauncherNameMax = {
      expr = failedAssertions (
        nixos (enabled // { launchers.${lib.fixedWidthString launcherNameMax "a" "w"} = { }; })
      );
      expected = [ ];
    };
    testLauncherNameTooLong =
      let
        name = lib.fixedWidthString (launcherNameMax + 1) "a" "w";
      in
      {
        expr = map (a: a.message) (failedAssertions (nixos (enabled // { launchers.${name} = { }; })));
        expected = [
          "agent-sandbox.claude-desktop: launcher name ${name} must be at most ${toString launcherNameMax} characters, so the socket paths it goes into fit a socket's 107 bytes and its NUL; the longest is the launcher's warning socket, /run/user/<uid>/claude-desktop/claude-desktop-<name>-app.service.warn"
        ];
      };
    # The sockets bound by a path the launcher's name is in, for a name at the cap and the longest runtime dir
    # (/run/user/4294967294): the launcher's warning socket, the broker's two, and the varlink socket of the sandbox's
    # journald namespace, which the NixOS module starts. None past a socket path's 107 bytes, the longest at them
    testLauncherNameSockets =
      let
        name = lib.fixedWidthString launcherNameMax "a" "w";
        sys = nixos (enabled // { launchers.${name}.permissions.broker.enable = true; });
        cfg =
          sys.config.home-manager.users.alice.agent-sandbox.claude-desktop.launchers.${name}.build.launcherConfig;
        runtime = "/run/user/4294967294/claude-desktop";
        journals = lib.filter (lib.hasInfix name) sys.config.systemd.targets.sockets.wants;
      in
      {
        expr = {
          failed = failedAssertions sys;
          sockets = lib.sort (a: b: a > b) (
            map lib.stringLength (
              [
                # The app's unit, as the module names it (appUnit in its lib.nix)
                "${runtime}/claude-desktop-${name}-app.service.warn"
                "${runtime}/${cfg.permissions.dir}-control.sock"
                "${runtime}/${cfg.permissions.dir}/request.sock"
              ]
              ++ map (
                j:
                "/run/systemd/journal.${lib.removePrefix "systemd-journald@" (lib.removeSuffix ".socket" j)}/io.systemd.journal"
              ) journals
            )
          );
        };
        expected = {
          failed = [ ];
          sockets = [
            107
            102
            100
            100
            94
          ];
        };
      };
    # The cap as the Go side has it: the tests that bind the warning socket and the broker's at it, and the helpers'
    # check of a launcher name
    testLauncherNameMaxAgrees = {
      expr = {
        warn = lib.toInt (
          builtins.head (
            builtins.match ".*\nconst launcherNameMax = ([0-9]+)\n.*" (
              builtins.readFile ../../cmd/launcher/warn_test.go
            )
          )
        );
        helpers = builtins.match ".*\nvar LauncherName = [^\n]*a-z0-9-][{]0,([0-9]+)[}][^\n]*\n.*" (
          builtins.readFile ../../internal/caller/caller.go
        );
      };
      expected = {
        warn = launcherNameMax;
        helpers = [ (toString (launcherNameMax - 1)) ];
      };
    };
    testLauncherNetnsAssertion = {
      expr = map (a: a.message) (
        failedAssertions (
          nixos (enabled // { launchers.work.sandbox.pasta.package = lib.mkOverride 10 pkgs.passt; })
        )
      );
      expected = [
        "agent-sandbox.claude-desktop: the sandbox always gets its own netns with a netkit pair; launchers.work.sandbox must not change bubblewrap.network or pasta"
      ];
    };
    # The proxy's rules: the portal's, and with a tray its item's name and the watcher's; a launcher's own pid, and
    # the user's merged in
    testDbusDefaults = {
      expr =
        let
          c =
            (nixos (
              lib.recursiveUpdate enabled {
                tray = true;
                permissions.bus."org.freedesktop.portal.Desktop".call = [ "org.freedesktop.portal.Email.*" ];
                launchers.work.tray = true;
              }
            )).config.home-manager.users.alice.agent-sandbox.claude-desktop;
        in
        {
          default = lib.attrNames c.permissions.bus;
          work = lib.attrNames c.launchers.work.permissions.bus;
          portal = lib.length c.permissions.bus."org.freedesktop.portal.Desktop".call;
          workPortal = lib.length c.launchers.work.permissions.bus."org.freedesktop.portal.Desktop".call;
        };
      expected = {
        default = [
          "org.freedesktop.StatusNotifierItem-100-1"
          "org.freedesktop.portal.Desktop"
          "org.kde.StatusNotifierWatcher"
        ];
        work = [
          "org.freedesktop.StatusNotifierItem-101-1"
          "org.freedesktop.portal.Desktop"
          "org.kde.StatusNotifierWatcher"
        ];
        portal = 6;
        workPortal = 5;
      };
    };
    # nixpak's own D-Bus rules would be argv the proxy refuses, and a name the proxy refuses fails at launch
    testDbusAssertions = {
      expr = map (a: a.message) (
        failedAssertions (
          nixos (
            lib.recursiveUpdate enabled {
              sandbox.dbus.policies."org.test.A" = "talk";
              permissions.bus = {
                "org.test.*".policy = "see";
                "org.freedesktop.DBus".policy = "talk";
                "org.test.Empty" = { };
                "org.test.Fine".policy = "see";
              };
              launchers.work.sandbox.dbus.rules.call."org.test.A" = [ "*" ];
            }
          )
        )
      );
      expected = [
        "agent-sandbox.claude-desktop: sandbox must not set dbus.policies, dbus.rules or dbus.args, which the D-Bus proxy doesn't take; its rules go in permissions.bus"
      ]
      ++
        map
          (
            n:
            "agent-sandbox.claude-desktop: permissions.bus.\"${n}\": a well-known bus name, exact and not the bus driver's, with a policy, a rule or a version"
          )
          [
            "org.freedesktop.DBus"
            "org.test.*"
            "org.test.Empty"
          ]
      ++ [
        "agent-sandbox.claude-desktop: launchers.work.sandbox must not set dbus.policies, dbus.rules or dbus.args, which the D-Bus proxy doesn't take; its rules go in launchers.work.permissions.bus"
      ];
    };
    # The proxy's rule syntax and caps, at eval: a rule it refuses or a config past its caps fails here, not at launch.
    # 64 rules a list and 64 names may be
    testDbusRuleAssertions = {
      expr = map (a: lib.head (lib.splitString "; it has" a.message)) (
        failedAssertions (
          nixos (
            lib.recursiveUpdate enabled {
              permissions.bus = {
                "org.test.Good" = {
                  call = [
                    "*"
                    "org.test.I.*"
                    "org.test.I.M"
                    "org.test.I.M@/"
                    "@/a/b"
                    "@/*"
                    "org.test.I.M@/a_1/*"
                    "*@/0"
                    "org.test.I.${lib.strings.replicate 255 "m"}"
                  ];
                  broadcast = [ "org.test.I.S@/a" ];
                  versions = {
                    "org.test.I@/" = 0;
                    "org.test.I@/a_1/b" = 4294967295;
                  };
                };
                "org.test.Bad" = {
                  call = [
                    ""
                    "@"
                    "org.test.I.M@"
                    "@//*"
                    "@/a/"
                    "@/a/*/b"
                    "org.test.I.M@/a@/b"
                    "Iface.*"
                    "org.test..M"
                    "org.test.I.9M"
                    "org.test.I.M-x"
                    " *"
                    "org.test.I.${lib.strings.replicate 256 "m"}"
                  ];
                  broadcast = [ "*.Get" ];
                  versions = lib.genAttrs [
                    "org.test.I"
                    "org.test.I@"
                    "org.test.I@/a/"
                    "org.test.I@/a/*"
                    "org.test.I.*@/a"
                    "I@/a"
                  ] (_: 1);
                };
                "org.test.Edge" = {
                  call = lib.genList (_: "*") 64;
                  versions = lib.genAttrs (map (i: "org.test.I${toString i}@/") (lib.range 1 64)) (_: 1);
                };
                "org.test.Many".broadcast = lib.genList (_: "*") 65;
                "org.test.ManyVersions".versions = lib.genAttrs (map (i: "org.test.I${toString i}@/") (
                  lib.range 1 65
                )) (_: 1);
                # Over 64 KiB in one rule
                "org.test.Big".call = [ "@/${lib.strings.replicate (64 * 1024) "a"}" ];
              };
              # With the portal's, 65 names; the default launcher's 64 above and its own
              launchers.work.permissions.bus = lib.genAttrs (map (i: "org.test.N${toString i}") (lib.range 1 64)) (
                _: { policy = "see"; }
              );
            }
          )
        )
      );
      expected =
        let
          rules = "at most 64 call and 64 broadcast rules, each [METHOD][@PATH], and 64 versions, each IFACE@PATH, as dbus-proxy --help says";
        in
        [
          ''agent-sandbox.claude-desktop: permissions.bus."org.test.Bad": ${rules}, not "", "@", "org.test.I.M@", "@//*", "@/a/", "@/a/*/b", "org.test.I.M@/a@/b", "Iface.*", "org.test..M", "org.test.I.9M", "org.test.I.M-x", " *", "org.test.I.${lib.strings.replicate 256 "m"}", "*.Get", "I@/a", "org.test.I", "org.test.I.*@/a", "org.test.I@", "org.test.I@/a/", "org.test.I@/a/*"''
          ''agent-sandbox.claude-desktop: permissions.bus."org.test.Many": ${rules}''
          ''agent-sandbox.claude-desktop: permissions.bus."org.test.ManyVersions": ${rules}''
          "agent-sandbox.claude-desktop: permissions.bus: at most 64 names and 65536 bytes of JSON, the D-Bus proxy's caps"
          "agent-sandbox.claude-desktop: launchers.work.permissions.bus: at most 64 names and 65536 bytes of JSON, the D-Bus proxy's caps"
        ];
    };
    # Each app gets a pid of its own, so their tray items don't clash on the session bus
    testLauncherTrays = {
      expr = failedAssertions (
        nixos (
          enabled
          // {
            tray = true;
            launchers.work.tray = true;
          }
        )
      );
      expected = [ ];
    };
    # Its own binds only: ~/.claude lives in its home
    testLauncherMcpRoots = {
      expr = alice.agent-sandbox.claude-desktop.launchers.work.mcpServers.filesystem.args;
      expected = [ "/srv/work" ];
    };
    testMcpRoots = {
      expr = lib.sort lib.lessThan alice.agent-sandbox.claude-desktop.mcpServers.filesystem.args;
      expected = [
        "/home/alice/.claude"
        "/srv/docs"
        "/srv/project"
      ];
    };
    # The sandbox's own, then programs.mcp.servers, in every launcher. Disabled ones left out
    testMcpServers = {
      expr = map (l: lib.attrNames l.mcpServers) [
        aliceMcp.agent-sandbox.claude-desktop
        aliceMcp.agent-sandbox.claude-desktop.launchers.work
      ];
      expected = lib.replicate 2 [
        "claude-code"
        "filesystem"
        "plain"
        "secret"
      ];
    };
    # Only a launcher with the broker gets its MCP server, given the host commands' declarations (checked in the
    # closure: without run)
    testPermissionsMcp = {
      expr =
        map
          (
            l:
            if l.mcpServers ? permissions then
              l.mcpServers.permissions // { args = lib.take 2 l.mcpServers.permissions.args; }
            else
              null
          )
          [
            aliceMemo.agent-sandbox.claude-desktop
            aliceMemo.agent-sandbox.claude-desktop.launchers.work
          ];
      expected = [
        null
        {
          command = lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.permissions-broker;
          args = [
            "mcp"
            "--commands"
          ];
        }
      ];
    };
    # Standing grants only with the broker, of a host command or host socket it has or a port, never of folders; a port's
    # params as the broker takes them, and no host socket or command named after the port capability. Each names its
    # entry; one that is off is left alone
    testStandingGrants = {
      expr = map (a: a.message) (
        failedAssertions (
          nixos (
            lib.recursiveUpdate enabled {
              permissions.grants.vm = { };
              launchers.work.permissions = {
                broker.enable = true;
                folders."/srv/notes" = { };
                sockets.agent = {
                  description = "an agent";
                  path = "/srv/agent.sock";
                };
                sockets.port = {
                  description = "a socket named port";
                  path = "/srv/port.sock";
                };
                grants = {
                  folder = {
                    capability = "folders/folder";
                    params.path = "/srv/notes";
                  };
                  none = { };
                  agent = { };
                  # Not given: nothing of it is checked
                  off = {
                    enable = false;
                    capability = "nothing";
                  };
                  port-max = {
                    capability = "port";
                    params = {
                      protocol = "tcp";
                      port = 65535;
                    };
                  };
                  port-sctp = {
                    capability = "port";
                    params = {
                      protocol = "sctp";
                      port = 80;
                    };
                  };
                  port-zero = {
                    capability = "port";
                    params = {
                      protocol = "udp";
                      port = 0;
                    };
                  };
                  port-over = {
                    capability = "port";
                    params = {
                      protocol = "udp";
                      port = 65536;
                    };
                  };
                  port-missing = {
                    capability = "port";
                    params.protocol = "tcp";
                  };
                  port-string = {
                    capability = "port";
                    params = {
                      protocol = "tcp";
                      port = "80";
                    };
                  };
                };
              };
            }
          )
        )
      );
      expected = [
        "agent-sandbox.claude-desktop: permissions.grants needs permissions.broker.enable"
        "agent-sandbox.claude-desktop: permissions.grants.vm: no capability vm in permissions.commands or permissions.sockets"
        "agent-sandbox.claude-desktop: launchers.work.permissions.grants.folder: folders get no standing grants, a folder that should always be there is a bind (permissions.binds)"
        "agent-sandbox.claude-desktop: launchers.work.permissions.grants.none: no capability none in permissions.commands or permissions.sockets"
      ]
      ++
        map
          (
            n:
            "agent-sandbox.claude-desktop: launchers.work.permissions.grants.${n}: the params of a port grant are protocol (tcp or udp) and port (1 to 65535)"
          )
          [
            "port-missing"
            "port-over"
            "port-sctp"
            "port-string"
            "port-zero"
          ]
      ++ [
        "agent-sandbox.claude-desktop: launchers.work.permissions: port is a capability built into the broker, not a host command or host socket name"
      ];
    };
    # What the broker's config gets of the attrsets: the folders by path and the standing grants by name, in that order
    # and without the ones that are off, a grant's capability its name unless it says another
    testBrokerConfig =
      let
        c =
          (nixos (
            lib.recursiveUpdate enabled {
              launchers.work.permissions = {
                broker.enable = true;
                folders = {
                  "/srv/notes" = { };
                  "/srv/more".rw = true;
                  "/srv/off".enable = false;
                };
                sockets.agent = {
                  description = "an agent";
                  path = "/srv/agent.sock";
                };
                grants = {
                  web = {
                    capability = "port";
                    params = {
                      protocol = "tcp";
                      port = 8080;
                    };
                  };
                  agent = { };
                  off = {
                    enable = false;
                    capability = "agent";
                  };
                };
              };
            }
          )).config.home-manager.users.alice.agent-sandbox.claude-desktop.launchers.work.build.permissionsConfig;
      in
      {
        expr = {
          inherit (c) folders grants;
        };
        expected = {
          folders = [
            {
              path = "/srv/more";
              rw = true;
            }
            {
              path = "/srv/notes";
              rw = false;
            }
          ];
          grants = [
            {
              capability = "agent";
              params = { };
            }
            {
              capability = "port";
              params = {
                protocol = "tcp";
                port = 8080;
              };
            }
          ];
        };
      };
    # Host sockets the broker would refuse, caught at eval: a bad name or one host commands have, neither or both of a
    # path and an instances glob, a D-Bus bus, $XDG_RUNTIME_DIR as a whole and the launchers' own sockets
    testSocketAssertions = {
      expr = map (a: a.message) (
        failedAssertions (
          nixos (
            lib.recursiveUpdate enabled {
              launchers.work.permissions = {
                broker.enable = true;
                commands.vm = {
                  description = "a VM";
                  consent.title = "use the VM";
                  commands.shot = {
                    description = "a screenshot";
                    consent = "Take screenshots";
                    run = [ "/srv/shot" ];
                  };
                };
                sockets = {
                  ok = {
                    description = "fine";
                    path = "$XDG_RUNTIME_DIR/ssh-agent.sock";
                  };
                  vms = {
                    description = "fine, by instance";
                    bounding.vm = {
                      type = "string";
                      description = "the VM";
                      instances = "\${XDG_RUNTIME_DIR}/vms/*/console.sock";
                    };
                  };
                  a_b = {
                    description = "bad name";
                    path = "/srv/a.sock";
                  };
                  vm = {
                    description = "a host commands' name";
                    path = "/srv/vm.sock";
                  };
                  neither.description = "no path, no glob";
                  both = {
                    description = "a path and a glob";
                    path = "/srv/a.sock";
                    bounding.vm = {
                      type = "string";
                      description = "the VM";
                      instances = "/srv/*.sock";
                    };
                  };
                  bus = {
                    description = "the session bus";
                    path = "$XDG_RUNTIME_DIR/bus";
                  };
                  system = {
                    description = "the system bus";
                    path = "/run/dbus/system_bus_socket";
                  };
                  all = {
                    description = "all of the runtime dir";
                    bounding.s = {
                      type = "string";
                      description = "a socket";
                      instances = "\${XDG_RUNTIME_DIR}/*";
                    };
                  };
                  control = {
                    description = "a launcher's control socket";
                    path = "/run/user/1000/claude-desktop/permissions-control.sock";
                  };
                  proxy = {
                    description = "nixpak's D-Bus proxy";
                    path = "$XDG_RUNTIME_DIR/nixpak-bus-1";
                  };
                  manager = {
                    description = "the systemd user manager";
                    path = "$XDG_RUNTIME_DIR/systemd/private";
                  };
                  managers = {
                    description = "the systemd user manager, by glob";
                    bounding.s = {
                      type = "string";
                      description = "a socket";
                      instances = "$XDG_RUNTIME_DIR/systemd/*";
                    };
                  };
                  atspi = {
                    description = "the accessibility bus";
                    path = "$XDG_RUNTIME_DIR/at-spi/bus_0";
                  };
                  procalias = {
                    description = "a /proc alias of the session bus";
                    path = "/proc/self/root/run/user/1000/bus";
                  };
                  varrun = {
                    description = "/var/run's alias of the session bus";
                    path = "/var/run/user/1000/bus";
                  };
                  dotted = {
                    description = "not clean";
                    path = "$XDG_RUNTIME_DIR/vms/../bus";
                  };
                  lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll = {
                    description = "a name too long for an address";
                    path = "/srv/l.sock";
                  };
                  anyvar = {
                    description = "a glob that could match /var/run";
                    bounding.s = {
                      type = "string";
                      description = "a socket";
                      instances = "/var/*/bus";
                    };
                  };
                  anyrun = {
                    description = "a glob that could match /run/dbus";
                    bounding.s = {
                      type = "string";
                      description = "a socket";
                      instances = "/run/*/x.sock";
                    };
                  };
                };
              };
            }
          )
        )
      );
      expected = map (m: "agent-sandbox.claude-desktop: launchers.work.permissions.sockets.${m}") [
        "a_b: a name of at most 80 letters, digits and - that no host commands have, and a path or one described string bounding argument with instances"
        "all: $XDG_RUNTIME_DIR/* is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets"
        "anyrun: /run/*/x.sock is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets"
        "anyvar: /var/*/bus is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets"
        "atspi: $XDG_RUNTIME_DIR/at-spi/bus_0 is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets"
        "both: a name of at most 80 letters, digits and - that no host commands have, and a path or one described string bounding argument with instances"
        "bus: $XDG_RUNTIME_DIR/bus is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets"
        "control: /run/user/1000/claude-desktop/permissions-control.sock is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets"
        "dotted: $XDG_RUNTIME_DIR/vms/../bus is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets"
        "lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll: a name of at most 80 letters, digits and - that no host commands have, and a path or one described string bounding argument with instances"
        "manager: $XDG_RUNTIME_DIR/systemd/private is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets"
        "managers: $XDG_RUNTIME_DIR/systemd/* is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets"
        "neither: a name of at most 80 letters, digits and - that no host commands have, and a path or one described string bounding argument with instances"
        "neither:  is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets"
        "procalias: /proc/self/root/run/user/1000/bus is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets"
        "proxy: $XDG_RUNTIME_DIR/nixpak-bus-1 is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets"
        "system: /run/dbus/system_bus_socket is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets"
        "varrun: /var/run/user/1000/bus is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets"
        "vm: a name of at most 80 letters, digits and - that no host commands have, and a path or one described string bounding argument with instances"
      ];
    };
    # Host commands the broker would refuse, caught at eval
    testCommandAssertions = {
      expr = map (a: a.message) (
        failedAssertions (
          nixos (
            lib.recursiveUpdate enabled {
              launchers.work.permissions = {
                broker.enable = true;
                commands.a_b = {
                  description = "bad name";
                  consent.title = "use it";
                  commands.c = {
                    description = "fine";
                    consent = "Do it";
                    run = [ "/bin/true" ];
                  };
                };
                commands.vm = {
                  description = "a VM";
                  consent.title = "use the VM";
                  bounding.vm.type = "string";
                  commands.ok = {
                    description = "a JSON result";
                    consent = "Read it";
                    result = "application/json";
                    run = [ "/bin/true" ];
                  };
                  commands.shot = {
                    description = "an argument named reason";
                    consent = "Take screenshots";
                    arguments.reason = {
                      type = "string";
                      description = "r";
                    };
                    run = [ "/bin/true" ];
                  };
                };
                # Without the user's words: no title, a command without its phrase, one on two lines, one too long
                commands.mute = {
                  description = "for Claude only";
                  commands.a = {
                    description = "no phrase";
                    run = [ "/bin/true" ];
                  };
                  commands.b = {
                    description = "two lines";
                    consent = "Look\nAllowed by the host";
                    run = [ "/bin/true" ];
                  };
                  commands.c = {
                    description = "too long";
                    consent = lib.concatStrings (lib.replicate 81 "x");
                    run = [ "/bin/true" ];
                  };
                  commands.d = {
                    description = "80 characters, fine";
                    consent = lib.concatStrings (lib.replicate 80 "x");
                    run = [ "/bin/true" ];
                  };
                  # Characters, not bytes, as the broker counts: Danish of 46 (49 bytes) and 80 (87 bytes), CJK of 80
                  # (240 bytes), all fine; CJK of 81 and Danish of 81 too long
                  commands.e = {
                    description = "Danish";
                    consent = "Læs og ret filer på din virtuelle maskine, Åse";
                    run = [ "/bin/true" ];
                  };
                  commands.f = {
                    description = "Danish at the cap";
                    consent = "Ændr, flyt og slet filer på den virtuelle maskine også når den kører, på én gang";
                    run = [ "/bin/true" ];
                  };
                  commands.g = {
                    description = "CJK at the cap";
                    consent = lib.concatStrings (lib.replicate 80 "画");
                    run = [ "/bin/true" ];
                  };
                  commands.h = {
                    description = "CJK past the cap";
                    consent = lib.concatStrings (lib.replicate 81 "画");
                    run = [ "/bin/true" ];
                  };
                  commands.i = {
                    description = "Danish past the cap";
                    consent = "Ændr, flyt og slet filer på den virtuelle maskine, også når den kører, på én gang";
                    run = [ "/bin/true" ];
                  };
                };
              };
            }
          )
        )
      );
      expected = [
        "agent-sandbox.claude-desktop: launchers.work.permissions.commands.a_b: a name of letters, digits and -, and at least one command"
        "agent-sandbox.claude-desktop: launchers.work.permissions.commands.mute: consent.title, for the user, one line of at most 80 characters"
        "agent-sandbox.claude-desktop: launchers.work.permissions.commands.mute.commands.a: consent, for the user, one line of at most 80 characters"
        "agent-sandbox.claude-desktop: launchers.work.permissions.commands.mute.commands.b: consent, for the user, one line of at most 80 characters"
        "agent-sandbox.claude-desktop: launchers.work.permissions.commands.mute.commands.c: consent, for the user, one line of at most 80 characters"
        "agent-sandbox.claude-desktop: launchers.work.permissions.commands.mute.commands.h: consent, for the user, one line of at most 80 characters"
        "agent-sandbox.claude-desktop: launchers.work.permissions.commands.mute.commands.i: consent, for the user, one line of at most 80 characters"
        "agent-sandbox.claude-desktop: launchers.work.permissions.commands.vm: every bounding argument needs a description, none may be named reason or lease, and none may be an array or multiline"
        "agent-sandbox.claude-desktop: launchers.work.permissions.commands.vm.commands.ok: a name of letters, digits and - (vm_ok at most 64 characters), every argument described, none named reason, lease or as a bounding one, and a result of text or image/*"
        "agent-sandbox.claude-desktop: launchers.work.permissions.commands.vm.commands.shot: a name of letters, digits and - (vm_shot at most 64 characters), every argument described, none named reason, lease or as a bounding one, and a result of text or image/*"
      ];
    };
    # S14 by every spelling: a bind's source is read as written, so it has to be the one spelling of its path, and
    # /proc and /var/run name every path of the host again. One trailing slash aside
    testBindSpellings = {
      expr = map (a: a.message) (
        failedAssertions (
          nixos (
            lib.recursiveUpdate enabled {
              permissions.binds."/srv/a".src = "/run/user//";
              permissions.binds."/srv/b".src = "/run/./user/1000";
              permissions.binds."/srv/c".src = "//run/user/1000";
              permissions.binds."/srv/d".src = "/home/alice/.local/share/claude-desktop/home/..";
              permissions.binds."/srv/e".src = "/home/alice/.local//share/claude-desktop-work";
              permissions.binds."/srv/f".src = ".local/share/claude-desktop-work";
              permissions.binds."/srv/g".src = "/var/run/user/1000";
              permissions.binds."/srv/h".src = "/proc/self/root/run/user/1000";
              permissions.binds."/srv/i".src = "/proc";
              # Clean but for its slash, and nothing no sandbox may reach
              permissions.binds."/srv/ok".src = "/srv/ok/";
              # Not bound
              permissions.binds."/srv/off" = {
                src = "/run/user//";
                enable = false;
              };
            }
          )
        )
      );
      expected =
        map
          (
            b:
            "agent-sandbox.claude-desktop: permissions.binds.${b}, which isn't an absolute path in its clean form (no ., .. or empty segments); the checks on what no sandbox may reach read it as written"
          )
          [
            ''"/srv/a" binds /run/user//''
            ''"/srv/b" binds /run/./user/1000''
            ''"/srv/c" binds //run/user/1000''
            ''"/srv/d" binds /home/alice/.local/share/claude-desktop/home/..''
            ''"/srv/e" binds /home/alice/.local//share/claude-desktop-work''
            ''"/srv/f" binds .local/share/claude-desktop-work''
          ]
        ++
          map
            (
              b:
              "agent-sandbox.claude-desktop: permissions.binds.${b}, which is /proc or /var/run or lies in one, where every path of the host has another name; no sandbox may reach those"
            )
            [
              ''"/srv/g" binds /var/run/user/1000''
              ''"/srv/h" binds /proc/self/root/run/user/1000''
              ''"/srv/i" binds /proc''
            ];
    };
    # S14 for devices, bound read-write from their own path: none that a bind's source may not be
    testStateDevices = {
      expr = map (a: a.message) (
        failedAssertions (
          nixos (
            lib.recursiveUpdate enabled {
              permissions.devices = {
                "/dev/nvidiactl" = { };
                "/run/user/1000" = { };
                "/home/alice/.local/share/claude-desktop-work" = { };
                "/dev/../run/user/1000" = { };
                "/proc/1/root" = { };
                # Not bound
                "/run/user/1001".enable = false;
              };
            }
          )
        )
      );
      expected = [
        ''agent-sandbox.claude-desktop: permissions.devices."/dev/../run/user/1000", which isn't an absolute path in its clean form (no ., .. or empty segments); the checks on what no sandbox may reach read it as written''
        ''agent-sandbox.claude-desktop: permissions.devices."/home/alice/.local/share/claude-desktop-work", which holds or lies in a launcher's state dir, or holds $XDG_RUNTIME_DIR or lies in its .flatpak or claude-desktop dir; no sandbox may reach those''
        ''agent-sandbox.claude-desktop: permissions.devices."/proc/1/root", which is /proc or /var/run or lies in one, where every path of the host has another name; no sandbox may reach those''
        ''agent-sandbox.claude-desktop: permissions.devices."/run/user/1000", which holds or lies in a launcher's state dir, or holds $XDG_RUNTIME_DIR or lies in its .flatpak or claude-desktop dir; no sandbox may reach those''
      ];
    };
    # A schema keyword the broker doesn't read (its schema package decodes leniently) would load and restrict nothing:
    # refused wherever a schema goes, as is a schema without a type of the broker's. Every keyword it has passes
    testSchemaKeywords = {
      expr = map (a: a.message) (
        failedAssertions (
          nixos (
            lib.recursiveUpdate enabled {
              launchers.work.permissions = {
                broker.enable = true;
                commands.vm = {
                  description = "a VM";
                  consent.title = "use the VM";
                  bounding.vm = {
                    type = "string";
                    description = "the VM";
                    const = "win11";
                  };
                  # No type: the broker refuses the schema
                  bounding.disk.description = "the disk";
                  commands.type = {
                    description = "typing";
                    consent = "Type text";
                    run = [ "/srv/type" ];
                    arguments.text = {
                      type = "string";
                      description = "the text";
                      maxlength = 10;
                      minLength = 1;
                    };
                    arguments.keys = {
                      type = "array";
                      description = "the keys";
                      items = {
                        type = "string";
                        format = "key";
                      };
                    };
                    arguments.flat = "string";
                  };
                };
                commands.all = {
                  description = "every keyword";
                  consent.title = "use every keyword";
                  bounding.vm = {
                    type = "string";
                    description = "the VM";
                    instances = "/srv/vms/*/console.sock";
                    maxLength = 20;
                    pattern = "[a-z]+";
                  };
                  commands.run = {
                    description = "running";
                    consent = "Run it";
                    run = [ "/srv/run" ];
                    arguments = {
                      n = {
                        type = "integer";
                        description = "a number";
                        minimum = 0;
                        maximum = 9;
                      };
                      s = {
                        type = "string";
                        description = "a string";
                        opaque = true;
                        enum = [ "a" ];
                      };
                      t = {
                        type = "string";
                        description = "lines";
                        multiline = true;
                      };
                      l = {
                        type = "array";
                        description = "a list";
                        maxItems = 3;
                        items.type = "boolean";
                      };
                    };
                  };
                };
                sockets.vms = {
                  description = "a console";
                  bounding.vm = {
                    type = "string";
                    description = "the VM";
                    instances = "/srv/vms/*/console.sock";
                    minLength = 1;
                  };
                };
              };
            }
          )
        )
      );
      expected =
        map
          (
            m:
            "agent-sandbox.claude-desktop: launchers.work.permissions.${m.at}: a schema of the broker's has a type of string, boolean, integer, number, array and of keywords type, description, opaque, multiline, maxLength, pattern, enum, minimum, maximum, items, maxItems, instances alone, any other it would ignore; not ${m.keys}"
          )
          [
            {
              at = "sockets.vms";
              keys = "vm.minLength";
            }
            {
              at = "commands.vm";
              keys = "disk.type, vm.const";
            }
            {
              at = "commands.vm.commands.type";
              keys = "flat.(not an object), keys.items.format, text.maxlength, text.minLength";
            }
          ]
        ++ [
          "agent-sandbox.claude-desktop: launchers.work.permissions.commands.vm.commands.type: a name of letters, digits and - (vm_type at most 64 characters), every argument described, none named reason, lease or as a bounding one, and a result of text or image/*"
        ];
    };
    # Host sockets the eval check took and the daemon refuses at its start, or reads as another path: ~ alone, a
    # variable past the leading one (the daemon expands any its environment has), no description, and an instances
    # glob that isn't one * without ? or [
    testSocketAgreement = {
      expr = map (a: a.message) (
        failedAssertions (
          nixos (
            lib.recursiveUpdate enabled {
              launchers.work.permissions = {
                broker.enable = true;
                sockets =
                  lib.mapAttrs
                    (_: instances: {
                      description = "by instance";
                      bounding.s = {
                        type = "string";
                        description = "a socket";
                        inherit instances;
                      };
                    })
                    {
                      glob-one = "/srv/socks/*.sock";
                      glob-two = "/srv/*/*.sock";
                      glob-mark = "/srv/*/?.sock";
                      glob-class = "/srv/*/[ab].sock";
                      glob-none = "/srv/a.sock";
                    }
                  // {
                    home = {
                      description = "below the home directory";
                      path = "~/.gnupg/S.gpg-agent";
                    };
                    tilde = {
                      description = "the home directory";
                      path = "~";
                    };
                    variable = {
                      description = "a variable the daemon would expand";
                      path = "/run/user/1000/\${EMPTY}bus";
                    };
                    variables = {
                      description = "the runtime dir twice";
                      path = "$XDG_RUNTIME_DIR/x/$XDG_RUNTIME_DIR/bus";
                    };
                    undescribed = {
                      description = "";
                      path = "/srv/a.sock";
                    };
                  };
              };
            }
          )
        )
      );
      expected = map (m: "agent-sandbox.claude-desktop: launchers.work.permissions.sockets.${m}") [
        "glob-class: instances is a glob with one * and no ? or [, on a string"
        "glob-mark: instances is a glob with one * and no ? or [, on a string"
        "glob-none: instances is a glob with one * and no ? or [, on a string"
        "glob-two: instances is a glob with one * and no ? or [, on a string"
        "tilde: ~ is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets"
        "undescribed: a description, which the consent names"
        "variable: /run/user/1000/\${EMPTY}bus is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets"
        "variables: $XDG_RUNTIME_DIR/x/$XDG_RUNTIME_DIR/bus is refused: a clean path, and nothing that is or could match a D-Bus bus, the systemd user manager, /proc, /var/run, $XDG_RUNTIME_DIR as a whole or the launchers' own sockets"
      ];
    };
    # Host commands the daemon refuses at its start (checkBounding, hostcmd's Check), caught at eval: instances on two
    # bounding arguments, on one that isn't a string, as a glob it doesn't take or on a free argument, no description,
    # nothing to run
    testCommandAgreement = {
      expr = map (a: a.message) (
        failedAssertions (
          nixos (
            lib.recursiveUpdate enabled {
              launchers.work.permissions = {
                broker.enable = true;
                commands =
                  lib.mapAttrs
                    (
                      _: c:
                      lib.recursiveUpdate {
                        description = "a VM";
                        consent.title = "use the VM";
                        commands.shot = {
                          description = "a screenshot";
                          consent = "Take screenshots";
                          run = [ "/srv/shot" ];
                        };
                      } c
                    )
                    {
                      ok.bounding.vm = {
                        type = "string";
                        description = "the VM";
                        instances = "$XDG_RUNTIME_DIR/vms/*/qmp.sock";
                      };
                      two.bounding = {
                        vm = {
                          type = "string";
                          description = "the VM";
                          instances = "/srv/vms/*";
                        };
                        disk = {
                          type = "string";
                          description = "the disk";
                          instances = "/srv/disks/*";
                        };
                      };
                      stars.bounding.vm = {
                        type = "string";
                        description = "the VM";
                        instances = "/srv/*/*";
                      };
                      number.bounding.vm = {
                        type = "integer";
                        description = "the VM";
                        instances = "/srv/vms/*";
                      };
                      free.commands.shot.arguments.screen = {
                        type = "string";
                        description = "the screen";
                        instances = "/srv/screens/*";
                      };
                      silent.commands.shot.description = "";
                      idle.commands.shot.run = lib.mkForce [ ];
                    };
              };
            }
          )
        )
      );
      expected = map (m: "agent-sandbox.claude-desktop: launchers.work.permissions.commands.${m}") [
        "free.commands.shot: a description, what it runs (run), and instances on bounding arguments only"
        "idle.commands.shot: a description, what it runs (run), and instances on bounding arguments only"
        "number: at most one bounding argument with instances, a glob with one * and no ? or [, on a string"
        "silent.commands.shot: a description, what it runs (run), and instances on bounding arguments only"
        "stars: at most one bounding argument with instances, a glob with one * and no ? or [, on a string"
        "two: at most one bounding argument with instances, a glob with one * and no ? or [, on a string"
      ];
    };
    # Standing grants the daemon refuses at its start (checkStanding), caught at eval: a parameter the capability
    # doesn't take, a value its bounding argument doesn't (type, enum, bounds, length; a pattern is the daemon's to
    # match), params that are no object, and one given twice, under two names
    testStandingGrantParams = {
      expr = map (a: a.message) (
        failedAssertions (
          nixos (
            lib.recursiveUpdate enabled {
              launchers.work.permissions = {
                broker.enable = true;
                commands.vm = {
                  description = "a VM";
                  consent.title = "use the VM";
                  bounding = {
                    vm = {
                      type = "string";
                      description = "the VM";
                      enum = [
                        "win11"
                        "win10"
                      ];
                    };
                    screen = {
                      type = "integer";
                      description = "the screen";
                      minimum = 0;
                      maximum = 3;
                    };
                    label = {
                      type = "string";
                      description = "a label";
                      maxLength = 4;
                    };
                  };
                  commands.shot = {
                    description = "a screenshot";
                    consent = "Take screenshots";
                    run = [ "/srv/shot" ];
                  };
                };
                sockets.agent = {
                  description = "an agent";
                  path = "/srv/agent.sock";
                };
                grants = {
                  vm-ok = {
                    capability = "vm";
                    params = {
                      vm = "win11";
                      screen = 3;
                      label = "æøå!";
                    };
                  };
                  # A bounding argument left out is a value of its own
                  vm = { };
                  agent = { };
                  vm-host = {
                    capability = "vm";
                    params.host = "desktop";
                  };
                  vm-range = {
                    capability = "vm";
                    params = {
                      vm = "win7";
                      screen = 4;
                      label = "label";
                    };
                  };
                  vm-types = {
                    capability = "vm";
                    params = {
                      vm = 11;
                      screen = "0";
                      label = "a\nb";
                    };
                  };
                  vm-list = {
                    capability = "vm";
                    params = [ "win11" ];
                  };
                  agent-param = {
                    capability = "agent";
                    params.socket = "other";
                  };
                  # The same grant under another name, twice over
                  agent-again.capability = "agent";
                  port = {
                    params = {
                      protocol = "tcp";
                      port = 3000;
                    };
                  };
                  port-again = {
                    capability = "port";
                    params = {
                      port = 3000;
                      protocol = "tcp";
                    };
                  };
                  # Off: the same grant once more, and not counted
                  port-off = {
                    enable = false;
                    capability = "port";
                    params = {
                      protocol = "tcp";
                      port = 3000;
                    };
                  };
                  port-string = {
                    capability = "port";
                    params = "tcp/3000";
                  };
                };
              };
            }
          )
        )
      );
      expected = map (m: "agent-sandbox.claude-desktop: launchers.work.permissions.grants${m}") [
        ".agent-param: the params of a agent grant are values of its bounding arguments (), each one its schema takes, not socket"
        ".port-string: the params of a port grant are protocol (tcp or udp) and port (1 to 65535)"
        ".vm-host: the params of a vm grant are values of its bounding arguments (label, screen, vm), each one its schema takes, not host"
        ''.vm-list: the params of a vm grant are values of its bounding arguments (label, screen, vm), each one its schema takes, not ["win11"]''
        ".vm-range: the params of a vm grant are values of its bounding arguments (label, screen, vm), each one its schema takes, not label, screen, vm"
        ".vm-types: the params of a vm grant are values of its bounding arguments (label, screen, vm), each one its schema takes, not label, screen, vm"
        ": agent, agent-again are the same grant, agent {}, which the broker takes only once"
        '': port, port-again are the same grant, port {"port":3000,"protocol":"tcp"}, which the broker takes only once''
      ];
    };
    testMcpServersHmTransform = {
      expr =
        let
          s = aliceMcp.agent-sandbox.claude-desktop.mcpServers;
        in
        {
          inherit (s) plain;
          secretWrapped = s.secret.command != "/srv/bin/secret" && !(s.secret ? env);
        };
      expected = {
        plain.command = "/srv/bin/plain";
        secretWrapped = true;
      };
    };
    testMcpServersNeedMcpEnable = {
      expr =
        lib.attrNames
          (withMcp { servers.plain.command = "/srv/bin/plain"; }).agent-sandbox.claude-desktop.mcpServers;
      expected = [
        "claude-code"
        "filesystem"
      ];
    };
    testMcpServersAssertion = {
      expr = map (a: a.message) (
        lib.filter (a: !a.assertion)
          (withMcp {
            enable = true;
            servers = {
              remote.url = "https://example.com/mcp";
              filesystem.command = "/srv/bin/fs";
            };
          }).assertions
      );
      expected =
        map
          (
            n:
            "agent-sandbox.claude-desktop: programs.mcp.servers.${n} must be a local server (command) and not named filesystem or claude-code, which are the sandbox's own"
          )
          [
            "filesystem"
            "remote"
          ];
    };
  };
  requestSend = import ./request-send.nix {
    inherit pkgs nixos;
    broker = self.packages.${pkgs.stdenv.hostPlatform.system}.permissions-broker;
    requestSend = self.packages.${pkgs.stdenv.hostPlatform.system}.request-send;
  };
  # The VM test's parts as vm-<part>, and vm, which builds them all
  vmParts = import ./vm {
    inherit pkgs aliceModule dbusProxy;
    broker = self.packages.${pkgs.stdenv.hostPlatform.system}.permissions-broker;
  };
  # The host side of the sandbox network, on machines of its own
  vmAll = vmParts // {
    uplink = import ./uplink.nix {
      inherit pkgs;
      module = self.nixosModules.claude-desktop;
    };
  };
  vmChecks = lib.mapAttrs' (part: lib.nameValuePair "vm-${part}") vmAll // {
    vm = pkgs.linkFarm "vm-tests" vmAll;
  };
  # vm-loop at 100 launches, for CI: the flake check's 20 keep a local run short
  vmLoopFull =
    (import ./vm {
      inherit pkgs aliceModule dbusProxy;
      broker = self.packages.${pkgs.stdenv.hostPlatform.system}.permissions-broker;
      launches = 100;
    }).loop;
in
{
  tests = evalTests // requestSend.tests;
  inherit vmLoopFull;

  checks = vmChecks // {
    inherit (self.packages.${pkgs.stdenv.hostPlatform.system})
      netns-netkit
      sandbox-hooks
      sandbox-uplink
      subid-broker
      dbus-proxy
      permissions-broker
      permissions-window
      request-send
      ;

    # S12 over the Go sources of every binary (nix/checks/execsites), which no package's own build holds together: no
    # exec with capabilities in a sandbox namespace resolves where the sandbox swaps directories
    host-execs =
      pkgs.runCommand "host-execs-check"
        {
          nativeBuildInputs = [ pkgs.go ];
          src = lib.fileset.toSource {
            root = ../..;
            fileset = lib.fileset.unions [
              ../../go.mod
              ../../go.sum
              ../../cmd
              ../../internal
              ./execsites
            ];
          };
        }
        ''
          export HOME=$TMPDIR GOPROXY=off GOTOOLCHAIN=local
          cd $src
          # The standard library alone: no module to fetch
          go test ./nix/checks/execsites/
          touch $out
        '';

    # The user units' build taking a calendar spec of the user's and refusing one systemd can't parse, by the timer and
    # the spec
    timer-calendar =
      let
        units =
          frequency:
          (nixos (enabled // { storeGc.frequency = frequency; }))
          .config.home-manager.users.alice.agent-sandbox.claude-desktop.build.userUnitsDir;
      in
      pkgs.runCommand "timer-calendar-check"
        {
          good = units "Mon *-*-* 04:00";
          failed = pkgs.testers.testBuildFailure (units "weakly");
        }
        ''
          grep -qxF "OnCalendar=Mon *-*-* 04:00" "$good/claude-desktop-store-gc.timer" ||
            { echo "the GC timer: $(<"$good/claude-desktop-store-gc.timer")" >&2; exit 1; }
          grep -qF "claude-desktop-store-gc.timer: OnCalendar=weakly isn't a calendar spec systemd parses" "$failed/testBuildFailure.log" ||
            { echo "the user units built with OnCalendar=weakly: $(<"$failed/testBuildFailure.log")" >&2; exit 1; }
          touch $out
        '';

    # nix-unit evaluates this flake again inside the build, which can't fetch, so every input (theirs too) comes from
    # the store
    claude-desktop-eval =
      let
        overrides =
          prefix: inputs':
          lib.concatLists (
            lib.mapAttrsToList (
              name: input:
              [
                "--override-input"
                "${prefix}${name}"
                "${input}"
              ]
              ++ overrides "${prefix}${name}/" (input.inputs or { })
            ) inputs'
          );
      in
      pkgs.runCommand "claude-desktop-eval" { nativeBuildInputs = [ pkgs.nix-unit ]; } ''
        export HOME=$PWD
        unset NIX_STORE
        export NIX_STORE_DIR=${builtins.storeDir} NIX_REMOTE=$HOME/storedata
        # The stack nix gives its evaluator and nix-unit doesn't; 8 MiB overflows
        ulimit -s 61440
        nix-unit --extra-experimental-features flakes ${
          lib.escapeShellArgs (overrides "" (removeAttrs inputs [ "self" ]))
        } --flake ${self}#tests.${pkgs.stdenv.hostPlatform.system}
        touch $out
      '';

    # Builds the sandboxed app (the patched asar and the scripts check themselves while building)
    # and checks what the sandbox gets from the config
    claude-desktop =
      pkgs.runCommand "claude-desktop-check"
        {
          nativeBuildInputs = [
            pkgs.jq
            pkgs.util-linux
          ];
          closure = pkgs.closureInfo { rootPaths = [ sandboxed ]; };
          workClosure = pkgs.closureInfo { rootPaths = [ work ]; };
          inherit work;
          customClosure = pkgs.closureInfo { rootPaths = [ customDoc ]; };
          inherit asarPatch;
        }
        ''
          paths=$closure/store-paths
          doc=$(grep -- '-claude-environment\.md$' "$paths")
          # The static part is linked, so the sandbox needs it in its store. All of it without memo, markers dropped
          import=$(grep -oxP '@\K/nix/store/[^/]+-claude-desktop-environment/environment\.md' "$doc") || { echo "environment.md lacks the import" >&2; exit 1; }
          grep -qxF -- "''${import%/*}" "$paths" || { echo "$import is not in the closure" >&2; exit 1; }
          grep -qxF '# Your environment: the Claude Desktop sandbox' "$import" || { echo "$import is not the module's environment.md" >&2; exit 1; }
          grep -qxF '## Nix' "$import" || { echo "$import lacks the sections memo would load" >&2; exit 1; }
          ! grep -qF '<!-- memo' "$import" || { echo "$import keeps the memo markers" >&2; exit 1; }
          custom=$(grep -- '-claude-environment\.md$' "$customClosure/store-paths")
          grep -qxP '@/nix/store/[^/]+-custom-environment\.md' "$custom" || { echo "environmentFile is not imported" >&2; exit 1; }
          for line in \
            '- `/srv/project` (rw, MCP)' \
            '- `/srv/docs` (ro, MCP)' \
            '- `/home/alice/.claude` (rw, MCP, from `/srv/claude`)' \
            '- `/nix` (rw, from `/home/alice/.local/share/claude-desktop/nix`)' \
            '- `/nix/store` (rw, from `/home/alice/.local/share/claude-desktop/nix/store`)' \
            '- `/tmp/claude-<uid>` (rw, from `/home/alice/.local/share/claude-desktop/tmp-scratchpad`): Claude Code'"'"'s temp dir with the session scratchpads' \
            '- `/dev/kvm` (dev, if present)' \
            '- `/dev/nvidiactl` (dev, if present)' \
            '`/srv/bin`, then the packages'; do
            grep -qxF -- "$line" "$doc" || { echo "environment.md lacks: $line" >&2; exit 1; }
          done
          (( $(grep -cF '`/dev/kvm`' "$doc") == 1 )) || { echo "environment.md lists /dev/kvm twice" >&2; exit 1; }
          ! grep -F /srv/hidden "$doc" || { echo "environment.md lists the non-MCP ro bind" >&2; exit 1; }
          grep -qE '^coreutils, .*, nix, systemd\.$' "$doc" || { echo "environment.md lacks the PATH packages" >&2; exit 1; }

          # nixpak's launcher starts our D-Bus proxy: the dbusProxy wrapper in its config runs the module's dbus-proxy,
          # and xdg-dbus-proxy isn't in the closure
          configs=$(grep -E -- '-nixpak-config\.json$' "$paths") || { echo "no nixpak launcher config" >&2; exit 1; }
          for c in $configs; do
            exe=$(jq -er '.dbusProxy.exe' "$c") || { echo "$c starts no D-Bus proxy" >&2; exit 1; }
            # In nixpak's bwrap, our wrapper, which logs the proxy into the host side's journal namespace
            inner=$(grep -oE '/nix/store/[^ ]+-xdg-dbus-proxy/bin/xdg-dbus-proxy' "$exe") || { echo "$exe runs no proxy wrapper" >&2; exit 1; }
            grep -qF -- '--identifier=dbus-proxy -- ${dbusProxy}/bin/dbus-proxy "$@"' "$inner" ||
              { echo "$inner doesn't run ${dbusProxy} through systemd-cat" >&2; exit 1; }
          done
          ! grep -qxF -- "${pkgs.xdg-dbus-proxy}" "$paths" || { echo "xdg-dbus-proxy is in the closure" >&2; exit 1; }
          # nixpak's launcher is the one nixpak-launcher-reaper.patch made: its reaper has Start (a Go binary keeps its
          # functions' names, stripped too), and no other launcher is in either closure
          for c in "$paths" "$workClosure/store-paths"; do
            nl=$(grep -E -- '-nixpak-launcher-[^/]*$' "$c")
            [[ $(wc -l <<<"$nl") == 1 ]] || { echo "nixpak launchers in the closure: $nl" >&2; exit 1; }
            grep -qaF 'main.(*ChildReaper).Start' "$nl/bin/launcher" || { echo "$nl is nixpak's launcher without the reaper patch" >&2; exit 1; }
          done

          # The tray icon by the colour scheme, also on GNOME (an asar stores its files as they are)
          asar=$(grep -- '-claude-desktop-app\.asar$' "$paths")
          ! grep -qaE '\(\)==="gnome"\|\|[A-Za-z0-9_$.]+\.shouldUseDarkColors\?"TrayIconLinux-Dark\.png"' "$asar" ||
            { echo "the asar picks the white tray icon on GNOME" >&2; exit 1; }
          grep -qaE '[A-Za-z0-9_$]\.shouldUseDarkColors\?"TrayIconLinux-Dark\.png":"TrayIconLinux\.png"' "$asar" ||
            { echo "the asar lost the tray icon's colour scheme check" >&2; exit 1; }

          # app-pid.sh drops the FHS env's ambient capabilities on the way to the app, also when it can't set the pid:
          # here, in a user namespace of its own with every capability ambient, but none over the build's pid ns
          appPid=$(grep -- '-claude-desktop-app-pid$' "$paths")/bin/claude-desktop-app-pid
          caps=$(unshare --user --map-user=1000 --keep-caps "$appPid" grep -E '^Cap(Eff|Amb):' /proc/self/status)
          [[ $(grep -c ':\s*0*$' <<<"$caps") == 2 ]] || { echo "the app keeps capabilities: $caps" >&2; exit 1; }
          # And when it can, in a pid ns that user namespace owns: the app at its pid, and neither it nor the shell
          # that started it and waits for it (app-run.sh, its parent) with a capability left (L4)
          got=$(unshare --user --map-user=1000 --keep-caps --pid --fork --mount --mount-proc "$appPid" \
            bash -c 'echo "pid $$"; grep -HE "^Cap(Inh|Prm|Eff|Amb):" /proc/self/status "/proc/$PPID/status"' 2>/dev/null)
          [[ $(head -n1 <<<"$got") == "pid 100" ]] || { echo "the app isn't at its pid: $got" >&2; exit 1; }
          [[ $(grep -c "^/proc/1/status:Cap" <<<"$got") == 4 && $(grep -c ':\s*0*$' <<<"$got") == 8 ]] ||
            { echo "the app or the script that waits for it keeps capabilities: $got" >&2; exit 1; }

          args=$(grep -- '-bwrap-args\.json$' "$paths")
          # The args as consecutive elements of bwrap's argv
          has() { jq -e '. as $a | $ARGS.positional as $p | any(range(length); $a[.:. + ($p | length)] == $p)' --args -- "$@" <"$args" >/dev/null; }
          need() { has "$@" || { echo "bwrap args lack: $*" >&2; exit 1; }; }
          need --unshare-net
          # nixpak adds it when pasta (the netns setup's slot) is off, and it wins over --unshare-net
          ! has --share-net || { echo "bwrap args share the host's network" >&2; exit 1; }
          need --bind-try /srv/project /srv/project
          need --ro-bind-try /srv/docs /srv/docs
          need --ro-bind-try /srv/hidden /srv/hidden
          need --bind-try /home/alice/.local/share/claude-desktop/nix /nix
          # The store dir on its own, after /nix, so the sandbox can't rename it
          need --bind-try /home/alice/.local/share/claude-desktop/nix/store /nix/store
          jq -e 'index("/nix") < index("/nix/store")' "$args" >/dev/null || { echo "bwrap args bind /nix/store before /nix" >&2; exit 1; }
          need --bind-try /srv/claude /home/alice/.claude
          need --dev-bind-try /dev/kvm /dev/kvm
          need --dev-bind-try /dev/nvidiactl /dev/nvidiactl
          (( $(jq '[.[] | select(. == "/dev/kvm")] | length' "$args") == 2 )) || { echo "bwrap args bind /dev/kvm twice" >&2; exit 1; }
          # After the /tmp tmpfs, the uid filled in by nixpak's launcher
          has --tmpfs /tmp || { echo "bwrap args lack the /tmp tmpfs" >&2; exit 1; }
          jq -e '. as $a | (index("--tmpfs") + 1) as $t | any(range($t; length); $a[.:. + 3] == ["--dev-bind-try",
            "/home/alice/.local/share/claude-desktop/tmp-scratchpad", {type: "concat", a: "/tmp/claude-", b: {type: "uid"}}])' \
            <"$args" >/dev/null || { echo "bwrap args lack the scratchpad bind after the /tmp tmpfs" >&2; exit 1; }

          # The files, in the FHS env's bwrap, the directory before the file in it. What they reference is in the closure
          fhs=$(grep -P -- '-claude-desktop-[^/]+-bwrap$' "$paths")
          dir=$(grep -nP -- '^\s*--ro-bind /nix/store/[^/ ]+-other /etc/agent-sandbox-test$' "$fhs") || { echo "the FHS env lacks the directory's bind" >&2; exit 1; }
          file=$(grep -nP -- '^\s*--ro-bind /nix/store/[^/ ]+-hello /etc/agent-sandbox-test/hello$' "$fhs") || { echo "the FHS env lacks the file's bind" >&2; exit 1; }
          (( ''${dir%%:*} < ''${file%%:*} )) || { echo "the file's bind comes before its directory's" >&2; exit 1; }
          hello=$(<"$(grep -oP -- '--ro-bind \K\S+' <<<"$file")")
          [[ $hello == ${lib.getExe pkgs.hello} ]] || { echo "the file holds $hello" >&2; exit 1; }
          grep -qxF -- "${pkgs.hello}" "$paths" || { echo "what the file references is not in the closure" >&2; exit 1; }
          ! grep -qF /srv/off "$fhs" || { echo "the FHS env binds the disabled file" >&2; exit 1; }

          # The work launcher: its own state dir, app ID and MAC, ~/.claude in its home, its own .desktop file
          [[ $(ls $work/bin) == claude-desktop-work ]] || { echo "work has more than its wrapper: $(ls $work/bin)" >&2; exit 1; }
          # A launcher's config, which its wrapper runs the Go launcher with
          configOf() {
            local w
            w=$(readlink -f "$1")
            grep -qF '${
              lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.launcher
            } start --config=' "$w" ||
              { echo "$1 doesn't run the launcher" >&2; exit 1; }
            grep -oP -- '--config=\K/nix/store/\S+\.json' "$w"
          }
          wcfg=$(configOf $work/bin/claude-desktop-work)
          dcfg0=$(configOf ${sandboxed}/bin/claude-desktop)
          # The launchers' slices: the app as a unit of the launcher's in its own, the broker and its calls as units of
          # their own there. The app's unit runs nixpak's launcher, waiting for the app's ready line, with a splash
          jq -e '.appId == "com.anthropic.Claude.work" and .launcher == "work"
            and .homeDirs == ["/home/alice/.local/share/claude-desktop-work/home"]
            and .storeRootsLink == "store-roots-work" and .slice == "claude\\x2ddesktop\\x2dwork.slice"
            and .unit == "claude-desktop-work-app.service" and (.nixpakLauncher | test("^/nix/store/[^/]+-nixpak-"))
            and .ready == "agent-sandbox: ready" and (.splash[0] | endswith("/bin/sandbox-splash"))
            and .splash[1] == "--title=Claude (work)"' "$wcfg" >/dev/null || { echo "work's launcher config: $(<"$wcfg")" >&2; exit 1; }
          jq -e '.slice == "claude\\x2ddesktop.slice" and .launcher == "" and .permissions == null
            and any(.splash[]; test("^--agent-logo=/nix/store/.+/share/icons/hicolor/256x256/apps/claude-desktop\\.png$"))
            and any(.splash[]; test("^--logo=/nix/store/[^/]+-orbit-landskab-farve\\.svg$"))
            and any(.splash[]; test("^--logo-dark=/nix/store/[^/]+-orbit-landskab-farve-negativ\\.svg$"))' \
            "$dcfg0" >/dev/null || { echo "the default launcher's config: $(<"$dcfg0")" >&2; exit 1; }
          # The asar prints the ready line once one of its windows is visible, loaded or shown
          grep -qaF '!w.isVisible()||(d=!0,o("agent-sandbox: ready"+String.fromCharCode(10)))};require("electron").app.on("browser-window-created"' "$asar" ||
            { echo "the asar lacks the ready line" >&2; exit 1; }
          # The sandbox's systemd --user's units: its timers and path unit wanted, the units option's too, none of
          # systemd's own sockets
          units=$(grep -- '-claude-desktop-user-units$' "$paths")
          for u in timers.target.wants/claude-desktop-store-gc.timer timers.target.wants/claude-desktop-scratchpad-prune.timer \
            paths.target.wants/claude-desktop-store-gc.path default.target \
            agent-sandbox-test.service timers.target.wants/agent-sandbox-test.timer; do
            [[ -e $units/$u ]] || { echo "the user units lack $u: $(ls -R "$units")" >&2; exit 1; }
          done
          [[ ! -e $units/sockets.target.wants ]] || { echo "the user units want systemd's sockets" >&2; exit 1; }
          # What the launcher writes in its home, confined to the directories in HOME_DIRS
          workState=$(grep -- '-claude-desktop-work-state-inner$' "$workClosure/store-paths")/bin/claude-desktop-work-state-inner
          for line in \
            "readonly DOT_CLAUDE=/home/alice/.local/share/claude-desktop-work/home/.claude" \
            "readonly CONFIG=/home/alice/.local/share/claude-desktop-work/home/.config/Claude/claude_desktop_config.json"; do
            grep -qxF -- "$line" "$workState" || { echo "work's state script lacks: $line" >&2; exit 1; }
          done
          # The permissions MCP server's host commands: what the sandbox may call, not what runs on the host
          workMcp=$(grep -oP '^readonly MCP_SERVERS=\K\S+' "$workState")
          jq -e '.[0].name == "vm" and .[0].commands.shot.result == "image/png" and (.[0].commands.shot | has("run") or has("consent") | not) and (.[0] | has("consent") | not)' \
            "$(jq -r '.permissions.args[2]' "$workMcp")" >/dev/null || { echo "work's MCP host commands are off" >&2; exit 1; }
          # The default launcher's ~/.claude is bound from /srv/claude, its ~/.config/Claude from the host's
          jq -e '.homeDirs == ["/home/alice/.local/share/claude-desktop/home", "/srv/claude", "/home/alice/.config/Claude"]' \
            "$dcfg0" >/dev/null || { echo "the default launcher's homeDirs are wrong" >&2; exit 1; }
          # The name netns-netkit derives the addresses from
          # nixpak's bwrap, the launcher's mode subid, whose --net names it; the FHS env's, mode parent, has no --net
          name() {
            local b
            for b in $(grep -- '-bwrap$' "$1"); do
              [[ -x $b/bin/bwrap ]] && grep -q -- '--mode=subid' "$b/bin/bwrap" || continue
              grep -oP -- "'--net=\K[^']*" "$b/bin/bwrap" | jq -r '.name // ""'
            done
          }
          [[ $(name "$paths") == "" && $(name "$workClosure/store-paths") == "work" ]] ||
            { echo "nixpak's bwrap's --net doesn't name work for work and nothing for the default launcher" >&2; exit 1; }
          for c in "$paths" "$workClosure/store-paths"; do
            [[ $(for b in $(grep -- '-bwrap$' "$c"); do grep -l -- '--mode=subid' "$b/bin/bwrap" 2>/dev/null; done | wc -l) == 1 ]] ||
              { echo "not one nixpak bwrap in mode subid in $c" >&2; exit 1; }
          done
          doc=$(grep -- '-claude-environment\.md$' "$workClosure/store-paths")
          for line in \
            '- `/srv/work` (rw, MCP)' \
            '- `/home/alice` (rw, from `/home/alice/.local/share/claude-desktop-work/home`)'; do
            grep -qxF -- "$line" "$doc" || { echo "work's environment.md lacks: $line" >&2; exit 1; }
          done
          ! grep -qF -e /srv/project -e /home/alice/.claude "$doc" || { echo "work's environment.md has the default launcher's binds" >&2; exit 1; }
          # work has memo: the part every session needs, the rest in the store, memo's config with the store after the
          # embedded ones
          import=$(grep -oxP '@\K/nix/store/[^/]+-claude-desktop-environment/core-environment\.md' "$doc") || { echo "work's environment.md lacks the core import" >&2; exit 1; }
          ! grep -qxF -e '## Nix' -e '## Home' "$import" || { echo "$import has the sections memo loads" >&2; exit 1; }
          grep -qF 'More loads through memo when the work touches it: Home (`topic=sandbox`)' "$import" || { echo "$import lacks the pointer to memo" >&2; exit 1; }
          fhs=$(grep -P -- '-claude-desktop-[^/]+-bwrap$' "$workClosure/store-paths")
          memo=$(grep -oP -- '--ro-bind \K\S+(?= /home/alice/\.config/agent-memos/config\.yaml$)' "$fhs") || { echo "work's FHS env lacks memo's config" >&2; exit 1; }
          stores=$(grep '^- ' "$memo" | tr '\n' ' ')
          [[ $stores =~ ^'- embed:core - embed:docs - '(/nix/store/[^/ ]+-claude-desktop-environment/environment\.memo)' - /srv/team.memo '$ ]] ||
            { echo "memo's stores in the sandbox: $stores" >&2; exit 1; }
          store=''${BASH_REMATCH[1]}
          grep -qxF "$(dirname "$store")" "$workClosure/store-paths" || { echo "work's closure lacks $store" >&2; exit 1; }
          for line in '-- nix/pragmas --' 'filter=topic={nix,sandbox}' 'topic=sandbox # The sandbox you run in: its home, what survives a restart, its namespaces' 'unix=environment' 'echo environment=bwrap'; do
            grep -qxF -- "$line" "$store" || { echo "$store lacks: $line" >&2; exit 1; }
          done
          # work has the permissions broker: its grant directory read-only at /run/permissions, its config, the daemon
          # started by the wrapper; the default launcher has none of it
          workArgs=$(grep -- '-bwrap-args\.json$' "$workClosure/store-paths")
          jq -e 'any(.[]; . == "/run/permissions")' "$workArgs" >/dev/null &&
            jq -e '. as $a | any(range(length); $a[.] == "--ro-bind-try" and $a[. + 2] == "/run/permissions")' "$workArgs" >/dev/null ||
            { echo "work's bwrap args lack the read-only /run/permissions" >&2; exit 1; }
          ! jq -e 'any(.[]; . == "/run/permissions")' "$args" >/dev/null || { echo "the default launcher binds /run/permissions" >&2; exit 1; }
          jq -e '.permissions.dir == "permissions-work" and .permissions.unit == "claude-desktop-work-permissions"' "$wcfg" >/dev/null ||
            { echo "work's launcher config lacks the broker" >&2; exit 1; }
          pcfg=$(jq -r .permissions.config "$wcfg")
          jq -e '.appId == "com.anthropic.Claude.work" and .launcher == "work" and .agent == "Claude"
            and .grantDir == "${"$"}{XDG_RUNTIME_DIR}/claude-desktop/permissions-work"
            and .controlSocket == "${"$"}{XDG_RUNTIME_DIR}/claude-desktop/permissions-work-control.sock"
            and .unit == "claude-desktop-work-permissions.service"
            and .slice == "claude\\x2ddesktop\\x2dwork.slice"
            and .sandboxGrantDir == "/run/permissions"
            and .window[1] == "--app-id=com.anthropic.Claude.work"
            and .window[2] == "${"$"}{XDG_RUNTIME_DIR}/claude-desktop/permissions-work-control.sock"
            and .window[3] == "Claude permissions (work)"
            and .denied == ["/home/alice/.local/share/claude-desktop", "/home/alice/.local/share/claude-desktop-work",
              "${"$"}{XDG_RUNTIME_DIR}"]
            and .folders == [{path: "/srv/notes", rw: false}] and (has("plugins") | not)
            and .sockets == [{name: "agent", description: "an agent", path: "$XDG_RUNTIME_DIR/agent.sock", bounding: {}}]
            and .grants == [{capability: "agent", params: {}}, {capability: "vm", params: {vm: "win11"}},
              {capability: "port", params: {protocol: "tcp", port: 8081}}]
            and .netnsNetkit == "/run/wrappers/bin/netns-netkit"
            and .commands == [{name: "vm", description: "a VM", consent: {title: "use the VM"}, exclusive: false,
              bounding: {vm: {type: "string", description: "the VM"}}, commands: {shot: {description: "a screenshot",
              consent: "Take screenshots", arguments: {}, result: "image/png", timeout: "PT1M", run: ["/srv/shot"]}}}]
            and (.overview.network | startswith("Its own network namespace"))
            and any(.overview.binds[]; .path == "/home/alice" and .src == "/home/alice/.local/share/claude-desktop-work/home" and .rw)
            and .overview.devices == []
            and (.overview.dbus["org.freedesktop.portal.Desktop"] | (.call | length) == 5 and .broadcast == ["org.freedesktop.portal.Settings.SettingChanged@/org/freedesktop/portal/desktop"]
              and .versions == {"org.freedesktop.portal.FileChooser@/org/freedesktop/portal/desktop": 1} and (has("policy") | not))
            and any(.overview.implicit[]; . == "Sockets: Wayland")
            and any(.overview.implicit[]; startswith("GPU: /dev/dri"))' "$pcfg" >/dev/null || { echo "work's broker config: $(<"$pcfg")" >&2; exit 1; }
          # No live D-Bus layer: no proxy takes rules from the broker, and no system-bus proxy or /run/dbus
          for a in "$args" "$workArgs"; do
            ! jq -e 'any(.[]; . == "/run/dbus")' "$a" >/dev/null || { echo "$a binds /run/dbus" >&2; exit 1; }
          done
          # The proxy's argv: the bus address, the socket, the module's config and --filter (nixpak adds --fd=3); work's
          # config, without a tray, the portal's rules, as its overview shows them
          for c in "$paths" "$workClosure/store-paths"; do
            a=$(grep -- '-xdg-dbus-proxy-args\.json$' "$c")
            jq -e 'length == 4 and (.[2] | test("^--config=/nix/store/[^/]+-dbus-proxy(-work)?\\.json$")) and .[3] == "--filter"' "$a" >/dev/null ||
              { echo "the proxy's argv: $(<"$a")" >&2; exit 1; }
          done
          dcfg=$(jq -r '.[2] | ltrimstr("--config=")' "$(grep -- '-xdg-dbus-proxy-args\.json$' "$workClosure/store-paths")")
          jq -e 'keys == ["org.freedesktop.portal.Desktop"]' "$dcfg" >/dev/null || { echo "work's D-Bus config: $(<"$dcfg")" >&2; exit 1; }
          jq -e --slurpfile o <(jq .overview.dbus "$pcfg") '. == $o[0]' "$dcfg" >/dev/null ||
            { echo "work's overview doesn't show its D-Bus config" >&2; exit 1; }
          jq -e 'has("dbus") or has("dbusControl") | not' "$pcfg" >/dev/null ||
            { echo "work's broker config has D-Bus capabilities: $(<"$pcfg")" >&2; exit 1; }
          # Each launcher's app ID names its .desktop file, the only one it installs, its StartupWMClass and its
          # windows' app ID, which Electron takes from desktopName (an asar stores its files as they are): the
          # portal names the app's notifications by the ID in /.flatpak-info, and gnome-shell drops them unless
          # <ID>.desktop exists
          same_id() {
            local pkg=$1 bin=$2 c=$3 id=$4 apps
            jq -e --arg id "$id" '.appId == $id' "$(configOf "$pkg/bin/$bin")" >/dev/null || { echo "$bin's appId isn't $id" >&2; exit 1; }
            grep -qxF "name=$id" "$(grep -- '-flatpak-shim-info$' "$c")" || { echo "$bin's /.flatpak-info doesn't name $id" >&2; exit 1; }
            apps=$(ls "$pkg/share/applications")
            [[ $apps == "$id.desktop" ]] || { echo "$bin's .desktop files: $apps" >&2; exit 1; }
            [[ $(grep '^StartupWMClass=' "$pkg/share/applications/$id.desktop") == "StartupWMClass=$id" ]] ||
              { echo "$bin's StartupWMClass isn't $id" >&2; exit 1; }
            grep -qaF "\"desktopName\": \"$id.desktop\"" "$(grep -- '-claude-desktop-app\.asar$' "$c")" ||
              { echo "$bin's asar lacks the desktopName $id.desktop" >&2; exit 1; }
          }
          same_id ${sandboxed} claude-desktop "$paths" com.anthropic.Claude
          same_id $work claude-desktop-work "$workClosure/store-paths" com.anthropic.Claude.work
          # The default launcher keeps the claude:// handler and upstream's actions, and lacks the Permissions action
          d=${sandboxed}/share/applications/com.anthropic.Claude.desktop
          for line in 'Name=Claude' 'Exec=claude-desktop %U' 'Name=New chat' 'Name=New shell'; do
            grep -qxF -- "$line" "$d" || { echo "$d lacks: $line" >&2; exit 1; }
          done
          grep -q '^MimeType=x-scheme-handler/claude' "$d" || { echo "$d lacks the claude:// handler" >&2; exit 1; }
          ! grep -q '^Name=Permissions$' "$d" || { echo "the default launcher has the Permissions action" >&2; exit 1; }
          # Its actions run the launcher by name, as its Exec does: a cached .desktop file keeps running the current one
          grep -qx 'Exec=/nix/store/[^ ]*/bin/xdg-terminal-exec claude-desktop --shell' "$d" ||
            { echo "$d's shell action doesn't run claude-desktop by name" >&2; exit 1; }
          ! grep -q '^Exec=/nix/store/[^ ]*/bin/claude-desktop' "$d" || { echo "$d runs a store path" >&2; exit 1; }
          d=$work/share/applications/com.anthropic.Claude.work.desktop
          for line in 'Name=Claude (work)' 'Exec=claude-desktop-work %U' 'Exec=claude-desktop-work claude://claude.ai/new' 'Name=New shell' 'Name=Permissions' 'Exec=claude-desktop-work --permissions'; do
            grep -qxF -- "$line" "$d" || { echo "$d lacks: $line" >&2; exit 1; }
          done
          ! grep -q -e '^MimeType=' -e '^Exec=claude-desktop ' "$d" || { echo "$d keeps the claude:// handler or the default Exec" >&2; exit 1; }
          grep -qx 'Exec=/nix/store/[^ ]*/bin/xdg-terminal-exec claude-desktop-work --shell' "$d" ||
            { echo "$d's shell action doesn't run claude-desktop-work by name" >&2; exit 1; }
          ! grep -q '^Exec=/nix/store/[^ ]*/bin/claude-desktop' "$d" || { echo "$d runs a store path" >&2; exit 1; }
          touch $out
        '';

    request-send-module = requestSend.check;

    scripts = pkgs.runCommand "scripts-check" { nativeBuildInputs = [ pkgs.shellcheck ]; } ''
      shellcheck ${../../scripts}/*.sh ${../home/claude-desktop}/*.sh
      touch $out
    '';
  };
}
