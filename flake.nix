{
  description = "Sandboxes for AI agents on NixOS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    # Only for the checks' test system
    home-manager = {
      url = "github:nix-community/home-manager/release-26.05";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixpak = {
      url = "github:nixpak/nixpak";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # Its own nixpkgs-unstable: it's only built and tested against that, and breaks on a stable release
    llm-agents.url = "github:numtide/llm-agents.nix";
    # NAT for the sandbox network (nix/packages/einat)
    einat = {
      url = "github:EHfive/einat-ebpf";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, nixpkgs, ... }@inputs:
    let
      forAllSystems = nixpkgs.lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
      checksFor =
        system:
        import ./nix/checks {
          inherit self inputs;
          pkgs = nixpkgs.legacyPackages.${system};
        };
    in
    {
      # Keyed, so a configuration that imports them twice (directly and through another flake's module) gets them once
      homeModules.claude-desktop = {
        key = "agent-sandbox#homeModules.claude-desktop";
        imports = [ (import ./nix/home/claude-desktop { inherit inputs; }) ];
      };
      nixosModules.claude-desktop = {
        key = "agent-sandbox#nixosModules.claude-desktop";
        imports = [ (import ./nix/nixos/claude-desktop.nix { inherit self; }) ];
      };
      packages = forAllSystems (system: {
        netns-macvlan = nixpkgs.legacyPackages.${system}.callPackage ./nix/packages/netns-macvlan { };
        subid-broker = nixpkgs.legacyPackages.${system}.callPackage ./nix/packages/subid-broker { };
        dbus-proxy = nixpkgs.legacyPackages.${system}.callPackage ./nix/packages/dbus-proxy { };
        permissions-broker = nixpkgs.legacyPackages.${system}.callPackage ./nix/packages/permissions-broker { };
        permissions-window = nixpkgs.legacyPackages.${system}.callPackage ./nix/packages/permissions-window { };
        request-send = nixpkgs.legacyPackages.${system}.callPackage ./nix/packages/request-send { };
        launcher = nixpkgs.legacyPackages.${system}.callPackage ./nix/packages/launcher { };
        sandbox-uplink = nixpkgs.legacyPackages.${system}.callPackage ./nix/packages/sandbox-uplink { };
        einat = nixpkgs.legacyPackages.${system}.callPackage ./nix/packages/einat { input = inputs.einat; };
      });
      checks = forAllSystems (system: (checksFor system).checks);
      # nix-unit's, run by checks.claude-desktop-eval
      tests = forAllSystems (system: (checksFor system).tests);
      # Built by CI, not by nix flake check: checks.vm-loop at 100 launches
      legacyPackages = forAllSystems (system: { vm-loop-full = (checksFor system).vmLoopFull; });
    };
}
