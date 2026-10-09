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
    llm-agents = {
      url = "github:numtide/llm-agents.nix";
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
      });
      checks = forAllSystems (
        system:
        import ./nix/checks {
          inherit self inputs;
          pkgs = nixpkgs.legacyPackages.${system};
        }
      );
    };
}
