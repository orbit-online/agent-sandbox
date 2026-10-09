{
  description = "Sandboxes for AI agents on NixOS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
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
      homeModules.claude-desktop = import ./nix/home/claude-desktop { inherit inputs; };
      nixosModules.claude-desktop = import ./nix/nixos/claude-desktop.nix { inherit self; };
      packages = forAllSystems (system: {
        netns-macvlan = nixpkgs.legacyPackages.${system}.callPackage ./nix/packages/netns-macvlan { };
      });
    };
}
