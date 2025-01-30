{
  description = "acm-sync-manager project";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/release-24.11";
    fenix.url = "github:/nix-community/fenix";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    fenix,
  }: let
    localOverlay = import ./nix/overlay.nix;
    overlays = [fenix.overlay localOverlay];
  in
    flake-utils.lib.eachDefaultSystem
    (system: let
      pkgs = import nixpkgs {
        inherit system overlays;
      };
    in {
      legacyPackages = pkgs;
      inherit (pkgs) devShell;
    })
    // {
      overlay = nixpkgs.lib.composeManyExtensions overlays;
      inherit overlays;
    };
}
