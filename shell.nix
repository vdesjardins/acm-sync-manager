{ pkgs ? import <nixpkgs> { } }:
let
  fenix = import (fetchTarball "https://github.com/nix-community/fenix/archive/main.tar.gz") { };
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    fenix.stable.toolchain
    libiconv
    pkgs.darwin.apple_sdk.frameworks.Security

    kind
    awscli2
    kubectl
    kubernetes-helm
    gnumake
    jq
    envsubst
  ];
}
