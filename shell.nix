{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    # pkg-config
    # openssl
    libiconv
    pkgs.darwin.apple_sdk.frameworks.Security

    kind
    awscli2
    kubectl
    kubernetes-helm
    gnumake
    jq
    envsubst
    #     # keep this line if you use bash
    #     pkgs.bashInteractive
  ];
}
