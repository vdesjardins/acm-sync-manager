{ awscli2
, darwin
, envsubst
, fenix
, gnumake
, jq
, kind
, kubectl
, kubernetes-helm
, lib
, libiconv
, mkShell
, openssl
, pkg-config
, stdenv
}:
mkShell {
  packages = [
    fenix.stable.toolchain

    libiconv
    openssl
    pkg-config

    kind
    awscli2
    kubectl
    kubernetes-helm
    gnumake
    jq
    envsubst
  ] ++ lib.optionals stdenv.isDarwin [
    darwin.apple_sdk.frameworks.Security
  ];
}
