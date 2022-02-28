{ libiconv
, awscli2
, darwin
, envsubst
, fenix
, gnumake
, jq
, kind
, kubectl
, kubernetes-helm
, lib
, mkShell
, stdenv
}:
mkShell {
  packages = [
    fenix.stable.toolchain

    libiconv

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
