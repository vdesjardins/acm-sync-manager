# ------------------------------------------------------------------------------
# Cargo Build Stage
# ------------------------------------------------------------------------------
FROM rust:1.58.1 as cargo-build

WORKDIR /usr/src/

WORKDIR /usr/src/acm-sync-manager

COPY Cargo.toml .
COPY Cargo.lock .
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
  --mount=type=cache,target=/usr/src/acm-sync-manager/target \
  cargo install --path .

# ------------------------------------------------------------------------------
# Final Stage
# ------------------------------------------------------------------------------
FROM debian:bookworm-20220125

WORKDIR /

RUN apt-get update --no-install-recommends && \
  apt-get install --no-install-recommends ca-certificates -y

COPY --from=cargo-build /usr/local/cargo/bin/acm-sync-manager ./

USER 1000

CMD ["/acm-sync-manager"]
