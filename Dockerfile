# ------------------------------------------------------------------------------
# Cargo Build Stage
# ------------------------------------------------------------------------------
FROM rust:1.86.0 as cargo-build

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
FROM debian:bookworm-20220912

WORKDIR /

RUN apt-get update && \
    apt-get install --no-install-recommends ca-certificates -y && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=cargo-build /usr/local/cargo/bin/acm-sync-manager ./

USER 1000

CMD ["/acm-sync-manager"]
