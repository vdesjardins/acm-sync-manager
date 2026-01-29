# ------------------------------------------------------------------------------
# Cargo Build Stage
# ------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM rust:1.93.0 AS cargo-build

ARG TARGETPLATFORM
ARG BUILDPLATFORM

WORKDIR /usr/src/acm-sync-manager

# Install cross-compilation dependencies
RUN case "$TARGETPLATFORM" in \
    "linux/amd64") echo "x86_64-unknown-linux-gnu" > /rust_target.txt ;; \
    "linux/arm64") echo "aarch64-unknown-linux-gnu" > /rust_target.txt && \
        apt-get update && \
        apt-get install -y gcc-aarch64-linux-gnu && \
        rustup target add aarch64-unknown-linux-gnu ;; \
    *) echo "Unsupported platform: $TARGETPLATFORM" && exit 1 ;; \
    esac

COPY Cargo.toml .
COPY Cargo.lock .
COPY src ./src

# Build for the target architecture
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    export RUST_TARGET=$(cat /rust_target.txt) && \
    if [ "$RUST_TARGET" = "aarch64-unknown-linux-gnu" ]; then \
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc && \
        cargo build --release --target $RUST_TARGET && \
        cp target/$RUST_TARGET/release/acm-sync-manager /usr/local/bin/acm-sync-manager ; \
    else \
        cargo build --release && \
        cp target/release/acm-sync-manager /usr/local/bin/acm-sync-manager ; \
    fi

# ------------------------------------------------------------------------------
# Final Stage
# ------------------------------------------------------------------------------
FROM debian:stable-slim

WORKDIR /

RUN apt-get update && \
    apt-get install --no-install-recommends ca-certificates -y && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=cargo-build /usr/local/bin/acm-sync-manager ./

USER 1000

CMD ["/acm-sync-manager"]
