# Two images from one build:
#   docker build --target operator -t iroh-gateway-operator .
#   docker build --target edge -t iroh-gateway-edge .

FROM rust:1.100-bookworm AS build
WORKDIR /src
# Not rust-toolchain.toml: the image is Rust 1.100 already, and with it rustup would download
# the extra components it lists.
COPY Cargo.toml Cargo.lock ./
COPY proto ./proto
COPY edge ./edge
COPY operator ./operator
RUN cargo build --release --locked -p iroh-gateway-operator -p iroh-gateway-edge

# The operator runs HAProxy as a child process, so it ships on HAProxy's image.
# The official image puts the binary at /usr/local/sbin/haproxy, which is on PATH.
FROM haproxy:3.2 AS operator
LABEL org.opencontainers.image.source=https://github.com/fables-for-robots/iroh-gateway \
      org.opencontainers.image.licenses=AGPL-3.0-or-later
COPY --from=build /src/target/release/iroh-gateway-operator /usr/local/bin/iroh-gateway-operator
USER 65532:65532
WORKDIR /
# The base image sets SIGUSR1 to stop HAProxy; the entrypoint here is the operator, which stops on SIGTERM.
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/iroh-gateway-operator", "run"]

FROM gcr.io/distroless/cc-debian12:nonroot AS edge
LABEL org.opencontainers.image.source=https://github.com/fables-for-robots/iroh-gateway \
      org.opencontainers.image.licenses=AGPL-3.0-or-later
COPY --from=build /src/target/release/iroh-gateway-edge /iroh-gateway-edge
ENTRYPOINT ["/iroh-gateway-edge"]
