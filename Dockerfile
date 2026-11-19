# syntax=docker/dockerfile:1.7
# Multi-stage build with cargo-chef dependency caching.
# Runtime image: distroless static (includes CA certificates), nonroot.

ARG RUST_VERSION=1.100.0

FROM rust:${RUST_VERSION}-bookworm AS chef
RUN cargo install cargo-chef --locked --version 0.1.78 \
 && rustup target add x86_64-unknown-linux-musl \
 && apt-get update \
 && apt-get install -y --no-install-recommends musl-tools
WORKDIR /src

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /src/recipe.json recipe.json
RUN cargo chef cook --release --locked --target x86_64-unknown-linux-musl --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --target x86_64-unknown-linux-musl -p otter-credential-broker \
 && cp target/x86_64-unknown-linux-musl/release/otter-credential-broker /otter-credential-broker

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=builder /otter-credential-broker /usr/local/bin/otter-credential-broker
USER 65532:65532
# 8080 LLM proxy and worker endpoint, 8081 admin API, 9090 metrics
EXPOSE 8080 8081 9090
ENTRYPOINT ["/usr/local/bin/otter-credential-broker"]
CMD ["serve"]
