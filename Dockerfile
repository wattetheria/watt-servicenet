# syntax=docker/dockerfile:1.6
FROM rust:1.89-bookworm AS builder

ARG WATTSWARM_REPO=https://github.com/wattetheria/wattswarm.git
ARG WATTSWARM_REF=main
ARG WATT_DID_REPO=https://github.com/wattetheria/watt-did.git
ARG WATT_DID_REF=main
ARG WATT_WALLET_REPO=https://github.com/wattetheria/watt-wallet.git
ARG WATT_WALLET_REF=main

WORKDIR /workspace

COPY . ./watt-servicenet

WORKDIR /workspace/watt-servicenet
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/cargo-target,sharing=locked \
    --mount=type=secret,id=github_token \
    set -eu; \
    token_file=/run/secrets/github_token; \
    if [ -s "$token_file" ]; then \
      token="$(cat "$token_file")"; \
      git config --global url."https://x-access-token:${token}@github.com/".insteadOf "https://github.com/"; \
    fi; \
    sed -i \
      -e "s|wattswarm-artifact-store = { path = \"../wattswarm/crates/artifact-store\" }|wattswarm-artifact-store = { git = \"${WATTSWARM_REPO}\", branch = \"${WATTSWARM_REF}\", package = \"wattswarm-artifact-store\" }|" \
      -e "s|wattswarm-network-substrate = { path = \"../wattswarm/crates/network-substrate\" }|wattswarm-network-substrate = { git = \"${WATTSWARM_REPO}\", branch = \"${WATTSWARM_REF}\", package = \"wattswarm-network-substrate\" }|" \
      -e "s|wattswarm-network-transport-core = { path = \"../wattswarm/crates/network-transport-core\" }|wattswarm-network-transport-core = { git = \"${WATTSWARM_REPO}\", branch = \"${WATTSWARM_REF}\", package = \"wattswarm-network-transport-core\" }|" \
      -e "s|wattswarm-network-transport-iroh = { path = \"../wattswarm/crates/network-transport-iroh\" }|wattswarm-network-transport-iroh = { git = \"${WATTSWARM_REPO}\", branch = \"${WATTSWARM_REF}\", package = \"wattswarm-network-transport-iroh\" }|" \
      Cargo.toml; \
    sed -i \
      -e "s|watt-did = { path = \"../../../watt-did\" }|watt-did = { git = \"${WATT_DID_REPO}\", branch = \"${WATT_DID_REF}\" }|" \
      crates/service-protocol/Cargo.toml crates/service-registry/Cargo.toml; \
    sed -i \
      -e "s|watt-wallet = { path = \"../../../watt-wallet\" }|watt-wallet = { git = \"${WATT_WALLET_REPO}\", branch = \"${WATT_WALLET_REF}\" }|" \
      crates/service-registry/Cargo.toml; \
    sed -i \
      -e "s|wattswarm-crypto = { path = \"../../../wattswarm/crates/crypto\" }|wattswarm-crypto = { git = \"${WATTSWARM_REPO}\", branch = \"${WATTSWARM_REF}\", package = \"wattswarm-crypto\" }|" \
      crates/service-network-p2p/Cargo.toml; \
    printf '\n[patch."%s"]\nwatt-did = { git = "%s", branch = "%s" }\n' \
      "$WATT_WALLET_REPO" "$WATT_DID_REPO" "$WATT_DID_REF" >> Cargo.toml; \
    CARGO_TARGET_DIR=/cargo-target cargo build --release -p watt-servicenet-node; \
    mkdir -p /out; \
    cp /cargo-target/release/watt-servicenet-node /out/watt-servicenet-node; \
    rm -f /root/.gitconfig

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /out/watt-servicenet-node /usr/local/bin/watt-servicenet-node

ENV SERVICENET_REGISTRY_FILE=/data/registry.json
ENV SERVICENET_P2P_ENABLED=0

VOLUME ["/data"]
EXPOSE 8042

CMD ["watt-servicenet-node"]
