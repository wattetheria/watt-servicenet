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

RUN --mount=type=secret,id=github_token set -eu; \
    token_file=/run/secrets/github_token; \
    if [ -s "$token_file" ]; then \
      token="$(cat "$token_file")"; \
      git config --global url."https://x-access-token:${token}@github.com/".insteadOf "https://github.com/"; \
    fi; \
    clone_ref() { \
      repo="$1"; \
      ref="$2"; \
      dir="$3"; \
      git clone --filter=blob:none --no-checkout "$repo" "$dir"; \
      git -C "$dir" fetch --depth 1 origin "$ref"; \
      git -C "$dir" checkout --detach FETCH_HEAD; \
    }; \
    clone_ref "$WATTSWARM_REPO" "$WATTSWARM_REF" ./wattswarm; \
    clone_ref "$WATT_DID_REPO" "$WATT_DID_REF" ./watt-did; \
    clone_ref "$WATT_WALLET_REPO" "$WATT_WALLET_REF" ./watt-wallet; \
    git config --global --unset-all url."https://x-access-token:${token:-}@github.com/".insteadOf || true

WORKDIR /workspace/watt-servicenet
RUN cargo build --release -p watt-servicenet-node

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /workspace/watt-servicenet/target/release/watt-servicenet-node /usr/local/bin/watt-servicenet-node

ENV SERVICENET_REGISTRY_FILE=/data/registry.json
ENV SERVICENET_P2P_ENABLED=0

VOLUME ["/data"]
EXPOSE 8042

CMD ["watt-servicenet-node"]
