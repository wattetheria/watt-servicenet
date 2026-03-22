# syntax=docker/dockerfile:1.6
FROM rust:1.89-bookworm AS builder

WORKDIR /workspace

COPY . ./wattswarm-servicenet
COPY --from=wattswarm_root . ./wattswarm

WORKDIR /workspace/wattswarm-servicenet
RUN cargo build --release -p wattswarm-servicenet-node

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /workspace/wattswarm-servicenet/target/release/wattswarm-servicenet-node /usr/local/bin/wattswarm-servicenet-node

ENV SERVICENET_REGISTRY_FILE=/data/registry.json
ENV SERVICENET_P2P_ENABLED=0

VOLUME ["/data"]
EXPOSE 8042

CMD ["wattswarm-servicenet-node"]
