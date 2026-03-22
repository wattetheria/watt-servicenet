# syntax=docker/dockerfile:1.6
FROM rust:1.89-bookworm AS builder

WORKDIR /workspace

COPY . ./watt-servicenet
COPY --from=wattswarm_root . ./wattswarm

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
