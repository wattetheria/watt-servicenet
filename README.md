# watt-servicenet

Decentralized agent registry and execution gateway for Watt agent networks.

`watt-servicenet` provides the first ServiceNet node implementation: provider
registration, A2A agent submission and publishing, invocation receipts,
governance records, and optional Iroh-backed P2P registry sync.

Full product documentation and API reference live at
[Watt ServiceNet Docs](https://hs-df36fa00.mintlify.app/).

## Architecture

```mermaid
flowchart TB
    provider["Agent provider<br/>DID ownership + attestation"]
    client["Agent consumer<br/>HTTP invocation client"]
    remote["Published A2A agent<br/>did:key + JSON-RPC endpoint"]
    peer["ServiceNet peer node"]

    subgraph node["watt-servicenet-node"]
        api["Node interface<br/>providers, submissions, agents, receipts"]
        registry["Service registry<br/>providers, submissions, published agents"]
        gateway["Execution gateway<br/>policy preflight + A2A adapter"]
        governance["Trust, health, moderation<br/>verification + audit records"]
        auth["Auth-context broker<br/>encrypted secret references"]
        p2p["Iroh P2P sync<br/>gossip + backfill"]
    end

    subgraph storage["Persistence options"]
        memory["In-memory"]
        file["JSON registry file"]
        postgres["PostgreSQL<br/>registry, receipts, trust, audit"]
    end

    provider -->|register provider / submit agent| api
    client -->|invoke agent / query receipts| api
    api --> registry
    api --> gateway
    api --> governance
    api --> auth
    registry --> storage
    gateway -->|A2A JSON-RPC| remote
    gateway -->|receipt| governance
    auth --> postgres
    governance --> postgres
    registry <--> p2p
    p2p <--> peer
```

## Service Agent Identity

Provider identity and Service Agent identity are intentionally distinct.
Provider operations use the registered `did:key` to prove who may publish or
update records. Every submitted Agent must also carry a unique `service_did`
using an independent Ed25519 `did:key`. The Provider signs the submission that
binds its identity to the Agent ID, Service Agent DID, Agent Card, endpoint, and
publication metadata.

At submission, Registry requires `deployment.runtime =
wattetheria_adapter`, verifies the Provider attestation, validates that the
Service Agent DID is an Ed25519 `did:key`, and rejects Provider-key reuse or a
Service Agent DID already assigned to another Agent. No DID document, public
`did.json` endpoint, domain lookup, or Endpoint-to-identity binding is required.

On every mediated A2A invocation, the Wattetheria Adapter must return
`extensions.service_agent_signature`. The signature binds the request digest,
request nonce, canonical result digest, response nonce, and timestamp. Gateway
derives the public key directly from `service_did`, verifies the signature, and
rejects replayed response nonces before recording a successful receipt. Private
Service Agent keys are never submitted to ServiceNet.

## Run Locally

Run with in-memory state:

```bash
cargo run -p watt-servicenet-node
```

Run with file-backed state:

```bash
SERVICENET_REGISTRY_FILE=.data/registry.json \
cargo run -p watt-servicenet-node
```

Run with PostgreSQL-backed state:

```bash
SERVICENET_DATABASE_URL=postgres://servicenet:servicenet@127.0.0.1:55433/watt-servicenet \
SERVICENET_DATABASE_SCHEMA=public \
SERVICENET_SECRET_BROKER_KEY=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc= \
SERVICENET_REQUIRE_PROVIDER_OWNERSHIP_CHALLENGES=1 \
cargo run -p watt-servicenet-node
```

The HTTP node listens on `127.0.0.1:8042` by default. Override it with
`SERVICENET_HTTP_ADDR`.

## Docker

```bash
docker compose up --build
```

Docker Compose starts PostgreSQL and `watt-servicenet-node`, with the API on
`127.0.0.1:8042` and PostgreSQL on `127.0.0.1:55433`.

The Rust workspace keeps local path dependencies for development. During Docker
builds, the `Dockerfile` rewrites those path dependencies to git dependencies so
release builds can run outside the local Watt source tree. The default
dependency sources are public GitHub repositories, so Docker builds do not
require a GitHub token:

```bash
docker compose up --build
```

Use these build args to pin dependency sources when needed:

- `WATTSWARM_REPO`, `WATTSWARM_REF`
- `WATT_DID_REPO`, `WATT_DID_REF`
- `WATT_WALLET_REPO`, `WATT_WALLET_REF`

## Core Configuration

| Variable | Purpose |
| --- | --- |
| `SERVICENET_HTTP_ADDR` | HTTP bind address. |
| `SERVICENET_REGISTRY_FILE` | JSON file-backed registry path. |
| `SERVICENET_DATABASE_URL` | Enables PostgreSQL-backed registry state. |
| `SERVICENET_DATABASE_SCHEMA` | PostgreSQL schema, defaults to `public`. |
| `SERVICENET_SECRET_BROKER_KEY` | Required for database-backed encrypted auth-context storage. |
| `SERVICENET_REQUIRE_PROVIDER_OWNERSHIP_CHALLENGES` | Requires signed provider ownership challenges. |
| `SERVICENET_REQUIRE_ADMIN_APPROVE` | Keeps submissions admin-gated instead of auto-publishing valid submissions. |
| `SERVICENET_GATEWAY_MAX_COST_UNITS` | Default gateway cost guardrail. |

## P2P Sync

Enable Iroh-backed provider and published-agent sync:

```bash
SERVICENET_P2P_ENABLED=1 \
SERVICENET_P2P_NETWORK_ID=devnet \
SERVICENET_P2P_LISTEN_ADDRS=0.0.0.0:4101 \
cargo run -p watt-servicenet-node
```

Each node prints and persists its Iroh `EndpointId` in
`SERVICENET_P2P_STATE_DIR/node_seed.hex`. Bootstrap peers use
`<endpoint-id>@<addr>` format:

```bash
SERVICENET_P2P_ENABLED=1 \
SERVICENET_P2P_NETWORK_ID=devnet \
SERVICENET_P2P_BOOTSTRAP_PEERS=<peer-endpoint-id>@127.0.0.1:4101 \
cargo run -p watt-servicenet-node
```

Set `SERVICENET_FEDERATION_MODE=trusted` and
`SERVICENET_FEDERATION_TRUSTED_PEERS=<endpoint-id-1>,<endpoint-id-2>` for curated
entry nodes that should only merge records from trusted peers. The default mode
is open federation.

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test
```

PostgreSQL integration tests use `SERVICENET_TEST_DATABASE_URL`:

```bash
SERVICENET_TEST_DATABASE_URL=postgres://servicenet:servicenet@127.0.0.1:55433/watt-servicenet \
cargo test
```

For Docker configuration checks:

```bash
docker compose config
```

## Star History

[![Star History Chart](https://api.star-history.com/image?repos=wattetheria/watt-servicenet&type=Date)](https://star-history.com/#wattetheria/watt-servicenet&Date)
