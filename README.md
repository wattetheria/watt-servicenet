# watt-servicenet

Decentralized agent registry and execution gateway for agent networks.

## What This Repository Contains

This repository starts the first `registry + gateway` implementation.

Current MVP scope:

- agent-native protocol, submission, publish, and invocation records
- independent provider records with revoke support
- in-memory provider, submission, and published-agent registry state
- optional JSON file-backed registry persistence
- PostgreSQL-backed registry, receipts, health, trust, auth-context, and audit persistence
- signed provider ownership challenge support for provider register and key rotation
- encrypted auth-context secret broker storage
- automated verifier sweep plus manual adjudication records
- moderation case workflow for provider and agent review
- HTTP gateway for agent invocation
- A2A JSON-RPC adapter
- execution receipts with request/result digests
- optional libp2p provider and published-agent gossip/backfill via `wattswarm-network-substrate`

This first version is still local-first in storage and policy, but it now includes an initial
P2P provider and published-agent sync layer built on the shared `network-substrate`.

## Direction

The public and internal model in this repository is now agent-native:

- public discovery and interaction standard: A2A
- developer review payload: `AgentSubmission`
- network-published identity: approved A2A agent

## Workspace Layout

- `crates/service-protocol`: canonical agent, provider, moderation, and receipt types
- `crates/service-registry`: provider registry, agent submission store, and published-agent state
- `crates/service-gateway`: agent policy preflight and A2A execution adapter
- `crates/service-network-p2p`: servicenet-specific libp2p overlay over shared substrate
- `apps/service-node`: HTTP node exposing registry and gateway APIs

## HTTP API

Run the node:

```bash
cargo run -p watt-servicenet-node
```

Run the node with file-backed persistence:

```bash
SERVICENET_REGISTRY_FILE=.data/registry.json cargo run -p watt-servicenet-node
```

Run the node with PostgreSQL-backed persistence:

```bash
SERVICENET_DATABASE_URL=postgres://servicenet:servicenet@127.0.0.1:55433/watt-servicenet \
SERVICENET_DATABASE_SCHEMA=public \
SERVICENET_REQUIRE_PROVIDER_OWNERSHIP_CHALLENGES=1 \
SERVICENET_SECRET_BROKER_KEY=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc= \
cargo run -p watt-servicenet-node
```

Run with Docker Compose:

```bash
docker compose up --build
```

Run the node with P2P registry sync enabled:

```bash
SERVICENET_P2P_ENABLED=1 \
SERVICENET_P2P_NETWORK_ID=devnet \
SERVICENET_P2P_LISTEN_ADDRS=/ip4/0.0.0.0/tcp/4101 \
cargo run -p watt-servicenet-node
```

Join an existing peer:

```bash
SERVICENET_P2P_ENABLED=1 \
SERVICENET_P2P_NETWORK_ID=devnet \
SERVICENET_P2P_LISTEN_ADDRS=/ip4/0.0.0.0/tcp/4102 \
SERVICENET_P2P_BOOTSTRAP_PEERS=/ip4/127.0.0.1/tcp/4101/p2p/<PEER_ID> \
cargo run -p watt-servicenet-node
```

Current P2P behavior:

- publish newly registered provider records over gossip
- publish newly approved agents over gossip
- subscribe to global servicenet provider and published-agent announcements
- request provider and published-agent backfill from newly connected peers
- merge inbound provider records and published agents into the local registry store
- support two-node PostgreSQL convergence tests for backfill + gossip persistence

Current submission behavior:

- provider registration and key rotation can require ownership challenges
- agent submissions must include provider attestations and an A2A-compatible card
- approved agents are the only records published to the shared network

Current provider behavior:

- provider records are registered independently from agent submissions
- provider registration and key rotation can require signed ownership challenges
- approved agents require an existing non-revoked provider
- provider key rotation is supported via the HTTP API
- revoked or blocked providers remain auditable but cannot be invoked

Current execution and policy behavior:

- receipts are persisted and queryable by `provider_id` or `agent_id`
- provider and agent health records are exposed over the public API
- provider and agent trust records include blocklist support
- agent review profiles carry risk and region policy metadata
- auth can be provided directly or via stored auth-context references
- auth-context secrets are encrypted at rest and only exposed as masked previews
- receipt verification supports automated sweeps and manual adjudication
- moderation cases can block providers or agents and then be resolved

## Docker

This repository currently depends on the shared local crate
`../wattswarm/crates/network-substrate`, so container builds use the parent `Watt` directory as
the Docker build context.

- `Dockerfile`: multi-stage build for `watt-servicenet-node`
- `docker-compose.yml`: local runtime with PostgreSQL + `watt-servicenet-node`
- `.dockerignore`: excludes local build and OS junk from repo-local Docker workflows
- PostgreSQL is exposed on `127.0.0.1:55433`
- database-backed runs now require `SERVICENET_SECRET_BROKER_KEY`

Run PostgreSQL-backed integration tests locally:

```bash
SERVICENET_TEST_DATABASE_URL=postgres://servicenet:servicenet@127.0.0.1:55433/servicenet cargo test
```

Register a provider:

```bash
curl -X POST http://127.0.0.1:8042/v1/providers/ownership-challenges \
  -H 'content-type: application/json' \
  -d '{
    "provider_id": "provider-local",
    "public_key": "cHJvdmlkZXItbG9jYWwtZGV2a2V5",
    "operation": "register"
  }'
```

Register a provider after signing the challenge:

```bash
curl -X POST http://127.0.0.1:8042/v1/providers/register \
  -H 'content-type: application/json' \
  -d '{
    "provider_id": "provider-local",
    "provider_did": "did:key:z6MkhaXgBZDvotD1X9gRrYkM5Xq9jYQqK6d8r8bQdE1mV2Xa",
    "display_name": "Provider Local",
    "ownership_challenge_id": "<CHALLENGE_ID>",
    "ownership_signature": "<BASE64_ED25519_SIGNATURE>"
  }'
```

Submit an agent for review:

```bash
curl -X POST http://127.0.0.1:8042/v1/agent-submissions \
  -H 'content-type: application/json' \
  -d '{
    "provider_id": "provider-local",
    "agent_id": "stripe-agent",
    "version": "0.1.0",
    "agent_card": {
      "name": "Stripe Agent",
      "description": "Handles Stripe payment flows",
      "url": "https://stripe-agent.example.com",
      "preferredTransport": "JSONRPC",
      "protocolVersion": "1.0",
      "skills": [
        {
          "id": "payments.create_link",
          "name": "Create Payment Link",
          "description": "Creates a Stripe payment link"
        }
      ],
      "securitySchemes": {
        "oauth2": { "type": "oauth2" }
      },
      "security": [
        { "oauth2": ["payments:write"] }
      ]
    },
    "deployment": {
      "runtime": "remote_http",
      "endpoint": {
        "url": "https://stripe-agent.example.com/a2a",
        "protocol_binding": "JSONRPC",
        "protocol_version": "1.0"
      }
    },
    "review": {
      "risk_level": "medium",
      "data_classes": ["financial"],
      "destructive_actions": ["payments.refund"],
      "human_approval_required": true,
      "allowed_regions": ["AU", "US"]
    },
    "artifacts": {
      "documentation_url": "https://stripe-agent.example.com/docs",
      "security_url": "https://stripe-agent.example.com/security"
    },
    "attestations": {
      "attestation_signature": "<ATTESTATION_SIGNATURE>",
      "source_commit": "<COMMIT_SHA>",
      "build_digest": "<BUILD_DIGEST>"
    }
  }'
```

Approve a submitted agent:

```bash
curl -X POST http://127.0.0.1:8042/v1/admin/agent-submissions/<SUBMISSION_ID>/approve \
  -H 'content-type: application/json' \
  -d '{
    "reviewed_by": "moderator-local",
    "review_notes": "approved"
  }'
```

Invoke an approved A2A agent:

```bash
curl -X POST http://127.0.0.1:8042/v1/agents/stripe-agent/invoke \
  -H 'content-type: application/json' \
  -d '{
    "message": "Create a payment link for 15 AUD",
    "input": {
      "amount": 15,
      "currency": "AUD"
    },
    "auth_token": "secret-token",
    "region": "AU"
  }'
```

Poll an A2A task:

```bash
curl -X POST http://127.0.0.1:8042/v1/agents/stripe-agent/tasks/<TASK_ID>/get \
  -H 'content-type: application/json' \
  -d '{
    "history_length": 10,
    "auth_token": "secret-token"
  }'
```

Register an auth context:

```bash
curl -X POST http://127.0.0.1:8042/v1/auth-contexts/register \
  -H 'content-type: application/json' \
  -d '{
    "subject_did": "did:key:z6MkhaXgBZDvotD1X9gRrYkM5Xq9jYQqK6d8r8bQdE1mV2Xa",
    "provider_id": "provider-local",
    "auth_model": { "mode": "bearer_token" },
    "token": "secret-token"
  }'
```

Run the automated verifier sweep:

```bash
curl -X POST http://127.0.0.1:8042/v1/verifier/run \
  -H 'content-type: application/json' \
  -d '{
    "verifier_id": "auto-verifier"
  }'
```

List verification records for a receipt:

```bash
curl http://127.0.0.1:8042/v1/receipts/<RECEIPT_ID>/verifications
```

Query receipts:

```bash
curl http://127.0.0.1:8042/v1/receipts?provider_id=provider-local
```

Verify a receipt:

```bash
curl -X POST http://127.0.0.1:8042/v1/receipts/<RECEIPT_ID>/verify \
  -H 'content-type: application/json' \
  -d '{
    "verifier_id": "verifier-local",
    "verdict": "verified"
  }'
```

Inspect agent trust:

```bash
curl http://127.0.0.1:8042/v1/trust/agents
```

Inspect agent health:

```bash
curl http://127.0.0.1:8042/v1/health/agents
```

Block an agent:

```bash
curl -X POST http://127.0.0.1:8042/v1/admin/agents/stripe-agent/block \
  -H 'content-type: application/json' \
  -d '{ "reason": "manual review" }'
```

Create an agent moderation case:

```bash
curl -X POST http://127.0.0.1:8042/v1/admin/moderation/cases \
  -H 'content-type: application/json' \
  -d '{
    "target_kind": "agent",
    "target_id": "stripe-agent",
    "created_by": "moderator-a",
    "reason": "manual review",
    "auto_block": true,
    "auto_revoke_provider": false
  }'
```
