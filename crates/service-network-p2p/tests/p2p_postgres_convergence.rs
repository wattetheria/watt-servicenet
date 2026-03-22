use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::time::sleep;
use uuid::Uuid;
use watt_servicenet_p2p::{
    Multiaddr, ServiceNetworkNode, ServiceNetworkP2pConfig, ServiceNetworkRuntime,
    ServiceNetworkRuntimeEvent,
};
use watt_servicenet_protocol::{
    AgentDeployment, AgentDeploymentEndpoint, AgentReviewProfile, ProviderRecord, ProviderStatus,
    PublishedAgentRecord, PublishedAgentStatus, RegisterProviderRequest, RevokeProviderRequest,
    RiskLevel,
};
use watt_servicenet_registry::{ServiceRegistry, ServiceRegistryConfig};

fn database_url() -> Option<String> {
    std::env::var("SERVICENET_TEST_DATABASE_URL").ok()
}

fn schema_name(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4().simple())
}

fn provider_request() -> RegisterProviderRequest {
    RegisterProviderRequest {
        provider_id: "provider-p2p".to_owned(),
        provider_public_key: "cHJvdmlkZXItcDJwLWRldmtleQ==".to_owned(),
        display_name: Some("Provider P2P".to_owned()),
        ownership_challenge_id: None,
        ownership_signature: None,
    }
}

fn published_agent() -> PublishedAgentRecord {
    PublishedAgentRecord {
        agent_id: "stripe-agent-p2p".to_owned(),
        provider_id: "provider-p2p".to_owned(),
        version: "0.1.0".to_owned(),
        status: PublishedAgentStatus::Approved,
        agent_card: serde_json::json!({
            "name": "Stripe Agent",
            "description": "Payments",
            "url": "https://stripe-agent.example.com",
            "preferredTransport": "JSONRPC",
            "protocolVersion": "1.0",
            "skills": [{ "id": "payments.create_link" }],
            "securitySchemes": { "oauth2": { "type": "oauth2" } },
            "security": [{ "oauth2": ["payments:write"] }]
        }),
        deployment: AgentDeployment {
            runtime: "remote_http".to_owned(),
            endpoint: AgentDeploymentEndpoint {
                url: "https://stripe-agent.example.com/a2a".to_owned(),
                protocol_binding: "JSONRPC".to_owned(),
                protocol_version: "1.0".to_owned(),
            },
        },
        review: AgentReviewProfile {
            risk_level: RiskLevel::Medium,
            data_classes: vec!["financial".to_owned()],
            destructive_actions: vec!["payments.refund".to_owned()],
            human_approval_required: true,
            allowed_regions: vec!["AU".to_owned()],
            cost_per_call_units: Some(5),
        },
        approved_at: Utc::now(),
        updated_at: Utc::now(),
        reviewed_by: "moderator-a".to_owned(),
        review_notes: Some("initial approval".to_owned()),
    }
}

fn test_config() -> ServiceNetworkP2pConfig {
    ServiceNetworkP2pConfig {
        listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".to_owned()],
        enable_mdns: false,
        ..ServiceNetworkP2pConfig::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_backfill_and_gossip_converge_between_two_nodes() {
    let Some(database_url) = database_url() else {
        eprintln!(
            "skipping postgres p2p convergence test; SERVICENET_TEST_DATABASE_URL is not set"
        );
        return;
    };
    let registry_a = ServiceRegistry::postgres_with_config(
        &database_url,
        &schema_name("p2p_a"),
        ServiceRegistryConfig::default(),
    )
    .await
    .expect("postgres registry a should initialize");
    let registry_b = ServiceRegistry::postgres_with_config(
        &database_url,
        &schema_name("p2p_b"),
        ServiceRegistryConfig::default(),
    )
    .await
    .expect("postgres registry b should initialize");

    registry_a
        .register_provider(provider_request())
        .await
        .expect("provider should register");
    registry_a
        .upsert_published_agent(published_agent())
        .await
        .expect("published agent should persist");

    let mut runtime_a = ServiceNetworkRuntime::new(
        ServiceNetworkNode::generate(test_config()).expect("node a should start"),
    )
    .expect("runtime a should start");
    runtime_a
        .subscribe_global()
        .expect("runtime a should subscribe");
    let listen_addr = wait_for_listen_addr(&mut runtime_a)
        .await
        .expect("runtime a should listen");
    let peer_a = runtime_a.local_peer_id();

    let mut config_b = test_config();
    config_b.bootstrap_peers = vec![format!("{listen_addr}/p2p/{peer_a}")];
    let mut runtime_b = ServiceNetworkRuntime::new(
        ServiceNetworkNode::generate(config_b).expect("node b should start"),
    )
    .expect("runtime b should start");
    runtime_b
        .subscribe_global()
        .expect("runtime b should subscribe");
    wait_for_connection(&mut runtime_a, &mut runtime_b)
        .await
        .expect("nodes should connect");

    runtime_b
        .send_provider_sync_request(&peer_a, 256)
        .expect("provider sync request should send");
    let provider_channel = wait_for_provider_sync_request(&mut runtime_a, &mut runtime_b)
        .await
        .expect("provider sync request should arrive");
    let providers = registry_a
        .list_providers()
        .await
        .expect("providers should load");
    runtime_a
        .send_provider_sync_response(provider_channel, &providers)
        .expect("provider sync response should send");
    let provider_response = wait_for_provider_sync_response(&mut runtime_a, &mut runtime_b)
        .await
        .expect("provider sync response should arrive");
    for provider in provider_response {
        registry_b
            .upsert_provider_record(provider)
            .await
            .expect("provider should persist on node b");
    }

    runtime_b
        .send_published_agent_sync_request(&peer_a, 256)
        .expect("published agent sync request should send");
    let agent_channel = wait_for_published_agent_sync_request(&mut runtime_a, &mut runtime_b)
        .await
        .expect("published agent sync request should arrive");
    let agents = registry_a
        .list_published_agents()
        .await
        .expect("published agents should load");
    runtime_a
        .send_published_agent_sync_response(agent_channel, &agents)
        .expect("published agent sync response should send");
    let agent_response = wait_for_published_agent_sync_response(&mut runtime_a, &mut runtime_b)
        .await
        .expect("published agent sync response should arrive");
    for record in agent_response {
        registry_b
            .upsert_published_agent(record)
            .await
            .expect("published agent should persist on node b");
    }

    let provider_b = registry_b
        .get_provider("provider-p2p")
        .await
        .expect("provider should exist on node b");
    assert_eq!(provider_b.provider_id, "provider-p2p");
    let agent_b = registry_b
        .get_published_agent("stripe-agent-p2p")
        .await
        .expect("published agent should exist on node b");
    assert_eq!(agent_b.agent_id, "stripe-agent-p2p");

    let revoked_provider = registry_a
        .revoke_provider(
            "provider-p2p",
            RevokeProviderRequest {
                reason: Some("compromised".to_owned()),
            },
        )
        .await
        .expect("provider should revoke on node a");
    publish_provider_when_ready(&mut runtime_a, &mut runtime_b, &revoked_provider)
        .await
        .expect("provider revoke gossip should publish");
    let inbound_provider = wait_for_provider_gossip(&mut runtime_a, &mut runtime_b)
        .await
        .expect("provider revoke gossip should arrive");
    registry_b
        .upsert_provider_record(inbound_provider)
        .await
        .expect("revoked provider should persist on node b");

    let mut updated_agent = registry_a
        .get_published_agent("stripe-agent-p2p")
        .await
        .expect("published agent should reload on node a");
    updated_agent.updated_at = Utc::now();
    updated_agent.review_notes = Some("rotated secrets".to_owned());
    registry_a
        .upsert_published_agent(updated_agent.clone())
        .await
        .expect("published agent update should persist on node a");
    publish_published_agent_when_ready(&mut runtime_a, &mut runtime_b, &updated_agent)
        .await
        .expect("published agent gossip should publish");
    let inbound_agent = wait_for_published_agent_gossip(&mut runtime_a, &mut runtime_b)
        .await
        .expect("published agent gossip should arrive");
    registry_b
        .upsert_published_agent(inbound_agent)
        .await
        .expect("published agent update should persist on node b");

    let provider_b = registry_b
        .get_provider("provider-p2p")
        .await
        .expect("provider should reload on node b");
    assert_eq!(provider_b.status, ProviderStatus::Revoked);

    let agent_b = registry_b
        .get_published_agent("stripe-agent-p2p")
        .await
        .expect("published agent should reload on node b");
    assert_eq!(agent_b.review_notes.as_deref(), Some("rotated secrets"));
}

async fn wait_for_listen_addr(runtime: &mut ServiceNetworkRuntime) -> anyhow::Result<Multiaddr> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for listen addr");
        }
        if let Some(ServiceNetworkRuntimeEvent::NewListenAddr { address }) =
            runtime.try_next_event()?
        {
            return Ok(address);
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_connection(
    runtime_a: &mut ServiceNetworkRuntime,
    runtime_b: &mut ServiceNetworkRuntime,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for p2p connection");
        }
        if let Some(ServiceNetworkRuntimeEvent::ConnectionEstablished { .. }) =
            runtime_a.try_next_event()?
        {
            return Ok(());
        }
        if let Some(ServiceNetworkRuntimeEvent::ConnectionEstablished { .. }) =
            runtime_b.try_next_event()?
        {
            return Ok(());
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_provider_sync_request(
    runtime_a: &mut ServiceNetworkRuntime,
    runtime_b: &mut ServiceNetworkRuntime,
) -> anyhow::Result<wattswarm_network_substrate::BackfillResponseChannel> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for provider sync request");
        }
        let _ = runtime_b.try_next_event()?;
        if let Some(ServiceNetworkRuntimeEvent::ProviderSyncRequest { channel, .. }) =
            runtime_a.try_next_event()?
        {
            return Ok(channel);
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_provider_sync_response(
    runtime_a: &mut ServiceNetworkRuntime,
    runtime_b: &mut ServiceNetworkRuntime,
) -> anyhow::Result<Vec<ProviderRecord>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for provider sync response");
        }
        let _ = runtime_a.try_next_event()?;
        if let Some(ServiceNetworkRuntimeEvent::ProviderSyncResponse { providers, .. }) =
            runtime_b.try_next_event()?
        {
            return Ok(providers);
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_published_agent_sync_request(
    runtime_a: &mut ServiceNetworkRuntime,
    runtime_b: &mut ServiceNetworkRuntime,
) -> anyhow::Result<wattswarm_network_substrate::BackfillResponseChannel> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for published agent sync request");
        }
        let _ = runtime_b.try_next_event()?;
        if let Some(ServiceNetworkRuntimeEvent::PublishedAgentSyncRequest { channel, .. }) =
            runtime_a.try_next_event()?
        {
            return Ok(channel);
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_published_agent_sync_response(
    runtime_a: &mut ServiceNetworkRuntime,
    runtime_b: &mut ServiceNetworkRuntime,
) -> anyhow::Result<Vec<PublishedAgentRecord>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for published agent sync response");
        }
        let _ = runtime_a.try_next_event()?;
        if let Some(ServiceNetworkRuntimeEvent::PublishedAgentSyncResponse { records, .. }) =
            runtime_b.try_next_event()?
        {
            return Ok(records);
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn publish_provider_when_ready(
    runtime_a: &mut ServiceNetworkRuntime,
    runtime_b: &mut ServiceNetworkRuntime,
    provider: &ProviderRecord,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for provider publish readiness");
        }
        match runtime_a.publish_provider(provider) {
            Ok(()) => return Ok(()),
            Err(err) if err.to_string().contains("NoPeersSubscribedToTopic") => {
                let _ = runtime_a.try_next_event()?;
                let _ = runtime_b.try_next_event()?;
                sleep(Duration::from_millis(50)).await;
            }
            Err(err) => return Err(err),
        }
    }
}

async fn publish_published_agent_when_ready(
    runtime_a: &mut ServiceNetworkRuntime,
    runtime_b: &mut ServiceNetworkRuntime,
    record: &PublishedAgentRecord,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for published agent publish readiness");
        }
        match runtime_a.publish_published_agent_record(record) {
            Ok(()) => return Ok(()),
            Err(err) if err.to_string().contains("NoPeersSubscribedToTopic") => {
                let _ = runtime_a.try_next_event()?;
                let _ = runtime_b.try_next_event()?;
                sleep(Duration::from_millis(50)).await;
            }
            Err(err) => return Err(err),
        }
    }
}

async fn wait_for_provider_gossip(
    runtime_a: &mut ServiceNetworkRuntime,
    runtime_b: &mut ServiceNetworkRuntime,
) -> anyhow::Result<ProviderRecord> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for provider gossip");
        }
        let _ = runtime_a.try_next_event()?;
        if let Some(ServiceNetworkRuntimeEvent::ProviderPublished { provider, .. }) =
            runtime_b.try_next_event()?
        {
            return Ok(provider);
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_published_agent_gossip(
    runtime_a: &mut ServiceNetworkRuntime,
    runtime_b: &mut ServiceNetworkRuntime,
) -> anyhow::Result<PublishedAgentRecord> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for published agent gossip");
        }
        let _ = runtime_a.try_next_event()?;
        if let Some(ServiceNetworkRuntimeEvent::PublishedAgentRecordPublished { record, .. }) =
            runtime_b.try_next_event()?
        {
            return Ok(record);
        }
        sleep(Duration::from_millis(25)).await;
    }
}
