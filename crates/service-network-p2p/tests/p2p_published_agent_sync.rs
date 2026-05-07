use std::time::{Duration, Instant};
use std::{env, fs, path::PathBuf};

use chrono::Utc;
use tokio::time::sleep;
use uuid::Uuid;
use watt_servicenet_p2p::{
    ServiceNetworkNode, ServiceNetworkP2pConfig, ServiceNetworkRuntime, ServiceNetworkRuntimeEvent,
};
use watt_servicenet_protocol::{
    AgentInteractionProtocol, PublishedAgentRecord, PublishedAgentStatus, RiskLevel,
};

fn demo_published_agent() -> PublishedAgentRecord {
    PublishedAgentRecord {
        agent_id: "stripe-agent".to_owned(),
        provider_id: "provider-local".to_owned(),
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
        deployment: watt_servicenet_protocol::AgentDeployment {
            runtime: "remote_http".to_owned(),
            endpoint: watt_servicenet_protocol::AgentDeploymentEndpoint {
                url: "https://stripe-agent.example.com/a2a".to_owned(),
                protocol_binding: "JSONRPC".to_owned(),
                protocol_version: "1.0".to_owned(),
                interaction_protocol: AgentInteractionProtocol::GoogleA2a,
            },
        },
        review: watt_servicenet_protocol::AgentReviewProfile {
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
        review_notes: Some("approved".to_owned()),
    }
}

fn test_config(network_id: &str) -> ServiceNetworkP2pConfig {
    let mut config = ServiceNetworkP2pConfig {
        state_dir: temp_state_dir("published-agent-sync"),
        listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".to_owned()],
        ..ServiceNetworkP2pConfig::default()
    };
    config.namespace.network_id = network_id.to_owned();
    config
}

fn test_network_id(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

fn temp_state_dir(prefix: &str) -> PathBuf {
    let dir = env::temp_dir().join(format!("servicenet-{prefix}-{}", Uuid::new_v4().simple()));
    fs::create_dir_all(&dir).expect("create temp state dir");
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn published_agent_gossip_syncs_between_two_nodes() {
    let network_id = test_network_id("published-agent-gossip");
    let mut runtime_a = ServiceNetworkRuntime::new(
        ServiceNetworkNode::generate(test_config(&network_id)).expect("node a should start"),
    )
    .expect("runtime a should start");
    runtime_a
        .subscribe_global()
        .expect("runtime a should subscribe");

    let listen_addr = wait_for_listen_addr(&mut runtime_a)
        .await
        .expect("runtime a should listen");
    let peer_a = runtime_a.local_peer_id();

    let mut config_b = test_config(&network_id);
    config_b.bootstrap_peers = vec![format!("{peer_a}@{listen_addr}")];
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

    let record = demo_published_agent();
    publish_when_ready(&mut runtime_a, &mut runtime_b, &record)
        .await
        .expect("published agent gossip should succeed");

    let received = wait_for_record(&mut runtime_a, &mut runtime_b)
        .await
        .expect("published agent should arrive");
    assert_eq!(received.agent_id, record.agent_id);
    assert_eq!(received.provider_id, record.provider_id);
}

async fn wait_for_listen_addr(
    runtime: &mut ServiceNetworkRuntime,
) -> anyhow::Result<watt_servicenet_p2p::NetworkAddress> {
    if let Some(address) = runtime.listen_addrs().first().cloned() {
        return Ok(address);
    }
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

async fn publish_when_ready(
    runtime_a: &mut ServiceNetworkRuntime,
    runtime_b: &mut ServiceNetworkRuntime,
    record: &PublishedAgentRecord,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for publish readiness");
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

async fn wait_for_record(
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
