use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::time::sleep;
use wattswarm_servicenet_p2p::{
    Multiaddr, ServiceNetworkNode, ServiceNetworkP2pConfig, ServiceNetworkRuntime,
    ServiceNetworkRuntimeEvent,
};
use wattswarm_servicenet_protocol::{PublishedAgentRecord, PublishedAgentStatus, RiskLevel};

fn demo_published_agent() -> PublishedAgentRecord {
    PublishedAgentRecord {
        agent_id: "twilio-agent".to_owned(),
        provider_id: "provider-local".to_owned(),
        version: "0.1.0".to_owned(),
        status: PublishedAgentStatus::Approved,
        agent_card: serde_json::json!({
            "name": "Twilio Agent",
            "description": "Messaging",
            "url": "https://twilio-agent.example.com",
            "preferredTransport": "JSONRPC",
            "protocolVersion": "1.0",
            "skills": [{ "id": "messaging.send_sms" }],
            "securitySchemes": { "oauth2": { "type": "oauth2" } },
            "security": [{ "oauth2": ["messaging:write"] }]
        }),
        deployment: wattswarm_servicenet_protocol::AgentDeployment {
            runtime: "remote_http".to_owned(),
            endpoint: wattswarm_servicenet_protocol::AgentDeploymentEndpoint {
                url: "https://twilio-agent.example.com/a2a".to_owned(),
                protocol_binding: "JSONRPC".to_owned(),
                protocol_version: "1.0".to_owned(),
            },
        },
        review: wattswarm_servicenet_protocol::AgentReviewProfile {
            risk_level: RiskLevel::Low,
            data_classes: vec![],
            destructive_actions: vec![],
            human_approval_required: false,
            allowed_regions: vec!["AU".to_owned()],
            cost_per_call_units: None,
        },
        approved_at: Utc::now(),
        updated_at: Utc::now(),
        reviewed_by: "moderator-a".to_owned(),
        review_notes: Some("approved".to_owned()),
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
async fn late_joiner_receives_published_agent_over_backfill() {
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

    let record = demo_published_agent();

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
        .send_published_agent_sync_request(&peer_a, 256)
        .expect("published agent sync request should send");
    let channel = wait_for_sync_request(&mut runtime_a, &mut runtime_b)
        .await
        .expect("sync request should arrive");
    runtime_a
        .send_published_agent_sync_response(channel, std::slice::from_ref(&record))
        .expect("sync response should send");

    let records = wait_for_sync_response(&mut runtime_a, &mut runtime_b)
        .await
        .expect("sync response should arrive");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].agent_id, record.agent_id);
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

async fn wait_for_sync_request(
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

async fn wait_for_sync_response(
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
