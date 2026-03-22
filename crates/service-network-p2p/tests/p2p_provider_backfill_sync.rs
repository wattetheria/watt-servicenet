use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::time::sleep;
use wattswarm_servicenet_p2p::{
    Multiaddr, ServiceNetworkNode, ServiceNetworkP2pConfig, ServiceNetworkRuntime,
    ServiceNetworkRuntimeEvent,
};
use wattswarm_servicenet_protocol::{
    ProviderRecord, ProviderStatus, SERVICE_PROTOCOL_SCHEMA_VERSION,
};

fn demo_provider() -> ProviderRecord {
    ProviderRecord {
        schema_version: SERVICE_PROTOCOL_SCHEMA_VERSION,
        provider_id: "provider-local".to_owned(),
        provider_public_key: "cHJvdmlkZXItbG9jYWwtZGV2a2V5".to_owned(),
        display_name: Some("Provider Local".to_owned()),
        status: ProviderStatus::Active,
        registered_at: Utc::now(),
        revoked_at: None,
        revoke_reason: None,
    }
}

fn revoked_provider() -> ProviderRecord {
    ProviderRecord {
        status: ProviderStatus::Revoked,
        revoked_at: Some(Utc::now()),
        revoke_reason: Some("policy_violation".to_owned()),
        ..demo_provider()
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
async fn late_joiner_receives_existing_provider_over_backfill() {
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

    let provider = demo_provider();

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
    let channel = wait_for_provider_sync_request(&mut runtime_a, &mut runtime_b)
        .await
        .expect("provider sync request should arrive");
    runtime_a
        .send_provider_sync_response(channel, std::slice::from_ref(&provider))
        .expect("provider sync response should send");

    let providers = wait_for_provider_sync_response(&mut runtime_a, &mut runtime_b)
        .await
        .expect("provider sync response should arrive");
    assert_eq!(providers, vec![provider]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_joiner_receives_revoked_provider_over_backfill() {
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

    let provider = revoked_provider();

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
    let channel = wait_for_provider_sync_request(&mut runtime_a, &mut runtime_b)
        .await
        .expect("provider sync request should arrive");
    runtime_a
        .send_provider_sync_response(channel, std::slice::from_ref(&provider))
        .expect("provider sync response should send");

    let providers = wait_for_provider_sync_response(&mut runtime_a, &mut runtime_b)
        .await
        .expect("provider sync response should arrive");
    assert_eq!(providers, vec![provider.clone()]);
    assert_eq!(providers[0].status, ProviderStatus::Revoked);
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
