use std::{env, fs, path::PathBuf};
use std::{
    sync::OnceLock,
    time::{Duration, Instant},
};

use chrono::Utc;
use tokio::time::sleep;
use uuid::Uuid;
use watt_servicenet_p2p::{
    ServiceNetworkNode, ServiceNetworkP2pConfig, ServiceNetworkRuntime, ServiceNetworkRuntimeEvent,
};
use watt_servicenet_protocol::{ProviderRecord, ProviderStatus, SERVICE_PROTOCOL_SCHEMA_VERSION};

fn demo_provider() -> ProviderRecord {
    ProviderRecord {
        schema_version: SERVICE_PROTOCOL_SCHEMA_VERSION,
        provider_id: "provider-local".to_owned(),
        provider_did: "did:key:z6MkpTHR8VNsBxYAAWHut2GeaddA1bbm8CLcfJ4pKzvmWwLp".to_owned(),
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

fn test_config(network_id: &str) -> ServiceNetworkP2pConfig {
    let mut config = ServiceNetworkP2pConfig {
        state_dir: temp_state_dir("provider-sync"),
        listen_addrs: vec!["127.0.0.1:0".to_owned()],
        ..ServiceNetworkP2pConfig::default()
    };
    config.namespace.network_id = network_id.to_owned();
    config
}

fn test_network_id(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

static P2P_TEST_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn p2p_test_lock() -> &'static tokio::sync::Mutex<()> {
    P2P_TEST_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn temp_state_dir(prefix: &str) -> PathBuf {
    let dir = env::temp_dir().join(format!("servicenet-{prefix}-{}", Uuid::new_v4().simple()));
    fs::create_dir_all(&dir).expect("create temp state dir");
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_gossip_syncs_between_two_nodes() {
    let _guard = p2p_test_lock().lock().await;
    let network_id = test_network_id("provider-gossip");
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

    let provider = demo_provider();
    publish_when_ready(&mut runtime_a, &mut runtime_b, &provider)
        .await
        .expect("provider publish should succeed");

    let received = wait_for_provider(&mut runtime_a, &mut runtime_b)
        .await
        .expect("provider should arrive");
    assert_eq!(received, provider);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_revocation_update_syncs_between_two_nodes() {
    let _guard = p2p_test_lock().lock().await;
    let network_id = test_network_id("provider-revocation");
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

    let active_provider = demo_provider();
    publish_when_ready(&mut runtime_a, &mut runtime_b, &active_provider)
        .await
        .expect("active provider publish should succeed");
    let received_active = wait_for_provider(&mut runtime_a, &mut runtime_b)
        .await
        .expect("active provider should arrive");
    assert_eq!(received_active, active_provider);

    let revoked_provider = revoked_provider();
    publish_when_ready(&mut runtime_a, &mut runtime_b, &revoked_provider)
        .await
        .expect("revoked provider publish should succeed");
    let received_revoked = wait_for_provider(&mut runtime_a, &mut runtime_b)
        .await
        .expect("revoked provider should arrive");
    assert_eq!(received_revoked, revoked_provider);
    assert_eq!(received_revoked.provider_id, received_active.provider_id);
    assert_eq!(received_revoked.status, ProviderStatus::Revoked);
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
    provider: &ProviderRecord,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for publish readiness");
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

async fn wait_for_provider(
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
