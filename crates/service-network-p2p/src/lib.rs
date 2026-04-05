use anyhow::{Result, anyhow, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use watt_servicenet_protocol::{ProviderRecord, PublishedAgentRecord};
use wattswarm_artifact_store::{ArtifactKind, ArtifactStore};
use wattswarm_network_substrate::{
    BackfillRequestId, BackfillResponseChannel, NetworkRuntimeObservabilitySnapshot,
    RawBackfillRequest, RawBackfillResponse, RawGossipMessage, SubstrateConfig, SubstrateNode,
    SubstrateRuntime, SubstrateRuntimeEvent, SwarmScope, TopicKind, TopicNamespace,
};
use wattswarm_network_transport_core::{
    DirectDataFetchRequest, DirectDataObjectKind, PeerTransportCapabilities, TransferIntent,
    TransportContactMaterial, TransportRoute, TransportRouter,
};
use wattswarm_network_transport_iroh::{
    export_local_contact_material, fetch_direct_data, shutdown_local_iroh_data_plane,
};

pub use wattswarm_network_substrate::{Multiaddr, PeerHandshakeMetadata, PeerId};
pub use wattswarm_network_transport_core::{
    PeerTransportCapabilities as ServiceNetworkTransportCapabilities,
    TransferIntent as ServiceNetworkTransferIntent, TransferKind as ServiceNetworkTransferKind,
    TransportContactMaterial as ServiceNetworkTransportContactMaterial,
    TransportRoute as ServiceNetworkTransportRoute,
};

pub const SERVICENET_IDENTIFY_AGENT_PREFIX: &str = "wattswarm-servicenet-p2p";
pub const PROVIDER_FEED_KEY: &str = "provider_record";
pub const PUBLISHED_AGENT_FEED_KEY: &str = "published_agent_record";
const NODE_SEED_FILE: &str = "node_seed.hex";
const CONTACT_MATERIAL_FILE: &str = "peer_transport_contacts.json";
const STATE_LOCK_FILE: &str = ".servicenet-p2p.lock";

pub fn encode_servicenet_agent_version(metadata: &PeerHandshakeMetadata) -> String {
    metadata.encode_agent_version_with_prefix(SERVICENET_IDENTIFY_AGENT_PREFIX)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceNetworkContentRef {
    pub uri: String,
    pub digest: String,
    pub size_bytes: u64,
    pub mime: String,
    pub created_at: u64,
    pub producer: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceNetworkContentEnvelope {
    pub content_ref: ServiceNetworkContentRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_contact_material: Option<TransportContactMaterial>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum ServiceNetworkMessage {
    ProviderPublished(ServiceNetworkContentEnvelope),
    PublishedAgentRecordPublished(ServiceNetworkContentEnvelope),
}

impl ServiceNetworkMessage {
    pub fn encode_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceNetworkP2pConfig {
    pub state_dir: PathBuf,
    pub namespace: TopicNamespace,
    pub protocol_version: String,
    pub identify_agent_version: String,
    pub listen_addrs: Vec<String>,
    pub bootstrap_peers: Vec<String>,
    pub enable_mdns: bool,
    pub max_established_per_peer: u32,
    pub gossipsub_d: usize,
    pub gossipsub_d_low: usize,
    pub gossipsub_d_high: usize,
    pub gossipsub_heartbeat_ms: u64,
    pub gossipsub_max_transmit_size: usize,
    pub max_backfill_events: usize,
    pub max_backfill_events_hard_limit: usize,
}

impl Default for ServiceNetworkP2pConfig {
    fn default() -> Self {
        let mut config = Self::from_substrate(SubstrateConfig::default());
        config.namespace.network = "wattswarm-servicenet".to_owned();
        config.protocol_version = "/wattswarm-servicenet/0.1.0".to_owned();
        config.identify_agent_version =
            encode_servicenet_agent_version(&PeerHandshakeMetadata::default());
        config
    }
}

impl ServiceNetworkP2pConfig {
    fn from_substrate(config: SubstrateConfig) -> Self {
        Self {
            state_dir: PathBuf::from(".servicenet-p2p-state"),
            namespace: config.namespace,
            protocol_version: config.protocol_version,
            identify_agent_version: config.identify_agent_version,
            listen_addrs: config.listen_addrs,
            bootstrap_peers: config.bootstrap_peers,
            enable_mdns: config.enable_mdns,
            max_established_per_peer: config.max_established_per_peer,
            gossipsub_d: config.gossipsub_d,
            gossipsub_d_low: config.gossipsub_d_low,
            gossipsub_d_high: config.gossipsub_d_high,
            gossipsub_heartbeat_ms: config.gossipsub_heartbeat_ms,
            gossipsub_max_transmit_size: config.gossipsub_max_transmit_size,
            max_backfill_events: config.max_backfill_events,
            max_backfill_events_hard_limit: config.max_backfill_events_hard_limit,
        }
    }

    fn as_substrate(&self) -> SubstrateConfig {
        SubstrateConfig {
            namespace: self.namespace.clone(),
            protocol_version: self.protocol_version.clone(),
            identify_agent_version: self.identify_agent_version.clone(),
            listen_addrs: self.listen_addrs.clone(),
            bootstrap_peers: self.bootstrap_peers.clone(),
            enable_mdns: self.enable_mdns,
            max_established_per_peer: self.max_established_per_peer,
            gossipsub_d: self.gossipsub_d,
            gossipsub_d_low: self.gossipsub_d_low,
            gossipsub_d_high: self.gossipsub_d_high,
            gossipsub_heartbeat_ms: self.gossipsub_heartbeat_ms,
            gossipsub_max_transmit_size: self.gossipsub_max_transmit_size,
            max_backfill_events: self.max_backfill_events,
            max_backfill_events_hard_limit: self.max_backfill_events_hard_limit,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.as_substrate().validate()
    }
}

pub struct ServiceNetworkNode {
    inner: SubstrateNode,
    state_dir: PathBuf,
    lock_path: PathBuf,
    lock_file: File,
}

impl ServiceNetworkNode {
    pub fn generate(config: ServiceNetworkP2pConfig) -> Result<Self> {
        initialize_state_dir(&config.state_dir)?;
        let (lock_path, lock_file) = acquire_state_dir_lock(&config.state_dir)?;
        let local_key = load_or_create_identity_keypair(&config.state_dir.join(NODE_SEED_FILE))?;
        Ok(Self {
            inner: SubstrateNode::new(config.as_substrate(), local_key)?,
            state_dir: config.state_dir,
            lock_path,
            lock_file,
        })
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ServiceNetworkRuntimeEvent {
    NewListenAddr {
        address: Multiaddr,
    },
    ConnectionEstablished {
        peer: PeerId,
    },
    ProviderPublished {
        peer: PeerId,
        provider: ProviderRecord,
    },
    PublishedAgentRecordPublished {
        peer: PeerId,
        record: PublishedAgentRecord,
    },
    ProviderSyncRequest {
        peer: PeerId,
        limit: usize,
        channel: BackfillResponseChannel,
    },
    ProviderSyncResponse {
        peer: PeerId,
        request_id: BackfillRequestId,
        providers: Vec<ProviderRecord>,
    },
    PublishedAgentSyncRequest {
        peer: PeerId,
        limit: usize,
        channel: BackfillResponseChannel,
    },
    PublishedAgentSyncResponse {
        peer: PeerId,
        request_id: BackfillRequestId,
        records: Vec<PublishedAgentRecord>,
    },
}

pub struct ServiceNetworkRuntime {
    inner: SubstrateRuntime,
    state_dir: PathBuf,
    lock_path: PathBuf,
    lock_file: File,
}

impl ServiceNetworkRuntime {
    pub fn new(node: ServiceNetworkNode) -> Result<Self> {
        Ok(Self {
            inner: SubstrateRuntime::new(node.inner)?,
            state_dir: node.state_dir,
            lock_path: node.lock_path,
            lock_file: node.lock_file,
        })
    }

    pub fn subscribe_global(&mut self) -> Result<()> {
        self.inner.subscribe_scope(&SwarmScope::Global)
    }

    pub fn observability_snapshot(&self) -> NetworkRuntimeObservabilitySnapshot {
        self.inner.observability_snapshot()
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.inner.local_peer_id()
    }

    pub fn listen_addrs(&self) -> &[Multiaddr] {
        self.inner.listen_addrs()
    }

    pub fn transport_capabilities(&self) -> PeerTransportCapabilities {
        PeerTransportCapabilities::iroh_direct_default()
    }

    pub fn export_transport_contact_material(
        &self,
        generated_at: u64,
    ) -> Result<TransportContactMaterial> {
        export_local_contact_material(&self.state_dir, &self.local_peer_id(), generated_at)
    }

    pub fn recommended_transfer_route(
        &self,
        remote_capabilities: Option<&PeerTransportCapabilities>,
        intent: &TransferIntent,
    ) -> TransportRoute {
        TransportRouter::select(intent, remote_capabilities)
    }

    pub fn publish_provider(&mut self, provider: &ProviderRecord) -> Result<()> {
        let envelope = self.materialize_record_envelope(provider)?;
        let message = ServiceNetworkMessage::ProviderPublished(envelope);
        self.inner.publish(
            &SwarmScope::Global,
            TopicKind::Rules,
            &message.encode_json()?,
        )
    }

    pub fn publish_published_agent_record(&mut self, record: &PublishedAgentRecord) -> Result<()> {
        let envelope = self.materialize_record_envelope(record)?;
        let message = ServiceNetworkMessage::PublishedAgentRecordPublished(envelope);
        self.inner.publish(
            &SwarmScope::Global,
            TopicKind::Rules,
            &message.encode_json()?,
        )
    }

    pub fn allows_outbound_backfill_to(&self, peer: &PeerId) -> bool {
        self.inner.allows_outbound_backfill_to(peer)
    }

    pub fn send_provider_sync_request(
        &mut self,
        peer: &PeerId,
        limit: usize,
    ) -> Result<BackfillRequestId> {
        self.inner.send_backfill_request(
            peer,
            RawBackfillRequest {
                scope: SwarmScope::Global,
                from_event_seq: 0,
                limit,
                feed_key: Some(PROVIDER_FEED_KEY.to_owned()),
            },
        )
    }

    pub fn send_provider_sync_response(
        &mut self,
        channel: BackfillResponseChannel,
        providers: &[ProviderRecord],
    ) -> Result<()> {
        let items = providers
            .iter()
            .map(|provider| {
                let envelope = self.materialize_record_envelope(provider)?;
                Ok(serde_json::to_vec(&envelope)?)
            })
            .collect::<Result<Vec<_>>>()?;
        self.inner.send_backfill_response(
            channel,
            RawBackfillResponse {
                scope: SwarmScope::Global,
                next_from_event_seq: providers.len() as u64,
                feed_key: Some(PROVIDER_FEED_KEY.to_owned()),
                items,
            },
        )
    }

    pub fn send_published_agent_sync_request(
        &mut self,
        peer: &PeerId,
        limit: usize,
    ) -> Result<BackfillRequestId> {
        self.inner.send_backfill_request(
            peer,
            RawBackfillRequest {
                scope: SwarmScope::Global,
                from_event_seq: 0,
                limit,
                feed_key: Some(PUBLISHED_AGENT_FEED_KEY.to_owned()),
            },
        )
    }

    pub fn send_published_agent_sync_response(
        &mut self,
        channel: BackfillResponseChannel,
        records: &[PublishedAgentRecord],
    ) -> Result<()> {
        let items = records
            .iter()
            .map(|record| {
                let envelope = self.materialize_record_envelope(record)?;
                Ok(serde_json::to_vec(&envelope)?)
            })
            .collect::<Result<Vec<_>>>()?;
        self.inner.send_backfill_response(
            channel,
            RawBackfillResponse {
                scope: SwarmScope::Global,
                next_from_event_seq: records.len() as u64,
                feed_key: Some(PUBLISHED_AGENT_FEED_KEY.to_owned()),
                items,
            },
        )
    }

    pub async fn next_event(&mut self) -> Result<ServiceNetworkRuntimeEvent> {
        loop {
            let runtime_event = self.inner.next_event().await?;
            if let Some(event) = self.map_runtime_event(runtime_event)? {
                return Ok(event);
            }
        }
    }

    pub fn try_next_event(&mut self) -> Result<Option<ServiceNetworkRuntimeEvent>> {
        self.inner
            .try_next_event()?
            .map(|event| self.map_runtime_event(event))
            .transpose()
            .map(|event| event.flatten())
    }

    fn map_runtime_event(
        &mut self,
        event: SubstrateRuntimeEvent,
    ) -> Result<Option<ServiceNetworkRuntimeEvent>> {
        Ok(match event {
            SubstrateRuntimeEvent::NewListenAddr { address } => {
                Some(ServiceNetworkRuntimeEvent::NewListenAddr { address })
            }
            SubstrateRuntimeEvent::ConnectionEstablished { peer, .. } => {
                Some(ServiceNetworkRuntimeEvent::ConnectionEstablished { peer })
            }
            SubstrateRuntimeEvent::Gossip {
                propagation_source,
                message:
                    RawGossipMessage {
                        kind: TopicKind::Rules,
                        payload,
                        ..
                    },
            } => match ServiceNetworkMessage::decode_json(&payload)? {
                ServiceNetworkMessage::ProviderPublished(envelope) => {
                    let provider = self
                        .hydrate_remote_record::<ProviderRecord>(&propagation_source, envelope)?;
                    Some(ServiceNetworkRuntimeEvent::ProviderPublished {
                        peer: propagation_source,
                        provider,
                    })
                }
                ServiceNetworkMessage::PublishedAgentRecordPublished(envelope) => {
                    let record = self.hydrate_remote_record::<PublishedAgentRecord>(
                        &propagation_source,
                        envelope,
                    )?;
                    Some(ServiceNetworkRuntimeEvent::PublishedAgentRecordPublished {
                        peer: propagation_source,
                        record,
                    })
                }
            },
            SubstrateRuntimeEvent::BackfillRequest {
                peer,
                request,
                channel,
            } if request.scope == SwarmScope::Global
                && request.feed_key.as_deref() == Some(PROVIDER_FEED_KEY) =>
            {
                Some(ServiceNetworkRuntimeEvent::ProviderSyncRequest {
                    peer,
                    limit: request.limit,
                    channel,
                })
            }
            SubstrateRuntimeEvent::BackfillRequest {
                peer,
                request,
                channel,
            } if request.scope == SwarmScope::Global
                && request.feed_key.as_deref() == Some(PUBLISHED_AGENT_FEED_KEY) =>
            {
                Some(ServiceNetworkRuntimeEvent::PublishedAgentSyncRequest {
                    peer,
                    limit: request.limit,
                    channel,
                })
            }
            SubstrateRuntimeEvent::BackfillResponse {
                peer,
                request_id,
                response,
            } if response.scope == SwarmScope::Global
                && response.feed_key.as_deref() == Some(PROVIDER_FEED_KEY) =>
            {
                let providers = response
                    .items
                    .into_iter()
                    .map(|item| -> Result<ProviderRecord> {
                        let envelope =
                            serde_json::from_slice::<ServiceNetworkContentEnvelope>(&item)?;
                        self.hydrate_remote_record::<ProviderRecord>(&peer, envelope)
                    })
                    .collect::<Result<Vec<_>>>()?;
                Some(ServiceNetworkRuntimeEvent::ProviderSyncResponse {
                    peer,
                    request_id,
                    providers,
                })
            }
            SubstrateRuntimeEvent::BackfillResponse {
                peer,
                request_id,
                response,
            } if response.scope == SwarmScope::Global
                && response.feed_key.as_deref() == Some(PUBLISHED_AGENT_FEED_KEY) =>
            {
                let records = response
                    .items
                    .into_iter()
                    .map(|item| -> Result<PublishedAgentRecord> {
                        let envelope =
                            serde_json::from_slice::<ServiceNetworkContentEnvelope>(&item)?;
                        self.hydrate_remote_record::<PublishedAgentRecord>(&peer, envelope)
                    })
                    .collect::<Result<Vec<_>>>()?;
                Some(ServiceNetworkRuntimeEvent::PublishedAgentSyncResponse {
                    peer,
                    request_id,
                    records,
                })
            }
            _ => None,
        })
    }

    fn materialize_record_envelope<T>(&self, record: &T) -> Result<ServiceNetworkContentEnvelope>
    where
        T: Serialize,
    {
        let content_ref = materialize_json_content_artifact(
            &self.state_dir,
            &self.local_peer_id().to_string(),
            record,
        )?;
        Ok(ServiceNetworkContentEnvelope {
            content_ref,
            transport_contact_material: Some(self.export_transport_contact_material(now_ms())?),
        })
    }

    fn hydrate_remote_record<T>(
        &mut self,
        remote_peer: &PeerId,
        envelope: ServiceNetworkContentEnvelope,
    ) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let contact =
            self.resolve_remote_contact(remote_peer, envelope.transport_contact_material)?;
        let bytes = fetch_direct_data(
            &self.state_dir,
            &self.local_peer_id(),
            &contact,
            &DirectDataFetchRequest {
                object_kind: DirectDataObjectKind::ReferenceArtifact,
                object_id: envelope.content_ref.digest.clone(),
                scope: None,
                source_uri: Some(envelope.content_ref.uri.clone()),
                expected_digest: Some(envelope.content_ref.digest.clone()),
                expected_size: Some(envelope.content_ref.size_bytes),
            },
        )?
        .bytes;
        let artifact_store = open_local_artifact_store(&self.state_dir)?;
        artifact_store.write_validated_bytes(
            ArtifactKind::Reference,
            &envelope.content_ref.digest,
            None,
            &bytes,
            Some(&envelope.content_ref.digest),
            Some(envelope.content_ref.size_bytes),
        )?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn resolve_remote_contact(
        &mut self,
        remote_peer: &PeerId,
        inline_contact: Option<TransportContactMaterial>,
    ) -> Result<TransportContactMaterial> {
        let remote_peer_id = remote_peer.to_string();
        if let Some(contact) = inline_contact {
            if contact.peer_id != remote_peer_id {
                bail!(
                    "transport contact peer mismatch: expected {}, got {}",
                    remote_peer_id,
                    contact.peer_id
                );
            }
            save_remote_contact_material(&self.state_dir, &remote_peer_id, contact.clone())?;
            return Ok(contact);
        }
        load_remote_contact_material(&self.state_dir, &remote_peer_id)?
            .ok_or_else(|| anyhow!("missing transport contact material for {remote_peer_id}"))
    }
}

impl Drop for ServiceNetworkRuntime {
    fn drop(&mut self) {
        shutdown_local_iroh_data_plane(&self.state_dir);
        let _ = fs::remove_file(&self.lock_path);
        let _ = self.lock_file.sync_all();
    }
}

fn initialize_state_dir(state_dir: &Path) -> Result<()> {
    fs::create_dir_all(state_dir)?;
    open_local_artifact_store(state_dir)?;
    Ok(())
}

fn acquire_state_dir_lock(state_dir: &Path) -> Result<(PathBuf, File)> {
    let lock_path = state_dir.join(STATE_LOCK_FILE);
    let lock_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&lock_path)
        .map_err(|err| anyhow!("lock state dir {}: {err}", state_dir.display()))?;
    Ok((lock_path, lock_file))
}

fn load_or_create_identity_keypair(seed_file: &Path) -> Result<libp2p_identity::Keypair> {
    if seed_file.exists() {
        let mut bytes = hex::decode(fs::read_to_string(seed_file)?.trim())?;
        if bytes.len() != 32 {
            bail!("seed must be 32 bytes");
        }
        return Ok(libp2p_identity::Keypair::ed25519_from_bytes(&mut bytes)?);
    }

    let seed: [u8; 32] = rand::random();
    if let Some(parent) = seed_file.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(seed_file, hex::encode(seed))?;
    Ok(libp2p_identity::Keypair::ed25519_from_bytes(seed.to_vec())?)
}

fn artifact_store_path(state_dir: &Path) -> PathBuf {
    state_dir.join("artifacts")
}

fn open_local_artifact_store(state_dir: &Path) -> Result<ArtifactStore> {
    let store = ArtifactStore::new(artifact_store_path(state_dir));
    store.ensure_layout()?;
    Ok(store)
}

fn content_artifact_uri(digest: &str) -> String {
    format!("artifact://reference/{digest}")
}

fn materialize_json_content_artifact<T>(
    state_dir: &Path,
    producer: &str,
    content: &T,
) -> Result<ServiceNetworkContentRef>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec(content)?;
    let digest = format!("sha256:{}", wattswarm_crypto::sha256_hex(&bytes));
    let artifact_store = open_local_artifact_store(state_dir)?;
    artifact_store.write_validated_bytes(
        ArtifactKind::Reference,
        &digest,
        None,
        &bytes,
        Some(&digest),
        Some(bytes.len() as u64),
    )?;
    Ok(ServiceNetworkContentRef {
        uri: content_artifact_uri(&digest),
        digest,
        size_bytes: bytes.len() as u64,
        mime: "application/json".to_owned(),
        created_at: now_ms(),
        producer: producer.to_owned(),
    })
}

fn contact_materials_path(state_dir: &Path) -> PathBuf {
    state_dir.join(CONTACT_MATERIAL_FILE)
}

fn load_remote_contact_materials(
    state_dir: &Path,
) -> Result<BTreeMap<String, TransportContactMaterial>> {
    let path = contact_materials_path(state_dir);
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn save_remote_contact_material(
    state_dir: &Path,
    peer_id: &str,
    contact: TransportContactMaterial,
) -> Result<()> {
    let mut contacts = load_remote_contact_materials(state_dir)?;
    contacts.insert(peer_id.to_owned(), contact);
    fs::write(
        contact_materials_path(state_dir),
        serde_json::to_vec_pretty(&contacts)?,
    )?;
    Ok(())
}

fn load_remote_contact_material(
    state_dir: &Path,
    peer_id: &str,
) -> Result<Option<TransportContactMaterial>> {
    Ok(load_remote_contact_materials(state_dir)?.remove(peer_id))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;
    use watt_servicenet_protocol::{
        AgentDeployment, AgentDeploymentEndpoint, AgentReviewProfile, PublishedAgentStatus,
        RiskLevel,
    };
    use wattswarm_network_transport_core::{TransferKind, TransportRoute};

    fn temp_state_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "servicenet-p2p-{prefix}-{}",
            Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&dir).expect("create temp state dir");
        dir
    }

    #[test]
    fn provider_message_round_trip() {
        let message = ServiceNetworkMessage::ProviderPublished(ServiceNetworkContentEnvelope {
            content_ref: ServiceNetworkContentRef {
                uri: "artifact://reference/sha256:demo".to_owned(),
                digest: "sha256:demo".to_owned(),
                size_bytes: 42,
                mime: "application/json".to_owned(),
                created_at: 123,
                producer: "peer-a".to_owned(),
            },
            transport_contact_material: None,
        });
        let bytes = message.encode_json().expect("encode should work");
        let decoded = ServiceNetworkMessage::decode_json(&bytes).expect("decode should work");
        assert_eq!(message, decoded);
    }

    #[test]
    fn published_agent_message_round_trip() {
        let message =
            ServiceNetworkMessage::PublishedAgentRecordPublished(ServiceNetworkContentEnvelope {
                content_ref: ServiceNetworkContentRef {
                    uri: "artifact://reference/sha256:demo-agent".to_owned(),
                    digest: "sha256:demo-agent".to_owned(),
                    size_bytes: 84,
                    mime: "application/json".to_owned(),
                    created_at: 456,
                    producer: "peer-b".to_owned(),
                },
                transport_contact_material: None,
            });
        let bytes = message.encode_json().expect("encode should work");
        let decoded = ServiceNetworkMessage::decode_json(&bytes).expect("decode should work");
        assert_eq!(message, decoded);
    }

    #[test]
    fn default_config_uses_servicenet_identity() {
        let config = ServiceNetworkP2pConfig::default();
        assert_eq!(config.namespace.network, "wattswarm-servicenet");
        assert!(
            config
                .identify_agent_version
                .starts_with(SERVICENET_IDENTIFY_AGENT_PREFIX)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn published_agent_gossip_round_trip_from_substrate_event() {
        let record = demo_published_agent();
        let sender_runtime = ServiceNetworkRuntime::new(
            ServiceNetworkNode::generate(ServiceNetworkP2pConfig {
                state_dir: temp_state_dir("mapping-sender"),
                ..ServiceNetworkP2pConfig::default()
            })
            .expect("node should start"),
        )
        .expect("sender runtime should start");
        let mut receiver_runtime = ServiceNetworkRuntime::new(
            ServiceNetworkNode::generate(ServiceNetworkP2pConfig {
                state_dir: temp_state_dir("mapping-receiver"),
                ..ServiceNetworkP2pConfig::default()
            })
            .expect("receiver node should start"),
        )
        .expect("receiver runtime should start");
        let envelope = sender_runtime
            .materialize_record_envelope(&record)
            .expect("record envelope");
        let event = SubstrateRuntimeEvent::Gossip {
            propagation_source: sender_runtime.local_peer_id(),
            message: RawGossipMessage {
                scope: SwarmScope::Global,
                kind: TopicKind::Rules,
                payload: ServiceNetworkMessage::PublishedAgentRecordPublished(envelope)
                    .encode_json()
                    .expect("encode should work"),
            },
        };

        match receiver_runtime
            .map_runtime_event(event)
            .expect("mapping should work")
            .expect("event should map")
        {
            ServiceNetworkRuntimeEvent::PublishedAgentRecordPublished {
                peer: _,
                record: mapped_record,
            } => {
                assert_eq!(mapped_record, record);
            }
            _ => panic!("expected published agent record"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ignores_unrelated_feed_key() {
        let mut runtime = ServiceNetworkRuntime::new(
            ServiceNetworkNode::generate(ServiceNetworkP2pConfig {
                state_dir: temp_state_dir("ignore-feed"),
                ..ServiceNetworkP2pConfig::default()
            })
            .expect("node should start"),
        )
        .expect("runtime should start");
        let event = SubstrateRuntimeEvent::Gossip {
            propagation_source: PeerId::random(),
            message: RawGossipMessage {
                scope: SwarmScope::Global,
                kind: TopicKind::Messages,
                payload: b"ignored".to_vec(),
            },
        };
        let mapped = runtime
            .map_runtime_event(event)
            .expect("mapping should work");
        assert!(mapped.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exported_contact_material_advertises_iroh_direct_capability() {
        let runtime = ServiceNetworkRuntime::new(
            ServiceNetworkNode::generate(ServiceNetworkP2pConfig {
                state_dir: temp_state_dir("contact-material"),
                ..ServiceNetworkP2pConfig::default()
            })
            .expect("node should start"),
        )
        .expect("runtime should start");

        let contact = runtime
            .export_transport_contact_material(1_764_292_800)
            .expect("contact material");

        assert_eq!(contact.transport, TransportRoute::IrohDirect.as_str());
        assert_eq!(
            contact.metadata.capabilities,
            PeerTransportCapabilities::iroh_direct_default()
        );
        assert_eq!(
            contact.metadata.endpoint_id.as_deref(),
            Some(contact.extra["endpoint_id"].as_str().expect("endpoint id"))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transport_router_prefers_iroh_for_large_backfill_when_remote_supports_it() {
        let runtime = ServiceNetworkRuntime::new(
            ServiceNetworkNode::generate(ServiceNetworkP2pConfig {
                state_dir: temp_state_dir("backfill-route"),
                ..ServiceNetworkP2pConfig::default()
            })
            .expect("node should start"),
        )
        .expect("runtime should start");

        let route = runtime.recommended_transfer_route(
            Some(&PeerTransportCapabilities::iroh_direct_default()),
            &TransferIntent {
                kind: TransferKind::BackfillChunk,
                payload_bytes: 128 * 1024,
                requires_streaming: false,
            },
        );

        assert_eq!(route, TransportRoute::IrohDirect);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transport_router_keeps_control_messages_on_libp2p() {
        let runtime = ServiceNetworkRuntime::new(
            ServiceNetworkNode::generate(ServiceNetworkP2pConfig {
                state_dir: temp_state_dir("control-route"),
                ..ServiceNetworkP2pConfig::default()
            })
            .expect("node should start"),
        )
        .expect("runtime should start");

        let route = runtime.recommended_transfer_route(
            Some(&PeerTransportCapabilities::iroh_direct_default()),
            &TransferIntent {
                kind: TransferKind::ControlMessage,
                payload_bytes: 512,
                requires_streaming: false,
            },
        );

        assert_eq!(route, TransportRoute::Libp2pControl);
    }

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
            review_notes: Some("approved".to_owned()),
        }
    }
}
