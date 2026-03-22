use anyhow::Result;
use serde::{Deserialize, Serialize};
use wattswarm_network_substrate::{
    BackfillRequestId, BackfillResponseChannel, NetworkRuntimeObservabilitySnapshot,
    RawBackfillRequest, RawBackfillResponse, RawGossipMessage, SubstrateConfig, SubstrateNode,
    SubstrateRuntime, SubstrateRuntimeEvent, SwarmScope, TopicKind, TopicNamespace,
};
use watt_servicenet_protocol::{ProviderRecord, PublishedAgentRecord};

pub use wattswarm_network_substrate::{Multiaddr, PeerHandshakeMetadata, PeerId};

pub const SERVICENET_IDENTIFY_AGENT_PREFIX: &str = "wattswarm-servicenet-p2p";
pub const PROVIDER_FEED_KEY: &str = "provider_record";
pub const PUBLISHED_AGENT_FEED_KEY: &str = "published_agent_record";

pub fn encode_servicenet_agent_version(metadata: &PeerHandshakeMetadata) -> String {
    metadata.encode_agent_version_with_prefix(SERVICENET_IDENTIFY_AGENT_PREFIX)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum ServiceNetworkMessage {
    ProviderPublished(ProviderRecord),
    PublishedAgentRecordPublished(PublishedAgentRecord),
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
}

impl ServiceNetworkNode {
    pub fn generate(config: ServiceNetworkP2pConfig) -> Result<Self> {
        Ok(Self {
            inner: SubstrateNode::generate(config.as_substrate())?,
        })
    }
}

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
}

impl ServiceNetworkRuntime {
    pub fn new(node: ServiceNetworkNode) -> Result<Self> {
        Ok(Self {
            inner: SubstrateRuntime::new(node.inner)?,
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

    pub fn publish_provider(&mut self, provider: &ProviderRecord) -> Result<()> {
        let message = ServiceNetworkMessage::ProviderPublished(provider.clone());
        self.inner.publish(
            &SwarmScope::Global,
            TopicKind::Rules,
            &message.encode_json()?,
        )
    }

    pub fn publish_published_agent_record(&mut self, record: &PublishedAgentRecord) -> Result<()> {
        let message = ServiceNetworkMessage::PublishedAgentRecordPublished(record.clone());
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
            .map(serde_json::to_vec)
            .collect::<serde_json::Result<Vec<_>>>()?;
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
            .map(serde_json::to_vec)
            .collect::<serde_json::Result<Vec<_>>>()?;
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
            if let Some(event) = Self::map_runtime_event(self.inner.next_event().await?)? {
                return Ok(event);
            }
        }
    }

    pub fn try_next_event(&mut self) -> Result<Option<ServiceNetworkRuntimeEvent>> {
        self.inner
            .try_next_event()?
            .map(Self::map_runtime_event)
            .transpose()
            .map(|event| event.flatten())
    }

    fn map_runtime_event(
        event: SubstrateRuntimeEvent,
    ) -> Result<Option<ServiceNetworkRuntimeEvent>> {
        Ok(match event {
            SubstrateRuntimeEvent::NewListenAddr { address } => {
                Some(ServiceNetworkRuntimeEvent::NewListenAddr { address })
            }
            SubstrateRuntimeEvent::ConnectionEstablished { peer } => {
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
                ServiceNetworkMessage::ProviderPublished(provider) => {
                    Some(ServiceNetworkRuntimeEvent::ProviderPublished {
                        peer: propagation_source,
                        provider,
                    })
                }
                ServiceNetworkMessage::PublishedAgentRecordPublished(record) => {
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
                    .map(|item| serde_json::from_slice::<ProviderRecord>(&item))
                    .collect::<serde_json::Result<Vec<_>>>()?;
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
                    .map(|item| serde_json::from_slice::<PublishedAgentRecord>(&item))
                    .collect::<serde_json::Result<Vec<_>>>()?;
                Some(ServiceNetworkRuntimeEvent::PublishedAgentSyncResponse {
                    peer,
                    request_id,
                    records,
                })
            }
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use watt_servicenet_protocol::{
        AgentDeployment, AgentDeploymentEndpoint, AgentReviewProfile, ProviderStatus,
        PublishedAgentStatus, RiskLevel, SERVICE_PROTOCOL_SCHEMA_VERSION,
    };

    fn demo_provider() -> ProviderRecord {
        ProviderRecord {
            schema_version: SERVICE_PROTOCOL_SCHEMA_VERSION,
            provider_id: "provider-local".to_owned(),
            provider_public_key: "cHJvdmlkZXItbG9jYWwtZGV2a2V5".to_owned(),
            display_name: Some("Provider Local".to_owned()),
            status: ProviderStatus::Active,
            registered_at: chrono::Utc::now(),
            revoked_at: None,
            revoke_reason: None,
        }
    }

    #[test]
    fn provider_message_round_trip() {
        let message = ServiceNetworkMessage::ProviderPublished(demo_provider());
        let bytes = message.encode_json().expect("encode should work");
        let decoded = ServiceNetworkMessage::decode_json(&bytes).expect("decode should work");
        assert_eq!(message, decoded);
    }

    #[test]
    fn published_agent_message_round_trip() {
        let message = ServiceNetworkMessage::PublishedAgentRecordPublished(demo_published_agent());
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

    #[test]
    fn published_agent_gossip_round_trip_from_substrate_event() {
        let record = demo_published_agent();
        let event = SubstrateRuntimeEvent::Gossip {
            propagation_source: PeerId::random(),
            message: RawGossipMessage {
                scope: SwarmScope::Global,
                kind: TopicKind::Rules,
                payload: ServiceNetworkMessage::PublishedAgentRecordPublished(record.clone())
                    .encode_json()
                    .expect("encode should work"),
            },
        };

        match ServiceNetworkRuntime::map_runtime_event(event)
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

    #[test]
    fn ignores_unrelated_feed_key() {
        let event = SubstrateRuntimeEvent::Gossip {
            propagation_source: PeerId::random(),
            message: RawGossipMessage {
                scope: SwarmScope::Global,
                kind: TopicKind::Messages,
                payload: b"ignored".to_vec(),
            },
        };
        let mapped = ServiceNetworkRuntime::map_runtime_event(event).expect("mapping should work");
        assert!(mapped.is_none());
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
