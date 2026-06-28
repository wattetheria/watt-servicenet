use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use thiserror::Error;
use uuid::Uuid;
use watt_did::{Did, DidKey, DidKeyPublicKey};
use watt_servicenet_protocol::{
    AgentInteractionProtocol, AuthContextRecord, ExecutionReceipt, GetAgentTaskRequest,
    InvocationMode, InvokeAgentRequest, InvokeAgentResponse, NormalizedSettlementRequest,
    PublishedAgentRecord, ReceiptStatus, RiskLevel, SettlementLayer, SettlementRequest,
    StoredReceipt, VerificationVerdict,
};
use watt_servicenet_registry::{RegistryError, ServiceRegistry};

const DEFAULT_SERVICENET_CONTEXT_NETWORK_ID: &str = "mainnet:watt-etheria";
const INVOCATION_REPLAY_MAX_CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("resource not found: {0}")]
    NotFound(String),
    #[error("request rejected: {0}")]
    Rejected(String),
    #[error("execution failed: {0}")]
    Execution(String),
}

#[derive(Debug, Clone, Default)]
pub struct GatewayPolicyConfig {
    pub default_max_cost_units: Option<u32>,
}

#[derive(Clone)]
pub struct GatewayService {
    registry: Arc<ServiceRegistry>,
    http_client: reqwest::Client,
    policy: GatewayPolicyConfig,
    replay_cache: Arc<Mutex<HashMap<String, u64>>>,
    receipt_signer: ReceiptSigner,
}

struct PreparedInvocation {
    record: PublishedAgentRecord,
    auth_token: Option<String>,
    adapter: Box<dyn A2aAdapter + Send + Sync>,
    normalized_settlement: Option<NormalizedSettlementRequest>,
    cost_units: Option<u32>,
    request_digest: String,
    caller_context: InvocationCallerContext,
    envelope_security: VerifiedAgentEnvelopeSecurity,
}

#[derive(Debug, Clone, Default)]
struct InvocationCallerContext {
    caller_agent_id: Option<String>,
    caller_public_id: Option<String>,
    caller_display_name: Option<String>,
    caller_node_id: Option<String>,
}

#[derive(Clone)]
struct ReceiptSigner {
    issuer_did: String,
    signing_key: Arc<SigningKey>,
}

#[derive(Debug, Clone, Default)]
struct VerifiedAgentEnvelopeSecurity {
    source_agent_id: String,
    signed_message: Value,
    nonce: Option<String>,
    issued_at_ms: Option<u64>,
    expires_at_ms: Option<u64>,
    request_digest: Option<String>,
}

#[derive(Debug, Serialize)]
struct SignedAgentEnvelopePayload<'a> {
    protocol: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport_profile: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_agent_id: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_agent_id: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_node_id: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_node_id: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capability: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_agent_card_hash: Option<&'a String>,
    message_json: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    extensions_json: Option<&'a String>,
}

#[derive(Debug, Serialize)]
struct SignedSourceAgentCardPayload<'a> {
    agent_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_id: Option<&'a String>,
    card_hash: &'a str,
    issued_at: u64,
}

impl InvocationCallerContext {
    fn service_context_id(&self, callee_agent_id: &str) -> Option<String> {
        self.caller_agent_id.as_deref().map(|caller_agent_id| {
            format!(
                "wattetheria:servicenet:{caller_agent_id}:{callee_agent_id}:{DEFAULT_SERVICENET_CONTEXT_NETWORK_ID}"
            )
        })
    }
}

impl ReceiptSigner {
    fn ephemeral() -> Self {
        let mut seed_material = Vec::new();
        seed_material.extend_from_slice(Uuid::new_v4().as_bytes());
        seed_material.extend_from_slice(
            &Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
                .to_be_bytes(),
        );
        let digest = Sha256::digest(seed_material);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest);
        let signing_key = SigningKey::from_bytes(&seed);
        let issuer_did = did_from_ed25519_public_key(&signing_key.verifying_key().to_bytes());
        Self {
            issuer_did,
            signing_key: Arc::new(signing_key),
        }
    }

    fn sign_value(&self, value: &Value) -> Result<String, GatewayError> {
        let payload = serde_jcs::to_vec(value).map_err(|error| {
            GatewayError::Execution(format!(
                "canonicalize receipt signature payload failed: {error}"
            ))
        })?;
        Ok(STANDARD.encode(self.signing_key.sign(&payload).to_bytes()))
    }
}

trait A2aAdapter: Send + Sync {
    fn send_message_method(&self) -> &'static str;

    fn get_task_method(&self) -> &'static str;

    fn version_header_name(&self) -> &'static str;

    fn build_send_message_payload(
        &self,
        request: &InvokeAgentRequest,
        settlement: Option<&NormalizedSettlementRequest>,
    ) -> Value;

    fn build_get_task_payload(&self, task_id: &str, request: &GetAgentTaskRequest) -> Value;
}

trait SettlementRailAdapter: Send + Sync {
    fn rail_id(&self) -> &'static str;

    fn layer(&self) -> SettlementLayer;

    fn normalize_request(&self, request: &Value) -> Result<Value, GatewayError>;
}

#[derive(Debug, Default)]
struct GoogleA2aAdapter;

impl A2aAdapter for GoogleA2aAdapter {
    fn send_message_method(&self) -> &'static str {
        "SendMessage"
    }

    fn get_task_method(&self) -> &'static str {
        "GetTask"
    }

    fn version_header_name(&self) -> &'static str {
        "A2A-Version"
    }

    fn build_send_message_payload(
        &self,
        request: &InvokeAgentRequest,
        settlement: Option<&NormalizedSettlementRequest>,
    ) -> Value {
        let mut parts = Vec::new();
        if let Some(message_text) = invoke_request_message_text(request) {
            parts.push(serde_json::json!({
                "kind": "text",
                "text": message_text,
            }));
        }
        if !request.input.is_null() {
            parts.push(serde_json::json!({
                "kind": "data",
                "data": request.input.clone(),
            }));
        }
        if parts.is_empty() {
            parts.push(serde_json::json!({
                "kind": "data",
                "data": Value::Null,
            }));
        }

        let mut map = serde_json::Map::new();
        if let Some(task_id) = &request.task_id {
            map.insert("taskId".to_owned(), Value::String(task_id.clone()));
        }
        if let Some(context_id) = &request.context_id {
            map.insert("contextId".to_owned(), Value::String(context_id.clone()));
        }
        if let Some(skill_id) = &request.skill_id {
            map.insert("skillId".to_owned(), Value::String(skill_id.clone()));
        }
        map.insert(
            "message".to_owned(),
            serde_json::json!({
                "role": "user",
                "parts": parts,
            }),
        );
        let mut extensions = serde_json::Map::new();
        if let Some(settlement) = settlement {
            extensions.insert("settlement".to_owned(), serde_json::json!(settlement));
        }
        if let Some(agent_envelope) = &request.agent_envelope {
            extensions.insert("agent_envelope".to_owned(), agent_envelope.clone());
        }
        if !extensions.is_empty() {
            map.insert("extensions".to_owned(), Value::Object(extensions));
        }
        Value::Object(map)
    }

    fn build_get_task_payload(&self, task_id: &str, request: &GetAgentTaskRequest) -> Value {
        serde_json::json!({
            "id": task_id,
            "historyLength": request.history_length.unwrap_or(10),
        })
    }
}

#[derive(Debug, Default)]
struct X402SettlementRailAdapter;

impl SettlementRailAdapter for X402SettlementRailAdapter {
    fn rail_id(&self) -> &'static str {
        "x402"
    }

    fn layer(&self) -> SettlementLayer {
        SettlementLayer::Web3
    }

    fn normalize_request(&self, request: &Value) -> Result<Value, GatewayError> {
        let mut normalized = match request {
            Value::Object(map) => Value::Object(map.clone()),
            Value::Null => serde_json::json!({}),
            _ => {
                return Err(GatewayError::Rejected(
                    "x402 settlement request must be a JSON object".to_owned(),
                ));
            }
        };
        if normalized.get("protocol").is_none() {
            normalized["protocol"] = Value::String("x402".to_owned());
        }
        Ok(normalized)
    }
}

fn a2a_adapter(protocol: AgentInteractionProtocol) -> Box<dyn A2aAdapter + Send + Sync> {
    match protocol {
        AgentInteractionProtocol::GoogleA2a => Box::<GoogleA2aAdapter>::default(),
    }
}

fn settlement_rail_adapter(
    settlement: &SettlementRequest,
) -> Result<Box<dyn SettlementRailAdapter + Send + Sync>, GatewayError> {
    match (
        settlement.layer,
        settlement.rail.trim().to_ascii_lowercase().as_str(),
    ) {
        (SettlementLayer::Web3, "x402") => Ok(Box::<X402SettlementRailAdapter>::default()),
        (SettlementLayer::Web3, rail) => Err(GatewayError::Rejected(format!(
            "unsupported web3 settlement rail: {rail}"
        ))),
        (SettlementLayer::Web2, rail) => Err(GatewayError::Rejected(format!(
            "web2 settlement rail is not implemented yet: {rail}"
        ))),
    }
}

impl GatewayService {
    pub fn new(registry: Arc<ServiceRegistry>) -> Self {
        Self::with_policy(registry, GatewayPolicyConfig::default())
    }

    pub fn with_policy(registry: Arc<ServiceRegistry>, policy: GatewayPolicyConfig) -> Self {
        Self {
            registry,
            http_client: reqwest::Client::new(),
            policy,
            replay_cache: Arc::new(Mutex::new(HashMap::new())),
            receipt_signer: ReceiptSigner::ephemeral(),
        }
    }

    pub async fn invoke_agent(
        &self,
        agent_id: &str,
        request: InvokeAgentRequest,
    ) -> Result<InvokeAgentResponse, GatewayError> {
        let prepared = self.prepare_invocation(agent_id, &request).await?;
        self.execute_prepared_invocation(
            agent_id,
            request,
            prepared,
            Uuid::new_v4(),
            Utc::now(),
            InvocationMode::Sync,
        )
        .await
    }

    pub async fn invoke_agent_async(
        &self,
        agent_id: &str,
        request: InvokeAgentRequest,
    ) -> Result<InvokeAgentResponse, GatewayError> {
        let prepared = self.prepare_invocation(agent_id, &request).await?;
        let receipt_id = Uuid::new_v4();
        let started_at = Utc::now();
        let mut execution_receipt = ExecutionReceipt {
            receipt_id,
            agent_id: prepared.record.agent_id.clone(),
            provider_id: prepared.record.provider_id.clone(),
            caller_agent_id: prepared.caller_context.caller_agent_id.clone(),
            caller_public_id: prepared.caller_context.caller_public_id.clone(),
            caller_display_name: prepared.caller_context.caller_display_name.clone(),
            caller_node_id: prepared.caller_context.caller_node_id.clone(),
            invoke_mode: InvocationMode::Async,
            status: ReceiptStatus::Running,
            verification: VerificationVerdict::NotRequired,
            request_digest: prepared.request_digest.clone(),
            result_digest: None,
            invocation_attestation: None,
            receipt_issuer_did: None,
            receipt_signed_at_ms: None,
            receipt_signature: None,
            started_at,
            completed_at: None,
            cost_units: prepared.cost_units,
        };
        self.attach_receipt_security(&mut execution_receipt, &prepared)?;
        let running = StoredReceipt {
            receipt: execution_receipt,
            output: None,
            stderr: None,
        };
        let stored = self
            .registry
            .record_receipt(&running)
            .await
            .map_err(map_registry_error)?;
        let service = self.clone();
        let agent_id_owned = agent_id.to_owned();
        tokio::spawn(async move {
            if let Err(error) = service
                .execute_prepared_invocation(
                    &agent_id_owned,
                    request,
                    prepared,
                    receipt_id,
                    started_at,
                    InvocationMode::Async,
                )
                .await
            {
                let _ = service
                    .record_failed_invocation(receipt_id, error.to_string())
                    .await;
            }
        });
        Ok(InvokeAgentResponse {
            agent_id: agent_id.to_owned(),
            status: "running".to_owned(),
            receipt_id: Some(stored.receipt.receipt_id),
            task_id: None,
            context_id: None,
            message: Some("ServiceNet invocation accepted".to_owned()),
            settlement: None,
            payment_receipt: None,
            output: None,
            raw: serde_json::json!({
                "agent_id": agent_id,
                "status": "running",
                "receipt_id": stored.receipt.receipt_id
            }),
        })
    }

    async fn prepare_invocation(
        &self,
        agent_id: &str,
        request: &InvokeAgentRequest,
    ) -> Result<PreparedInvocation, GatewayError> {
        let record = self
            .registry
            .get_published_agent(agent_id)
            .await
            .map_err(map_registry_error)?;
        let normalized_settlement = normalize_settlement_request(request.settlement.as_ref())?;
        let request_digest = invocation_request_digest(request, normalized_settlement.as_ref())?;
        let envelope_security = verify_agent_envelope_signature(request)?;
        self.enforce_invocation_replay_protection(request, &envelope_security)?;
        let auth_token = self
            .resolve_agent_auth_context(&record, request.auth_context_id)
            .await?
            .or(request.auth_token.clone());
        self.enforce_agent_preflight(&record, request, auth_token.as_deref())
            .await?;
        let adapter = a2a_adapter(record.deployment.endpoint.interaction_protocol);
        let agent_cost_units = agent_cost_units(&record.agent_card);
        let cost_units = request
            .max_cost_units
            .and(agent_cost_units)
            .or(agent_cost_units);
        Ok(PreparedInvocation {
            record,
            auth_token,
            adapter,
            normalized_settlement,
            cost_units,
            request_digest,
            caller_context: invocation_caller_context(request),
            envelope_security,
        })
    }

    async fn execute_prepared_invocation(
        &self,
        agent_id: &str,
        mut request: InvokeAgentRequest,
        prepared: PreparedInvocation,
        receipt_id: Uuid,
        started_at: DateTime<Utc>,
        invoke_mode: InvocationMode,
    ) -> Result<InvokeAgentResponse, GatewayError> {
        if request
            .context_id
            .as_deref()
            .is_none_or(|context_id| context_id.trim().is_empty())
            && let Some(context_id) = prepared.caller_context.service_context_id(agent_id)
        {
            request.context_id = Some(context_id);
        }
        let response = self
            .a2a_jsonrpc_call(
                &prepared.record,
                prepared.adapter.as_ref(),
                prepared.adapter.send_message_method(),
                prepared
                    .adapter
                    .build_send_message_payload(&request, prepared.normalized_settlement.as_ref()),
                prepared.auth_token.as_deref(),
            )
            .await?;
        let completed_at = Utc::now();
        let receipt_output = stored_invocation_output(&response);

        let mut execution_receipt = ExecutionReceipt {
            receipt_id,
            agent_id: prepared.record.agent_id.clone(),
            provider_id: prepared.record.provider_id.clone(),
            caller_agent_id: prepared.caller_context.caller_agent_id.clone(),
            caller_public_id: prepared.caller_context.caller_public_id.clone(),
            caller_display_name: prepared.caller_context.caller_display_name.clone(),
            caller_node_id: prepared.caller_context.caller_node_id.clone(),
            invoke_mode,
            status: ReceiptStatus::Succeeded,
            verification: verification_for_risk(&prepared.record.review.risk_level),
            request_digest: prepared.request_digest.clone(),
            result_digest: receipt_output
                .as_ref()
                .map(digest_value)
                .transpose()
                .map_err(|err| GatewayError::Execution(err.to_string()))?,
            invocation_attestation: None,
            receipt_issuer_did: None,
            receipt_signed_at_ms: None,
            receipt_signature: None,
            started_at,
            completed_at: Some(completed_at),
            cost_units: prepared.cost_units,
        };
        self.attach_receipt_security(&mut execution_receipt, &prepared)?;
        let receipt = StoredReceipt {
            receipt: execution_receipt,
            output: receipt_output,
            stderr: None,
        };
        let stored = self
            .registry
            .record_receipt(&receipt)
            .await
            .map_err(map_registry_error)?;
        Ok(build_invoke_agent_response(
            agent_id,
            Some(stored.receipt.receipt_id),
            prepared.normalized_settlement,
            response,
        ))
    }

    fn enforce_invocation_replay_protection(
        &self,
        request: &InvokeAgentRequest,
        security: &VerifiedAgentEnvelopeSecurity,
    ) -> Result<(), GatewayError> {
        let Some(nonce) = security.nonce.as_deref() else {
            return Ok(());
        };
        let issued_at_ms = security.issued_at_ms.ok_or_else(|| {
            GatewayError::Rejected(
                "agent_envelope.extensions.issued_at_ms is required when nonce is set".to_owned(),
            )
        })?;
        let expires_at_ms = security.expires_at_ms.ok_or_else(|| {
            GatewayError::Rejected(
                "agent_envelope.extensions.expires_at_ms is required when nonce is set".to_owned(),
            )
        })?;
        let request_digest = security.request_digest.as_deref().ok_or_else(|| {
            GatewayError::Rejected(
                "agent_envelope.extensions.request_digest is required when nonce is set".to_owned(),
            )
        })?;
        validate_signed_invocation_message_matches_request(request, &security.signed_message)?;
        if !request_digest_matches_signed_message(request_digest, &security.signed_message)
            .map_err(|err| GatewayError::Execution(err.to_string()))?
        {
            return Err(GatewayError::Rejected(
                "agent_envelope.extensions.request_digest does not match signed invocation message"
                    .to_owned(),
            ));
        }
        let now_ms = Utc::now().timestamp_millis();
        let issued_at = issued_at_ms as i64;
        let expires_at = expires_at_ms as i64;
        if issued_at - now_ms > INVOCATION_REPLAY_MAX_CLOCK_SKEW_MS {
            return Err(GatewayError::Rejected(
                "agent_envelope.extensions.issued_at_ms is too far in the future".to_owned(),
            ));
        }
        if expires_at <= issued_at {
            return Err(GatewayError::Rejected(
                "agent_envelope.extensions.expires_at_ms must be greater than issued_at_ms"
                    .to_owned(),
            ));
        }
        if expires_at + INVOCATION_REPLAY_MAX_CLOCK_SKEW_MS < now_ms {
            return Err(GatewayError::Rejected(
                "agent_envelope.extensions.expires_at_ms has already passed".to_owned(),
            ));
        }

        let mut cache = self.replay_cache.lock().map_err(|_| {
            GatewayError::Execution("invocation replay cache lock poisoned".to_owned())
        })?;
        let cutoff = now_ms.max(0) as u64;
        cache.retain(|_, expires_at_ms| *expires_at_ms >= cutoff);
        let key = format!("{}:{nonce}", security.source_agent_id);
        if cache.contains_key(&key) {
            return Err(GatewayError::Rejected(
                "agent_envelope nonce has already been used; refusing to replay".to_owned(),
            ));
        }
        cache.insert(key, expires_at_ms);
        Ok(())
    }

    fn attach_receipt_security(
        &self,
        receipt: &mut ExecutionReceipt,
        prepared: &PreparedInvocation,
    ) -> Result<(), GatewayError> {
        receipt.invocation_attestation = Some(invocation_attestation(receipt, prepared)?);
        self.sign_receipt(receipt)
    }

    fn sign_receipt(&self, receipt: &mut ExecutionReceipt) -> Result<(), GatewayError> {
        receipt.receipt_issuer_did = Some(self.receipt_signer.issuer_did.clone());
        receipt.receipt_signed_at_ms = Some(Utc::now().timestamp_millis().max(0) as u64);
        receipt.receipt_signature = None;
        let payload = receipt_signature_payload(receipt)?;
        receipt.receipt_signature = Some(self.receipt_signer.sign_value(&payload)?);
        Ok(())
    }

    async fn record_failed_invocation(
        &self,
        receipt_id: Uuid,
        error: String,
    ) -> Result<(), GatewayError> {
        let mut stored = self
            .registry
            .get_receipt(receipt_id)
            .await
            .map_err(map_registry_error)?;
        stored.receipt.status = ReceiptStatus::Failed;
        stored.receipt.completed_at = Some(Utc::now());
        let status = stored.receipt.status.clone();
        let result_digest = stored.receipt.result_digest.clone();
        if let Some(attestation) = stored
            .receipt
            .invocation_attestation
            .as_mut()
            .and_then(Value::as_object_mut)
        {
            attestation.insert("status".to_owned(), serde_json::json!(status));
            attestation.insert("result_digest".to_owned(), serde_json::json!(result_digest));
        }
        self.sign_receipt(&mut stored.receipt)?;
        stored.stderr = Some(error);
        self.registry
            .record_receipt(&stored)
            .await
            .map_err(map_registry_error)?;
        Ok(())
    }

    pub async fn get_agent_task(
        &self,
        agent_id: &str,
        task_id: &str,
        request: GetAgentTaskRequest,
    ) -> Result<InvokeAgentResponse, GatewayError> {
        let record = self
            .registry
            .get_published_agent(agent_id)
            .await
            .map_err(map_registry_error)?;
        let auth_token = self
            .resolve_agent_auth_context(&record, request.auth_context_id)
            .await?
            .or(request.auth_token.clone());
        self.enforce_agent_task_access(&record, auth_token.as_deref())
            .await?;
        let adapter = a2a_adapter(record.deployment.endpoint.interaction_protocol);
        let response = self
            .a2a_jsonrpc_call(
                &record,
                adapter.as_ref(),
                adapter.get_task_method(),
                adapter.build_get_task_payload(task_id, &request),
                auth_token.as_deref(),
            )
            .await?;
        Ok(build_invoke_agent_response(agent_id, None, None, response))
    }

    async fn resolve_agent_auth_context(
        &self,
        record: &PublishedAgentRecord,
        auth_context_id: Option<Uuid>,
    ) -> Result<Option<String>, GatewayError> {
        let Some(auth_context_id) = auth_context_id else {
            return Ok(None);
        };
        let context = self
            .registry
            .get_auth_context(auth_context_id)
            .await
            .map_err(map_registry_error)?;
        self.validate_auth_context_provider(record, &context)?;
        let token = self
            .registry
            .resolve_auth_context_token(auth_context_id)
            .await
            .map_err(map_registry_error)?;
        Ok(Some(token))
    }

    fn validate_auth_context_provider(
        &self,
        record: &PublishedAgentRecord,
        context: &AuthContextRecord,
    ) -> Result<(), GatewayError> {
        if context.provider_id != record.provider_id {
            return Err(GatewayError::Rejected(
                "auth context provider does not match target provider".to_owned(),
            ));
        }
        if context
            .expires_at
            .is_some_and(|expires_at| expires_at <= Utc::now())
        {
            return Err(GatewayError::Rejected(
                "auth context has expired".to_owned(),
            ));
        }
        Ok(())
    }

    async fn enforce_agent_preflight(
        &self,
        record: &PublishedAgentRecord,
        request: &InvokeAgentRequest,
        auth_token: Option<&str>,
    ) -> Result<(), GatewayError> {
        self.enforce_agent_task_access(record, auth_token).await?;
        if !record.review.allowed_regions.is_empty() {
            let Some(region) = request.region.as_deref() else {
                return Err(GatewayError::Rejected(
                    "region is required for this agent".to_owned(),
                ));
            };
            if !record
                .review
                .allowed_regions
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(region))
            {
                return Err(GatewayError::Rejected(
                    "requested region is not allowed".to_owned(),
                ));
            }
        }
        if let Some(max_cost_units) = request
            .max_cost_units
            .or(self.policy.default_max_cost_units)
            && agent_cost_units(&record.agent_card).is_some_and(|cost| cost > max_cost_units)
        {
            return Err(GatewayError::Rejected(
                "agent cost exceeds caller budget".to_owned(),
            ));
        }
        if matches!(record.review.risk_level, RiskLevel::High) && !request.confirm_risky {
            return Err(GatewayError::Rejected(
                "high-risk agent requires explicit confirmation".to_owned(),
            ));
        }
        Ok(())
    }

    async fn enforce_agent_task_access(
        &self,
        record: &PublishedAgentRecord,
        auth_token: Option<&str>,
    ) -> Result<(), GatewayError> {
        let provider = self
            .registry
            .get_provider(&record.provider_id)
            .await
            .map_err(map_registry_error)?;
        let provider_trust = self
            .registry
            .get_provider_trust(&record.provider_id)
            .await
            .map_err(map_registry_error)?;
        let agent_trust = self
            .registry
            .get_agent_trust(&record.agent_id)
            .await
            .map_err(map_registry_error)?;
        if provider.status == watt_servicenet_protocol::ProviderStatus::Revoked {
            return Err(GatewayError::Rejected("provider is revoked".to_owned()));
        }
        if provider_trust.blocked {
            return Err(GatewayError::Rejected("provider is blocked".to_owned()));
        }
        if agent_trust.blocked {
            return Err(GatewayError::Rejected("agent is blocked".to_owned()));
        }
        if agent_requires_auth(&record.agent_card) && auth_token.is_none() {
            return Err(GatewayError::Rejected(
                "auth token or auth context is required".to_owned(),
            ));
        }
        Ok(())
    }

    async fn a2a_jsonrpc_call(
        &self,
        record: &PublishedAgentRecord,
        adapter: &(dyn A2aAdapter + Send + Sync),
        method: &str,
        params: Value,
        auth_token: Option<&str>,
    ) -> Result<Value, GatewayError> {
        let mut builder = self
            .http_client
            .post(&record.deployment.endpoint.url)
            .header(
                adapter.version_header_name(),
                &record.deployment.endpoint.protocol_version,
            );
        if let Some(token) = auth_token {
            builder = builder.bearer_auth(token);
        }
        let response = builder
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": Uuid::new_v4().to_string(),
                "method": method,
                "params": params,
            }))
            .send()
            .await
            .map_err(|err| {
                GatewayError::Execution(classify_a2a_send_error(record, method, &err))
            })?;
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let text = response.text().await.map_err(|err| {
            GatewayError::Execution(format!(
                "callee agent response body could not be read after ServiceNet sent `{method}` to agent `{}`: {}. The target may have closed the connection while responding; the caller may retry.",
                record.agent_id, err
            ))
        })?;
        if !status.is_success() {
            return Err(GatewayError::Execution(format!(
                "callee agent returned HTTP {status} after ServiceNet sent `{method}` to agent `{}`. content_type={}; body_preview={}. This is a target agent or upstream proxy response; the caller may retry later.",
                record.agent_id,
                content_type.as_deref().unwrap_or("unknown"),
                body_preview(&text)
            )));
        }
        let body = serde_json::from_str::<Value>(&text).map_err(|err| {
            GatewayError::Execution(format!(
                "callee agent returned a non-JSON or invalid A2A response after ServiceNet sent `{method}` to agent `{}`: {err}. content_type={}; body_preview={}. This means the target agent or its upstream proxy responded, but not with valid A2A JSON; the caller may retry later.",
                record.agent_id,
                content_type.as_deref().unwrap_or("unknown"),
                body_preview(&text)
            ))
        })?;
        if let Some(error) = body.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("a2a request failed");
            return Err(GatewayError::Execution(format!(
                "callee agent returned an A2A error after ServiceNet sent `{method}` to agent `{}`: {message}. The caller may retry later if this was transient.",
                record.agent_id
            )));
        }
        Ok(body)
    }
}

fn verification_for_risk(risk_level: &RiskLevel) -> VerificationVerdict {
    match risk_level {
        RiskLevel::Low => VerificationVerdict::NotRequired,
        RiskLevel::Medium | RiskLevel::High => VerificationVerdict::Pending,
    }
}

fn agent_requires_auth(agent_card: &Value) -> bool {
    let Some(security) = agent_card.get("security") else {
        return security_schemes_require_auth(agent_card);
    };
    match security {
        Value::Array(items) => {
            !items.is_empty()
                && !items.iter().any(|item| {
                    item.as_object()
                        .is_some_and(|object| object.contains_key("none"))
                })
        }
        Value::Object(map) => !map.is_empty() && !map.contains_key("none"),
        Value::Null => false,
        _ => true,
    }
}

fn security_schemes_require_auth(agent_card: &Value) -> bool {
    agent_card
        .get("securitySchemes")
        .and_then(Value::as_object)
        .is_some_and(|schemes| {
            !schemes.is_empty()
                && !schemes.iter().all(|(name, scheme)| {
                    name == "none"
                        || scheme
                            .get("type")
                            .and_then(Value::as_str)
                            .is_some_and(|scheme_type| scheme_type.eq_ignore_ascii_case("none"))
                })
        })
}

fn agent_cost_units(agent_card: &Value) -> Option<u32> {
    agent_card
        .get("cost")
        .and_then(Value::as_u64)
        .and_then(|cost| u32::try_from(cost).ok())
}

fn invocation_request_digest(
    request: &InvokeAgentRequest,
    normalized_settlement: Option<&NormalizedSettlementRequest>,
) -> Result<String, GatewayError> {
    digest_value(&serde_json::json!({
        "task_id": request.task_id,
        "context_id": request.context_id,
        "message": request.message,
        "input": request.input,
        "skill_id": request.skill_id,
        "settlement": normalized_settlement
    }))
    .map_err(|err| GatewayError::Execution(err.to_string()))
}

fn invoke_request_message_text(request: &InvokeAgentRequest) -> Option<String> {
    request
        .message
        .as_deref()
        .and_then(non_empty_text)
        .or_else(|| message_text_from_value(&request.input))
}

fn message_text_from_value(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => non_empty_text(text),
        Value::Object(object) => {
            for key in ["message", "text", "query", "prompt"] {
                if let Some(text) = object
                    .get(key)
                    .and_then(Value::as_str)
                    .and_then(non_empty_text)
                {
                    return Some(text);
                }
            }
            object
                .get("message")
                .and_then(a2a_message_text)
                .or_else(|| a2a_message_text(value))
        }
        _ => None,
    }
}

fn a2a_message_text(value: &Value) -> Option<String> {
    value
        .get("parts")
        .and_then(Value::as_array)
        .and_then(|parts| {
            parts
                .iter()
                .filter_map(|part| part.get("text").and_then(Value::as_str))
                .find_map(non_empty_text)
        })
}

fn non_empty_text(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn invocation_caller_context(request: &InvokeAgentRequest) -> InvocationCallerContext {
    let Some(envelope) = request.agent_envelope.as_ref() else {
        return InvocationCallerContext::default();
    };
    InvocationCallerContext {
        caller_agent_id: json_string_at(envelope, &["source_agent_id"]),
        caller_public_id: json_string_at(envelope, &["extensions", "caller_public_id"])
            .or_else(|| json_string_at(envelope, &["caller_public_id"])),
        caller_display_name: json_string_at(envelope, &["source_agent_card", "card", "name"])
            .or_else(|| json_string_at(envelope, &["source_agent_card", "name"])),
        caller_node_id: json_string_at(envelope, &["source_node_id"]),
    }
}

fn verify_agent_envelope_signature(
    request: &InvokeAgentRequest,
) -> Result<VerifiedAgentEnvelopeSecurity, GatewayError> {
    let envelope = request
        .agent_envelope
        .as_ref()
        .ok_or_else(|| GatewayError::Rejected("agent_envelope is required".to_owned()))?;
    let signature = json_string_at(envelope, &["signature"])
        .ok_or_else(|| GatewayError::Rejected("agent_envelope.signature is required".to_owned()))?;
    let source_agent_id = json_string_at(envelope, &["source_agent_id"]).ok_or_else(|| {
        GatewayError::Rejected("agent_envelope.source_agent_id is required".to_owned())
    })?;
    let protocol = json_string_at(envelope, &["protocol"])
        .ok_or_else(|| GatewayError::Rejected("agent_envelope.protocol is required".to_owned()))?;
    let message = envelope
        .get("message")
        .ok_or_else(|| GatewayError::Rejected("agent_envelope.message is required".to_owned()))?;
    let message_json = serde_json::to_string(message).map_err(|error| {
        GatewayError::Rejected(format!("invalid agent_envelope.message: {error}"))
    })?;
    let extensions_json = envelope
        .get("extensions")
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| {
            GatewayError::Rejected(format!("invalid agent_envelope.extensions: {error}"))
        })?;
    verify_source_agent_card(envelope, &source_agent_id)?;
    let verified_source_agent_id = source_agent_id.clone();
    let source_agent_id = Some(source_agent_id);
    let transport_profile = json_string_at(envelope, &["transport_profile"]);
    let target_agent_id = json_string_at(envelope, &["target_agent_id"]);
    let source_node_id = json_string_at(envelope, &["source_node_id"]);
    let target_node_id = json_string_at(envelope, &["target_node_id"]);
    let capability = json_string_at(envelope, &["capability"]);
    let source_agent_card_hash = json_string_at(envelope, &["source_agent_card", "card_hash"]);
    let payload = SignedAgentEnvelopePayload {
        protocol: &protocol,
        transport_profile: transport_profile.as_ref(),
        source_agent_id: source_agent_id.as_ref(),
        target_agent_id: target_agent_id.as_ref(),
        source_node_id: source_node_id.as_ref(),
        target_node_id: target_node_id.as_ref(),
        capability: capability.as_ref(),
        source_agent_card_hash: source_agent_card_hash.as_ref(),
        message_json: &message_json,
        extensions_json: extensions_json.as_ref(),
    };
    verify_payload_signature(&payload, &signature, source_agent_id.as_deref().unwrap()).map_err(
        |error| {
            GatewayError::Rejected(format!(
                "agent_envelope signature verification failed: {error}"
            ))
        },
    )?;
    Ok(VerifiedAgentEnvelopeSecurity {
        source_agent_id: verified_source_agent_id,
        signed_message: message.clone(),
        nonce: json_string_at(envelope, &["extensions", "nonce"]),
        issued_at_ms: json_u64_at(envelope, &["extensions", "issued_at_ms"]),
        expires_at_ms: json_u64_at(envelope, &["extensions", "expires_at_ms"]),
        request_digest: json_string_at(envelope, &["extensions", "request_digest"]),
    })
}

fn verify_source_agent_card(envelope: &Value, source_agent_id: &str) -> Result<(), GatewayError> {
    let Some(card) = envelope.get("source_agent_card") else {
        return Ok(());
    };
    let card_agent_id = json_string_at(card, &["agent_id"]).ok_or_else(|| {
        GatewayError::Rejected("agent_envelope.source_agent_card.agent_id is required".to_owned())
    })?;
    if card_agent_id != source_agent_id {
        return Err(GatewayError::Rejected(
            "agent_envelope.source_agent_card.agent_id must match source_agent_id".to_owned(),
        ));
    }
    let card_hash = json_string_at(card, &["card_hash"]).ok_or_else(|| {
        GatewayError::Rejected("agent_envelope.source_agent_card.card_hash is required".to_owned())
    })?;
    let card_body = card.get("card").ok_or_else(|| {
        GatewayError::Rejected("agent_envelope.source_agent_card.card is required".to_owned())
    })?;
    let computed_hash = canonical_value_hash(card_body)?;
    if card_hash != computed_hash {
        return Err(GatewayError::Rejected(
            "agent_envelope.source_agent_card.card_hash does not match card".to_owned(),
        ));
    }
    let signature = json_string_at(card, &["signature"]).ok_or_else(|| {
        GatewayError::Rejected("agent_envelope.source_agent_card.signature is required".to_owned())
    })?;
    let issued_at = card
        .get("issued_at")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            GatewayError::Rejected(
                "agent_envelope.source_agent_card.issued_at is required".to_owned(),
            )
        })?;
    let node_id = json_string_at(card, &["node_id"]);
    let payload = SignedSourceAgentCardPayload {
        agent_id: &card_agent_id,
        node_id: node_id.as_ref(),
        card_hash: &card_hash,
        issued_at,
    };
    verify_payload_signature(&payload, &signature, source_agent_id).map_err(|error| {
        GatewayError::Rejected(format!(
            "source_agent_card signature verification failed: {error}"
        ))
    })?;
    Ok(())
}

fn verify_payload_signature(
    payload: &impl Serialize,
    signature_b64: &str,
    signer_did: &str,
) -> Result<(), GatewayError> {
    let payload = serde_jcs::to_vec(payload).map_err(|error| {
        GatewayError::Rejected(format!("canonicalize signed payload failed: {error}"))
    })?;
    let signature = STANDARD
        .decode(signature_b64)
        .map_err(|_| GatewayError::Rejected("invalid signature encoding".to_owned()))?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| GatewayError::Rejected("invalid signature length".to_owned()))?;
    let public_key = did_ed25519_public_key(signer_did)?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| GatewayError::Rejected("invalid did:key public key length".to_owned()))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| GatewayError::Rejected("invalid did:key public key bytes".to_owned()))?;
    verifying_key
        .verify(&payload, &Signature::from_bytes(&signature))
        .map_err(|_| GatewayError::Rejected("signature does not verify".to_owned()))
}

fn did_ed25519_public_key(signer_did: &str) -> Result<Vec<u8>, GatewayError> {
    let did = Did::parse(signer_did)
        .map_err(|error| GatewayError::Rejected(format!("invalid source agent DID: {error}")))?;
    let did_key = DidKey::from_did(did).map_err(|error| {
        GatewayError::Rejected(format!("unsupported source agent DID: {error}"))
    })?;
    match did_key.decode_public_key().map_err(|error| {
        GatewayError::Rejected(format!("invalid source agent DID public key: {error}"))
    })? {
        DidKeyPublicKey::Ed25519(bytes) => Ok(bytes.to_vec()),
        _ => Err(GatewayError::Rejected(
            "source agent DID must resolve to an Ed25519 key".to_owned(),
        )),
    }
}

fn canonical_value_hash(value: &Value) -> Result<String, GatewayError> {
    let bytes = serde_jcs::to_vec(value).map_err(|error| {
        GatewayError::Rejected(format!("canonicalize agent card failed: {error}"))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn did_from_ed25519_public_key(public_key: &[u8; 32]) -> String {
    format!(
        "did:key:z{}",
        bs58::encode([[0xed, 0x01].as_slice(), public_key.as_slice()].concat()).into_string()
    )
}

fn json_string_at(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for segment in path {
        current = current.get(segment)?;
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn json_u64_at(value: &Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for segment in path {
        current = current.get(segment)?;
    }
    current.as_u64()
}

fn invocation_envelope_message(request: &InvokeAgentRequest) -> Result<Value, GatewayError> {
    let mut message = serde_json::to_value(request).map_err(|error| {
        GatewayError::Execution(format!("serialize invocation request failed: {error}"))
    })?;
    if let Some(object) = message.as_object_mut() {
        object.remove("auth_token");
        object.remove("auth_context_id");
        object.remove("agent_envelope");
    }
    Ok(message)
}

fn validate_signed_invocation_message_matches_request(
    request: &InvokeAgentRequest,
    signed_message: &Value,
) -> Result<(), GatewayError> {
    let signed_request = serde_json::from_value::<InvokeAgentRequest>(signed_message.clone())
        .map_err(|error| {
            GatewayError::Rejected(format!("invalid signed invocation message: {error}"))
        })?;
    let signed_message = invocation_envelope_message(&signed_request)?;
    let request_message = invocation_envelope_message(request)?;
    if signed_message == request_message {
        return Ok(());
    }
    Err(GatewayError::Rejected(
        "agent_envelope.message does not match invocation request".to_owned(),
    ))
}

fn normalize_settlement_request(
    settlement: Option<&SettlementRequest>,
) -> Result<Option<NormalizedSettlementRequest>, GatewayError> {
    settlement
        .map(|settlement| {
            let rail = settlement_rail_adapter(settlement)?;
            Ok(NormalizedSettlementRequest {
                layer: rail.layer(),
                rail: rail.rail_id().to_owned(),
                request: rail.normalize_request(&settlement.request)?,
            })
        })
        .transpose()
}

fn invocation_attestation(
    receipt: &ExecutionReceipt,
    prepared: &PreparedInvocation,
) -> Result<Value, GatewayError> {
    let record = &prepared.record;
    Ok(serde_json::json!({
        "profile": "wattetheria.secure_agent_invocation.v1",
        "agent_id": record.agent_id,
        "service_address": record.service_address,
        "provider_id": record.provider_id,
        "endpoint_url": record.deployment.endpoint.url,
        "agent_card_digest": canonical_value_hash(&record.agent_card)?,
        "deployment_digest": digest_value(&serde_json::json!(record.deployment))
            .map_err(|error| GatewayError::Execution(error.to_string()))?,
        "published_record_digest": digest_value(&serde_json::json!(record))
            .map_err(|error| GatewayError::Execution(error.to_string()))?,
        "request_digest": receipt.request_digest,
        "result_digest": receipt.result_digest,
        "caller_agent_id": receipt.caller_agent_id,
        "caller_public_id": receipt.caller_public_id,
        "caller_node_id": receipt.caller_node_id,
        "invoke_mode": receipt.invoke_mode,
        "status": receipt.status,
        "envelope_nonce": prepared.envelope_security.nonce,
        "envelope_issued_at_ms": prepared.envelope_security.issued_at_ms,
        "envelope_expires_at_ms": prepared.envelope_security.expires_at_ms,
        "envelope_request_digest": prepared.envelope_security.request_digest,
    }))
}

fn receipt_signature_payload(receipt: &ExecutionReceipt) -> Result<Value, GatewayError> {
    let mut payload = serde_json::to_value(receipt)
        .map_err(|error| GatewayError::Execution(format!("serialize receipt failed: {error}")))?;
    if let Some(object) = payload.as_object_mut() {
        object.remove("receipt_signature");
    }
    Ok(payload)
}

fn build_invoke_agent_response(
    agent_id: &str,
    receipt_id: Option<Uuid>,
    settlement: Option<NormalizedSettlementRequest>,
    response: Value,
) -> InvokeAgentResponse {
    let task = response
        .pointer("/result/task")
        .cloned()
        .unwrap_or(Value::Null);
    let status = task
        .pointer("/status/state")
        .and_then(Value::as_str)
        .unwrap_or("TASK_STATE_UNKNOWN")
        .to_owned();
    let output = extract_task_output(&response);
    let message = extract_message_text(&response);
    InvokeAgentResponse {
        agent_id: agent_id.to_owned(),
        status,
        receipt_id,
        task_id: task
            .get("id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        context_id: task
            .get("contextId")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        message,
        settlement,
        payment_receipt: extract_payment_receipt(&response),
        output,
        raw: response,
    }
}

fn extract_task_output(response: &Value) -> Option<Value> {
    response
        .pointer("/result/task/artifacts")
        .and_then(Value::as_array)
        .and_then(|artifacts| artifacts.first())
        .and_then(|artifact| artifact.get("parts"))
        .and_then(Value::as_array)
        .and_then(|parts| parts.first())
        .and_then(extract_message_value)
}

fn stored_invocation_output(response: &Value) -> Option<Value> {
    Some(response.clone())
}

fn extract_message_text(response: &Value) -> Option<String> {
    response
        .pointer("/result/task/messages")
        .and_then(Value::as_array)
        .and_then(|messages| messages.last())
        .and_then(|message| message.get("parts"))
        .and_then(Value::as_array)
        .and_then(|parts| {
            parts.iter().find_map(|part| {
                part.get("text")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
        })
}

fn extract_message_value(part: &Value) -> Option<Value> {
    part.get("data")
        .cloned()
        .or_else(|| part.get("text").cloned())
}

fn extract_payment_receipt(response: &Value) -> Option<Value> {
    extract_task_output(response).and_then(|value| {
        value
            .get("payment_receipt")
            .cloned()
            .or_else(|| value.get("receipt").cloned())
    })
}

fn digest_value(value: &Value) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

fn jcs_sha256_digest_value(value: &Value) -> Result<String> {
    let bytes = serde_jcs::to_vec(value)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn request_digest_matches_signed_message(
    request_digest: &str,
    signed_message: &Value,
) -> Result<bool> {
    Ok(request_digest == canonical_value_hash(signed_message)?
        || request_digest == jcs_sha256_digest_value(signed_message)?)
}

fn classify_a2a_send_error(
    record: &PublishedAgentRecord,
    method: &str,
    error: &reqwest::Error,
) -> String {
    if error.is_timeout() {
        return format!(
            "ServiceNet sent `{method}` to agent `{}` but did not receive a response before timeout: {error}. The target agent or network path may be unavailable; the caller may retry later.",
            record.agent_id
        );
    }
    if error.is_connect() {
        return format!(
            "ServiceNet could not connect to the target endpoint for agent `{}` while sending `{method}`: {error}. The request was not delivered to the callee agent; the caller may retry later.",
            record.agent_id
        );
    }
    if error.is_request() {
        return format!(
            "ServiceNet could not send `{method}` to agent `{}` because the outgoing request failed before delivery: {error}. The caller may retry later.",
            record.agent_id
        );
    }
    if error.is_body() {
        return format!(
            "ServiceNet started sending `{method}` to agent `{}` but the request body failed before delivery completed: {error}. The caller may retry later.",
            record.agent_id
        );
    }
    format!(
        "ServiceNet failed while sending `{method}` to agent `{}` before a valid callee response was received: {error}. The caller may retry later.",
        record.agent_id
    )
}

fn body_preview(text: &str) -> String {
    let preview: String = text.chars().take(500).collect();
    if text.chars().count() > 500 {
        format!("{preview}...")
    } else {
        preview
    }
}

fn map_registry_error(error: RegistryError) -> GatewayError {
    match error {
        RegistryError::ProviderNotFound(_) | RegistryError::PublishedAgentNotFound(_) => {
            GatewayError::NotFound(error.to_string())
        }
        RegistryError::ProviderBlocked(_)
        | RegistryError::AgentBlocked(_)
        | RegistryError::ProviderRevoked(_)
        | RegistryError::AuthContextNotFound(_) => GatewayError::Rejected(error.to_string()),
        _ => GatewayError::Execution(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::State, routing::post};
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::{Arc, Mutex};
    use watt_servicenet_protocol::{
        AgentArtifacts, AgentAttestations, AgentDeployment, AgentDeploymentEndpoint,
        AgentInteractionProtocol, AgentReviewProfile, ApproveAgentSubmissionRequest, AuthModel,
        RegisterAuthContextRequest, RegisterProviderRequest, RiskLevel, SettlementLayer,
        SettlementRequest, SubmitAgentRequest, build_agent_attestation_payload,
    };

    fn provider_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[21u8; 32])
    }

    fn caller_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn did_from_signing_key(signing_key: &SigningKey) -> String {
        format!(
            "did:key:z{}",
            bs58::encode(
                [
                    &[0xed, 0x01][..],
                    &signing_key.verifying_key().to_bytes()[..]
                ]
                .concat()
            )
            .into_string()
        )
    }

    fn sign_submission_attestation(request: &mut SubmitAgentRequest, signing_key: &SigningKey) {
        let payload = serde_jcs::to_vec(&build_agent_attestation_payload(request)).unwrap();
        request.attestations.attestation_signature =
            STANDARD.encode(signing_key.sign(&payload).to_bytes());
    }

    fn sign_payload(payload: &impl Serialize, signing_key: &SigningKey) -> String {
        STANDARD.encode(
            signing_key
                .sign(&serde_jcs::to_vec(payload).expect("payload should canonicalize"))
                .to_bytes(),
        )
    }

    fn signed_source_agent_card(signing_key: &SigningKey) -> Value {
        let agent_id = did_from_signing_key(signing_key);
        let node_id = Some("node-caller".to_owned());
        let card = serde_json::json!({
            "name": "Caller Agent"
        });
        let card_hash = canonical_value_hash(&card).expect("card should hash");
        let issued_at = 1_776_000_000;
        let payload = SignedSourceAgentCardPayload {
            agent_id: &agent_id,
            node_id: node_id.as_ref(),
            card_hash: &card_hash,
            issued_at,
        };
        serde_json::json!({
            "agent_id": agent_id,
            "node_id": node_id,
            "card_hash": card_hash,
            "issued_at": issued_at,
            "card": card,
            "signature": sign_payload(&payload, signing_key)
        })
    }

    fn signed_agent_envelope() -> Value {
        let signing_key = caller_signing_key();
        let source_agent_id = did_from_signing_key(&signing_key);
        let transport_profile = Some("wattswarm_mesh".to_owned());
        let target_agent_id = Some("stripe-agent".to_owned());
        let source_node_id = Some("node-caller".to_owned());
        let capability = Some("servicenet.agents.invoke".to_owned());
        let source_agent_card = signed_source_agent_card(&signing_key);
        let source_agent_card_hash = json_string_at(&source_agent_card, &["card_hash"]);
        let message = serde_json::json!({
            "message": "Create payment link"
        });
        let extensions = serde_json::json!({
            "caller_public_id": "pub_caller"
        });
        let message_json = serde_json::to_string(&message).expect("message should serialize");
        let extensions_json =
            Some(serde_json::to_string(&extensions).expect("extensions should serialize"));
        let payload = SignedAgentEnvelopePayload {
            protocol: "google_a2a",
            transport_profile: transport_profile.as_ref(),
            source_agent_id: Some(&source_agent_id),
            target_agent_id: target_agent_id.as_ref(),
            source_node_id: source_node_id.as_ref(),
            target_node_id: None,
            capability: capability.as_ref(),
            source_agent_card_hash: source_agent_card_hash.as_ref(),
            message_json: &message_json,
            extensions_json: extensions_json.as_ref(),
        };
        serde_json::json!({
            "protocol": "google_a2a",
            "transport_profile": transport_profile,
            "source_agent_id": source_agent_id,
            "target_agent_id": target_agent_id,
            "source_node_id": source_node_id,
            "capability": capability,
            "source_agent_card": source_agent_card,
            "message": message,
            "extensions": extensions,
            "signature": sign_payload(&payload, &signing_key)
        })
    }

    fn signed_agent_envelope_for_request(request: &InvokeAgentRequest, nonce: &str) -> Value {
        let signing_key = caller_signing_key();
        let source_agent_id = did_from_signing_key(&signing_key);
        let transport_profile = Some("wattswarm_mesh".to_owned());
        let target_agent_id = Some("stripe-agent".to_owned());
        let source_node_id = Some("node-caller".to_owned());
        let capability = Some("servicenet.agents.invoke".to_owned());
        let source_agent_card = signed_source_agent_card(&signing_key);
        let source_agent_card_hash = json_string_at(&source_agent_card, &["card_hash"]);
        let message = invocation_envelope_message(request).expect("message should build");
        let issued_at_ms = Utc::now().timestamp_millis().max(0) as u64;
        let extensions = serde_json::json!({
            "caller_public_id": "pub_caller",
            "nonce": nonce,
            "issued_at_ms": issued_at_ms,
            "expires_at_ms": issued_at_ms + 300_000,
            "request_digest": jcs_sha256_digest_value(&message).expect("request digest should build")
        });
        let message_json = serde_json::to_string(&message).expect("message should serialize");
        let extensions_json =
            Some(serde_json::to_string(&extensions).expect("extensions should serialize"));
        let payload = SignedAgentEnvelopePayload {
            protocol: "google_a2a",
            transport_profile: transport_profile.as_ref(),
            source_agent_id: Some(&source_agent_id),
            target_agent_id: target_agent_id.as_ref(),
            source_node_id: source_node_id.as_ref(),
            target_node_id: None,
            capability: capability.as_ref(),
            source_agent_card_hash: source_agent_card_hash.as_ref(),
            message_json: &message_json,
            extensions_json: extensions_json.as_ref(),
        };
        serde_json::json!({
            "protocol": "google_a2a",
            "transport_profile": transport_profile,
            "source_agent_id": source_agent_id,
            "target_agent_id": target_agent_id,
            "source_node_id": source_node_id,
            "capability": capability,
            "source_agent_card": source_agent_card,
            "message": message,
            "extensions": extensions,
            "signature": sign_payload(&payload, &signing_key)
        })
    }

    fn signed_agent_envelope_for_sparse_message(message: Value, nonce: &str) -> Value {
        let signing_key = caller_signing_key();
        let source_agent_id = did_from_signing_key(&signing_key);
        let transport_profile = Some("wattswarm_mesh".to_owned());
        let target_agent_id = Some("stripe-agent".to_owned());
        let source_node_id = Some("node-caller".to_owned());
        let capability = Some("servicenet.agents.invoke".to_owned());
        let source_agent_card = signed_source_agent_card(&signing_key);
        let source_agent_card_hash = json_string_at(&source_agent_card, &["card_hash"]);
        let issued_at_ms = Utc::now().timestamp_millis().max(0) as u64;
        let extensions = serde_json::json!({
            "caller_public_id": "pub_caller",
            "nonce": nonce,
            "issued_at_ms": issued_at_ms,
            "expires_at_ms": issued_at_ms + 300_000,
            "request_digest": canonical_value_hash(&message).expect("message digest should build")
        });
        let message_json = serde_json::to_string(&message).expect("message should serialize");
        let extensions_json =
            Some(serde_json::to_string(&extensions).expect("extensions should serialize"));
        let payload = SignedAgentEnvelopePayload {
            protocol: "google_a2a",
            transport_profile: transport_profile.as_ref(),
            source_agent_id: Some(&source_agent_id),
            target_agent_id: target_agent_id.as_ref(),
            source_node_id: source_node_id.as_ref(),
            target_node_id: None,
            capability: capability.as_ref(),
            source_agent_card_hash: source_agent_card_hash.as_ref(),
            message_json: &message_json,
            extensions_json: extensions_json.as_ref(),
        };
        serde_json::json!({
            "protocol": "google_a2a",
            "transport_profile": transport_profile,
            "source_agent_id": source_agent_id,
            "target_agent_id": target_agent_id,
            "source_node_id": source_node_id,
            "capability": capability,
            "source_agent_card": source_agent_card,
            "message": message,
            "extensions": extensions,
            "signature": sign_payload(&payload, &signing_key)
        })
    }

    fn provider_request() -> RegisterProviderRequest {
        RegisterProviderRequest {
            provider_id: "provider-1".to_owned(),
            provider_did: did_from_signing_key(&provider_signing_key()),
            display_name: Some("Provider One".to_owned()),
            ownership_challenge_id: None,
            ownership_signature: None,
        }
    }

    fn agent_submission(url_base: &str, endpoint_url: &str) -> SubmitAgentRequest {
        let provider_did = did_from_signing_key(&provider_signing_key());
        let mut request = SubmitAgentRequest {
            provider_id: "provider-1".to_owned(),
            agent_id: "stripe-agent".to_owned(),
            service_address: Some("stripe@wattetheria".to_owned()),
            version: "0.1.0".to_owned(),
            agent_card: serde_json::json!({
                "name": "Stripe Agent",
                "description": "Payments",
                "url": url_base,
                "preferredTransport": "JSONRPC",
                "protocolVersion": "1.0",
                "supportsTask": false,
                "cost": 5,
                "skills": [{"id": "payments.create_link"}],
                "securitySchemes": {"oauth2": {"type": "oauth2"}},
                "security": [{"oauth2": ["payments:write"]}],
                "didDocument": {
                    "id": provider_did,
                    "alsoKnownAs": ["stripe@wattetheria"],
                    "service": [{
                        "id": "#servicenet-agent",
                        "type": "WattetheriaServiceNetAgent",
                        "serviceEndpoint": "wattetheria://servicenet/stripe@wattetheria"
                    }]
                }
            }),
            deployment: AgentDeployment {
                runtime: "remote_http".to_owned(),
                endpoint: AgentDeploymentEndpoint {
                    url: endpoint_url.to_owned(),
                    protocol_binding: "JSONRPC".to_owned(),
                    protocol_version: "1.0".to_owned(),
                    interaction_protocol: AgentInteractionProtocol::GoogleA2a,
                },
            },
            review: AgentReviewProfile {
                risk_level: RiskLevel::Medium,
                data_classes: vec!["financial".to_owned()],
                destructive_actions: vec!["payments.refund".to_owned()],
                human_approval_required: true,
                allowed_regions: vec!["AU".to_owned()],
                cost_per_call_units: None,
            },
            artifacts: AgentArtifacts::default(),
            attestations: AgentAttestations {
                attestation_signature: String::new(),
                provider_attester_did: None,
                delegation_token: None,
                source_commit: None,
                build_digest: None,
                nonce: None,
                issued_at_ms: None,
                expires_at_ms: None,
            },
        };
        let provider_key = provider_signing_key();
        sign_submission_attestation(&mut request, &provider_key);
        request
    }

    async fn start_mock_a2a_server() -> String {
        async fn handle(headers: axum::http::HeaderMap, Json(request): Json<Value>) -> Json<Value> {
            let method = request["method"].as_str().unwrap_or_default();
            let has_auth = headers.get("authorization").is_some();
            let response = match method {
                "SendMessage" => serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": request["id"].clone(),
                    "result": {
                        "task": {
                            "id": "task-1",
                            "contextId": "ctx-1",
                            "status": { "state": "TASK_STATE_WORKING" },
                            "artifacts": [
                                {
                                    "artifactId": "artifact-1",
                                    "parts": [{ "data": { "authorized": has_auth } }]
                                }
                            ]
                        }
                    }
                }),
                "GetTask" => serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": request["id"].clone(),
                    "result": {
                        "task": {
                            "id": "task-1",
                            "contextId": "ctx-1",
                            "status": { "state": "TASK_STATE_COMPLETED" }
                        }
                    }
                }),
                _ => serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": request["id"].clone(),
                    "error": { "code": -32601, "message": "Method not found" }
                }),
            };
            Json(response)
        }

        let app = Router::new().route("/a2a", post(handle));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("mock server should run");
        });
        format!("http://{addr}/a2a")
    }

    async fn start_mock_a2a_server_with_capture() -> (String, Arc<Mutex<Vec<Value>>>) {
        let captured = Arc::new(Mutex::new(Vec::<Value>::new()));

        async fn handle(
            State(captured): State<Arc<Mutex<Vec<Value>>>>,
            Json(request): Json<Value>,
        ) -> Json<Value> {
            captured.lock().expect("capture lock").push(request.clone());
            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request["id"].clone(),
                "result": {
                    "task": {
                        "id": "task-ap2-1",
                        "contextId": "ctx-ap2-1",
                        "status": { "state": "TASK_STATE_COMPLETED" },
                        "artifacts": [
                            {
                                "artifactId": "artifact-1",
                                "parts": [
                                    {
                                        "data": {
                                            "payment_receipt": {
                                                "status": "authorized"
                                            },
                                            "provider": "mock-a2a"
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                }
            });
            Json(response)
        }

        let app = Router::new()
            .route("/a2a", post(handle))
            .with_state(Arc::clone(&captured));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("mock server should run");
        });
        (format!("http://{addr}/a2a"), captured)
    }

    async fn start_invalid_a2a_server() -> String {
        async fn handle() -> &'static str {
            "callee returned a non-json response"
        }

        let app = Router::new().route("/a2a", post(handle));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("local addr should exist");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("mock server should run");
        });
        format!("http://{addr}/a2a")
    }

    async fn approved_gateway_with_a2a_url(
        a2a_url: String,
    ) -> (Arc<ServiceRegistry>, GatewayService) {
        let registry = Arc::new(ServiceRegistry::in_memory());
        registry
            .register_provider(provider_request())
            .await
            .expect("provider should register");
        let card_url = a2a_url.trim_end_matches("/a2a").to_owned();
        let submission = registry
            .submit_agent(agent_submission(&card_url, &a2a_url))
            .await
            .expect("agent should submit");
        registry
            .approve_agent_submission(
                submission.submission_id,
                ApproveAgentSubmissionRequest {
                    reviewed_by: "moderator-a".to_owned(),
                    review_notes: Some("approved".to_owned()),
                },
            )
            .await
            .expect("agent should approve");
        let gateway = GatewayService::new(registry.clone());
        (registry, gateway)
    }

    async fn approved_gateway() -> (Arc<ServiceRegistry>, GatewayService) {
        approved_gateway_with_a2a_url(start_mock_a2a_server().await).await
    }

    #[tokio::test]
    async fn invoke_agent_records_receipt() {
        let (registry, gateway) = approved_gateway().await;
        let response = gateway
            .invoke_agent(
                "stripe-agent",
                InvokeAgentRequest {
                    message: Some("Create payment link".to_owned()),
                    input: serde_json::json!({"amount": 42}),
                    region: Some("AU".to_owned()),
                    confirm_risky: true,
                    ..InvokeAgentRequest {
                        task_id: None,
                        context_id: None,
                        message: None,
                        input: Value::Null,
                        skill_id: None,
                        settlement: None,
                        auth_token: Some("secret-token".to_owned()),
                        auth_context_id: None,
                        region: None,
                        confirm_risky: false,
                        max_cost_units: Some(10),
                        agent_envelope: Some(signed_agent_envelope()),
                    }
                },
            )
            .await
            .expect("invoke should succeed");
        assert_eq!(response.agent_id, "stripe-agent");
        let receipts = registry
            .list_receipts(&watt_servicenet_protocol::ReceiptQuery {
                agent_id: Some("stripe-agent".to_owned()),
                ..Default::default()
            })
            .await
            .expect("receipts should load");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].receipt.invoke_mode, InvocationMode::Sync);
        assert!(receipts[0].receipt.invocation_attestation.is_some());
        assert!(
            receipts[0]
                .receipt
                .receipt_issuer_did
                .as_deref()
                .is_some_and(|value| value.starts_with("did:key:"))
        );
        assert!(receipts[0].receipt.receipt_signed_at_ms.is_some());
        assert!(
            receipts[0]
                .receipt
                .receipt_signature
                .as_deref()
                .is_some_and(|value| !value.is_empty())
        );
    }

    #[tokio::test]
    async fn invoke_agent_rejects_replayed_agent_envelope_nonce() {
        let (_registry, gateway) = approved_gateway().await;
        let mut request = InvokeAgentRequest {
            task_id: None,
            context_id: None,
            message: Some("Create payment link".to_owned()),
            input: serde_json::json!({"amount": 42}),
            skill_id: None,
            settlement: None,
            auth_token: Some("secret-token".to_owned()),
            auth_context_id: None,
            region: Some("AU".to_owned()),
            confirm_risky: true,
            max_cost_units: Some(10),
            agent_envelope: None,
        };
        let envelope = signed_agent_envelope_for_request(&request, "nonce-replay-1");
        request.agent_envelope = Some(envelope.clone());
        gateway
            .invoke_agent("stripe-agent", request.clone())
            .await
            .expect("first invoke should succeed");

        let err = gateway
            .invoke_agent("stripe-agent", request)
            .await
            .expect_err("replayed invoke should fail");
        assert!(err.to_string().contains("nonce has already been used"));
    }

    #[tokio::test]
    async fn invoke_agent_accepts_sparse_signed_message_digest() {
        let (_registry, gateway) = approved_gateway().await;
        let sparse_message = serde_json::json!({
            "message": "Create payment link",
            "region": "AU",
            "confirm_risky": true,
            "max_cost_units": 10,
            "auth_token": "secret-token"
        });
        let response = gateway
            .invoke_agent(
                "stripe-agent",
                InvokeAgentRequest {
                    task_id: None,
                    context_id: None,
                    message: Some("Create payment link".to_owned()),
                    input: Value::Null,
                    skill_id: None,
                    settlement: None,
                    auth_token: Some("secret-token".to_owned()),
                    auth_context_id: None,
                    region: Some("AU".to_owned()),
                    confirm_risky: true,
                    max_cost_units: Some(10),
                    agent_envelope: Some(signed_agent_envelope_for_sparse_message(
                        sparse_message,
                        "nonce-sparse-1",
                    )),
                },
            )
            .await
            .expect("sparse signed message should match request semantics");
        assert_eq!(response.agent_id, "stripe-agent");
    }

    #[tokio::test]
    async fn invoke_agent_derives_servicenet_context_id_from_caller_envelope() {
        let (a2a_url, captured) = start_mock_a2a_server_with_capture().await;
        let (_registry, gateway) = approved_gateway_with_a2a_url(a2a_url).await;
        gateway
            .invoke_agent(
                "stripe-agent",
                InvokeAgentRequest {
                    task_id: None,
                    context_id: None,
                    message: Some("Create payment link".to_owned()),
                    input: serde_json::json!({"amount": 42}),
                    skill_id: None,
                    settlement: None,
                    auth_token: Some("secret-token".to_owned()),
                    auth_context_id: None,
                    region: Some("AU".to_owned()),
                    confirm_risky: true,
                    max_cost_units: Some(10),
                    agent_envelope: Some(signed_agent_envelope()),
                },
            )
            .await
            .expect("invoke should succeed");

        let captured = captured.lock().expect("capture lock");
        let request = captured.last().expect("captured request");
        let expected_context_id = format!(
            "wattetheria:servicenet:{}:stripe-agent:mainnet:watt-etheria",
            did_from_signing_key(&caller_signing_key())
        );
        assert_eq!(
            request["params"]["contextId"].as_str(),
            Some(expected_context_id.as_str())
        );
    }

    #[tokio::test]
    async fn invoke_agent_rejects_missing_agent_envelope() {
        let (_registry, gateway) = approved_gateway().await;
        let err = gateway
            .invoke_agent(
                "stripe-agent",
                InvokeAgentRequest {
                    task_id: None,
                    context_id: None,
                    message: Some("Create payment link".to_owned()),
                    input: Value::Null,
                    skill_id: None,
                    settlement: None,
                    auth_token: Some("secret-token".to_owned()),
                    auth_context_id: None,
                    region: Some("AU".to_owned()),
                    confirm_risky: true,
                    max_cost_units: Some(10),
                    agent_envelope: None,
                },
            )
            .await
            .expect_err("invoke should reject unsigned callers");
        assert!(matches!(err, GatewayError::Rejected(_)));
        assert!(err.to_string().contains("agent_envelope is required"));
    }

    #[tokio::test]
    async fn invoke_agent_reports_invalid_callee_response() {
        let (_registry, gateway) =
            approved_gateway_with_a2a_url(start_invalid_a2a_server().await).await;
        let err = gateway
            .invoke_agent(
                "stripe-agent",
                InvokeAgentRequest {
                    message: Some("Create payment link".to_owned()),
                    input: Value::Null,
                    region: Some("AU".to_owned()),
                    confirm_risky: true,
                    auth_token: Some("secret-token".to_owned()),
                    ..InvokeAgentRequest {
                        task_id: None,
                        context_id: None,
                        message: None,
                        input: Value::Null,
                        skill_id: None,
                        settlement: None,
                        auth_token: None,
                        auth_context_id: None,
                        region: None,
                        confirm_risky: false,
                        max_cost_units: None,
                        agent_envelope: Some(signed_agent_envelope()),
                    }
                },
            )
            .await
            .expect_err("invalid callee response should fail");

        let message = err.to_string();
        assert!(message.contains("callee agent returned a non-JSON or invalid A2A response"));
        assert!(message.contains("body_preview=callee returned a non-json response"));
        assert!(message.contains("caller may retry later"));
    }

    #[tokio::test]
    async fn invoke_agent_async_returns_receipt_and_records_result() {
        let (registry, gateway) = approved_gateway().await;
        let response = gateway
            .invoke_agent_async(
                "stripe-agent",
                InvokeAgentRequest {
                    task_id: None,
                    context_id: None,
                    message: Some("Create payment link".to_owned()),
                    input: Value::Null,
                    skill_id: None,
                    settlement: None,
                    auth_token: Some("secret-token".to_owned()),
                    auth_context_id: None,
                    region: Some("AU".to_owned()),
                    confirm_risky: true,
                    max_cost_units: Some(10),
                    agent_envelope: Some(signed_agent_envelope()),
                },
            )
            .await
            .expect("async invoke should be accepted");
        assert_eq!(response.status, "running");
        let receipt_id = response.receipt_id.expect("receipt id should be returned");

        let mut stored = registry
            .get_receipt(receipt_id)
            .await
            .expect("running receipt should exist");
        assert_eq!(stored.receipt.invoke_mode, InvocationMode::Async);
        for _ in 0..20 {
            if stored.receipt.status == ReceiptStatus::Succeeded {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            stored = registry
                .get_receipt(receipt_id)
                .await
                .expect("receipt should remain queryable");
        }

        assert_eq!(stored.receipt.status, ReceiptStatus::Succeeded);
        assert_eq!(stored.receipt.invoke_mode, InvocationMode::Async);
        assert!(stored.receipt.completed_at.is_some());
        assert_eq!(
            stored
                .output
                .as_ref()
                .and_then(|output| output.pointer("/result/task/id"))
                .and_then(Value::as_str),
            Some("task-1")
        );
    }

    #[test]
    fn stored_invocation_output_preserves_message_result() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "response-1",
            "result": {
                "kind": "message",
                "role": "agent",
                "parts": [
                    {
                        "kind": "text",
                        "text": "Tokyo is partly cloudy."
                    }
                ]
            }
        });

        let output = stored_invocation_output(&response).expect("output should be stored");

        assert_eq!(output, response);
    }

    #[test]
    fn stored_invocation_output_preserves_plain_result() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "response-1",
            "result": "Tokyo is partly cloudy."
        });

        let output = stored_invocation_output(&response).expect("output should be stored");

        assert_eq!(output, response);
    }

    #[test]
    fn stored_invocation_output_preserves_raw_body_without_result() {
        let response = serde_json::json!({
            "message": "Tokyo is partly cloudy."
        });

        let output = stored_invocation_output(&response).expect("output should be stored");

        assert_eq!(output, response);
    }

    #[tokio::test]
    async fn blocked_agent_is_rejected() {
        let (registry, gateway) = approved_gateway().await;
        registry
            .block_agent(
                "stripe-agent",
                watt_servicenet_protocol::BlockEntityRequest {
                    reason: Some("manual".to_owned()),
                },
            )
            .await
            .expect("agent should block");
        let err = gateway
            .invoke_agent(
                "stripe-agent",
                InvokeAgentRequest {
                    region: Some("AU".to_owned()),
                    confirm_risky: true,
                    ..InvokeAgentRequest {
                        task_id: None,
                        context_id: None,
                        message: Some("Create payment link".to_owned()),
                        input: Value::Null,
                        skill_id: None,
                        settlement: None,
                        auth_token: Some("secret-token".to_owned()),
                        auth_context_id: None,
                        region: None,
                        confirm_risky: false,
                        max_cost_units: Some(10),
                        agent_envelope: Some(signed_agent_envelope()),
                    }
                },
            )
            .await
            .expect_err("invoke should reject");
        assert!(matches!(err, GatewayError::Rejected(_)));
    }

    #[tokio::test]
    async fn auth_context_can_supply_token() {
        let (registry, gateway) = approved_gateway().await;
        let auth_context = registry
            .register_auth_context(RegisterAuthContextRequest {
                subject_did: "did:key:z6MkfZ7QWbG4zY4C8z8c2jv7b6hJ6x9o4D7hS1x2T3y4Z5k6".to_owned(),
                provider_id: "provider-1".to_owned(),
                auth_model: AuthModel::BearerToken,
                token: "secret-token".to_owned(),
                expires_at: None,
            })
            .await
            .expect("auth context should register");
        let response = gateway
            .invoke_agent(
                "stripe-agent",
                InvokeAgentRequest {
                    task_id: None,
                    context_id: None,
                    message: Some("Create payment link".to_owned()),
                    input: Value::Null,
                    skill_id: None,
                    settlement: None,
                    auth_token: None,
                    auth_context_id: Some(auth_context.auth_context_id),
                    region: Some("AU".to_owned()),
                    confirm_risky: true,
                    max_cost_units: Some(10),
                    agent_envelope: Some(signed_agent_envelope()),
                },
            )
            .await
            .expect("invoke should succeed");
        assert_eq!(
            response.output,
            Some(serde_json::json!({ "authorized": true }))
        );
    }

    #[tokio::test]
    async fn invoke_agent_normalizes_x402_settlement_and_records_receipt() {
        let registry = Arc::new(ServiceRegistry::in_memory());
        registry
            .register_provider(provider_request())
            .await
            .expect("provider should register");
        let (a2a_url, captured) = start_mock_a2a_server_with_capture().await;
        let card_url = a2a_url.trim_end_matches("/a2a").to_owned();
        let submission = registry
            .submit_agent(agent_submission(&card_url, &a2a_url))
            .await
            .expect("agent should submit");
        registry
            .approve_agent_submission(
                submission.submission_id,
                ApproveAgentSubmissionRequest {
                    reviewed_by: "moderator-a".to_owned(),
                    review_notes: Some("approved".to_owned()),
                },
            )
            .await
            .expect("agent should approve");
        let gateway = GatewayService::new(registry.clone());

        let response = gateway
            .invoke_agent(
                "stripe-agent",
                InvokeAgentRequest {
                    task_id: Some("task-ap2-1".to_owned()),
                    context_id: Some("ctx-ap2-1".to_owned()),
                    message: Some("Book the best flight".to_owned()),
                    input: serde_json::json!({
                        "quote_id": "quote-1"
                    }),
                    skill_id: None,
                    settlement: Some(SettlementRequest {
                        layer: SettlementLayer::Web3,
                        rail: "X402".to_owned(),
                        request: serde_json::json!({
                            "pay_to": "0xabc123"
                        }),
                    }),
                    auth_token: Some("secret-token".to_owned()),
                    auth_context_id: None,
                    region: Some("AU".to_owned()),
                    confirm_risky: true,
                    max_cost_units: Some(10),
                    agent_envelope: Some(signed_agent_envelope()),
                },
            )
            .await
            .expect("invoke should succeed");
        assert_eq!(response.status, "TASK_STATE_COMPLETED");
        assert_eq!(
            response
                .settlement
                .as_ref()
                .map(|value| value.rail.as_str()),
            Some("x402")
        );
        assert_eq!(
            response
                .payment_receipt
                .as_ref()
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str),
            Some("authorized")
        );

        let captured = captured.lock().expect("capture lock");
        let request = captured.last().expect("captured request");
        assert_eq!(request["method"].as_str(), Some("SendMessage"));
        assert_eq!(
            request["params"]["extensions"]["settlement"]["rail"].as_str(),
            Some("x402")
        );
        assert_eq!(
            request["params"]["extensions"]["settlement"]["request"]["protocol"].as_str(),
            Some("x402")
        );
    }

    #[test]
    fn agent_requires_auth_treats_none_security_as_public() {
        assert!(!agent_requires_auth(&serde_json::json!({
            "securitySchemes": {"none": {"type": "none"}},
            "security": [{"none": []}]
        })));
        assert!(agent_requires_auth(&serde_json::json!({
            "securitySchemes": {"oauth2": {"type": "oauth2"}},
            "security": [{"oauth2": ["payments:write"]}]
        })));
        assert!(agent_requires_auth(&serde_json::json!({
            "securitySchemes": {"oauth2": {"type": "oauth2"}}
        })));
    }

    #[test]
    fn google_a2a_adapter_builds_existing_send_message_shape() {
        let adapter = GoogleA2aAdapter;
        let payload = adapter.build_send_message_payload(
            &InvokeAgentRequest {
                task_id: Some("task-1".to_owned()),
                context_id: Some("ctx-1".to_owned()),
                message: Some("Create payment link".to_owned()),
                input: serde_json::json!({"amount": 42}),
                skill_id: Some("payments.create_link".to_owned()),
                settlement: None,
                auth_token: None,
                auth_context_id: None,
                region: None,
                confirm_risky: false,
                max_cost_units: None,
                agent_envelope: Some(serde_json::json!({
                    "source_agent_id": "did:key:zCaller",
                    "source_agent_card": {
                        "agent_id": "did:key:zCaller"
                    }
                })),
            },
            None,
        );
        assert_eq!(adapter.send_message_method(), "SendMessage");
        assert_eq!(adapter.get_task_method(), "GetTask");
        assert_eq!(adapter.version_header_name(), "A2A-Version");
        assert_eq!(payload["taskId"].as_str(), Some("task-1"));
        assert_eq!(payload["contextId"].as_str(), Some("ctx-1"));
        assert_eq!(payload["skillId"].as_str(), Some("payments.create_link"));
        assert_eq!(
            payload["message"]["parts"][0]["text"].as_str(),
            Some("Create payment link")
        );
        assert_eq!(
            payload["message"]["parts"][1]["data"]["amount"].as_i64(),
            Some(42)
        );
        assert_eq!(
            payload["extensions"]["agent_envelope"]["source_agent_id"].as_str(),
            Some("did:key:zCaller")
        );
    }

    #[test]
    fn google_a2a_adapter_derives_text_from_input_shapes() {
        let adapter = GoogleA2aAdapter;
        let payload = adapter.build_send_message_payload(
            &InvokeAgentRequest {
                task_id: None,
                context_id: None,
                message: None,
                input: serde_json::json!({"query": "Recommend dishes"}),
                skill_id: None,
                settlement: None,
                auth_token: None,
                auth_context_id: None,
                region: None,
                confirm_risky: false,
                max_cost_units: None,
                agent_envelope: None,
            },
            None,
        );
        assert_eq!(
            payload["message"]["parts"][0]["text"].as_str(),
            Some("Recommend dishes")
        );
        assert_eq!(
            payload["message"]["parts"][1]["data"]["query"].as_str(),
            Some("Recommend dishes")
        );

        let payload = adapter.build_send_message_payload(
            &InvokeAgentRequest {
                task_id: None,
                context_id: None,
                message: None,
                input: serde_json::json!("plain user prompt"),
                skill_id: None,
                settlement: None,
                auth_token: None,
                auth_context_id: None,
                region: None,
                confirm_risky: false,
                max_cost_units: None,
                agent_envelope: None,
            },
            None,
        );
        assert_eq!(
            payload["message"]["parts"][0]["text"].as_str(),
            Some("plain user prompt")
        );

        let payload = adapter.build_send_message_payload(
            &InvokeAgentRequest {
                task_id: None,
                context_id: None,
                message: None,
                input: serde_json::json!({
                    "message": {
                        "role": "user",
                        "parts": [{"kind": "text", "text": "A2A user prompt"}]
                    }
                }),
                skill_id: None,
                settlement: None,
                auth_token: None,
                auth_context_id: None,
                region: None,
                confirm_risky: false,
                max_cost_units: None,
                agent_envelope: None,
            },
            None,
        );
        assert_eq!(
            payload["message"]["parts"][0]["text"].as_str(),
            Some("A2A user prompt")
        );
    }
}
