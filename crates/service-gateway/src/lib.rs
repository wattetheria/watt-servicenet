use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;
use watt_servicenet_protocol::{
    AgentInteractionProtocol, AuthContextRecord, ExecutionReceipt, GetAgentTaskRequest,
    InvokeAgentRequest, InvokeAgentResponse, NormalizedSettlementRequest, PublishedAgentRecord,
    ReceiptStatus, RiskLevel, SettlementLayer, SettlementRequest, StoredReceipt,
    VerificationVerdict,
};
use watt_servicenet_registry::{RegistryError, ServiceRegistry};

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
}

struct PreparedInvocation {
    record: PublishedAgentRecord,
    auth_token: Option<String>,
    adapter: Box<dyn A2aAdapter + Send + Sync>,
    normalized_settlement: Option<NormalizedSettlementRequest>,
    cost_units: Option<u32>,
    request_digest: String,
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
        let parts = match (&request.message, &request.input) {
            (Some(message), Value::Null) => vec![serde_json::json!({
                "kind": "text",
                "text": message,
            })],
            (Some(message), input) => vec![
                serde_json::json!({
                    "kind": "text",
                    "text": message,
                }),
                serde_json::json!({
                    "kind": "data",
                    "data": input,
                }),
            ],
            (None, input) => vec![serde_json::json!({
                "kind": "data",
                "data": input,
            })],
        };

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
        }
    }

    pub async fn invoke_agent(
        &self,
        agent_id: &str,
        request: InvokeAgentRequest,
    ) -> Result<InvokeAgentResponse, GatewayError> {
        let prepared = self.prepare_invocation(agent_id, &request).await?;
        self.execute_prepared_invocation(agent_id, request, prepared, Uuid::new_v4(), Utc::now())
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
        let running = StoredReceipt {
            receipt: ExecutionReceipt {
                receipt_id,
                agent_id: prepared.record.agent_id.clone(),
                provider_id: prepared.record.provider_id.clone(),
                status: ReceiptStatus::Running,
                verification: VerificationVerdict::NotRequired,
                request_digest: prepared.request_digest.clone(),
                result_digest: None,
                started_at,
                completed_at: None,
                cost_units: prepared.cost_units,
            },
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
        let auth_token = self
            .resolve_agent_auth_context(&record, request.auth_context_id)
            .await?
            .or(request.auth_token.clone());
        self.enforce_agent_preflight(&record, request, auth_token.as_deref())
            .await?;
        let adapter = a2a_adapter(record.deployment.endpoint.interaction_protocol);
        let normalized_settlement = normalize_settlement_request(request.settlement.as_ref())?;
        let agent_cost_units = agent_cost_units(&record.agent_card);
        let cost_units = request
            .max_cost_units
            .and(agent_cost_units)
            .or(agent_cost_units);
        let request_digest = invocation_request_digest(request, normalized_settlement.as_ref())?;
        Ok(PreparedInvocation {
            record,
            auth_token,
            adapter,
            normalized_settlement,
            cost_units,
            request_digest,
        })
    }

    async fn execute_prepared_invocation(
        &self,
        agent_id: &str,
        request: InvokeAgentRequest,
        prepared: PreparedInvocation,
        receipt_id: Uuid,
        started_at: DateTime<Utc>,
    ) -> Result<InvokeAgentResponse, GatewayError> {
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

        let receipt = StoredReceipt {
            receipt: ExecutionReceipt {
                receipt_id,
                agent_id: prepared.record.agent_id.clone(),
                provider_id: prepared.record.provider_id.clone(),
                status: ReceiptStatus::Succeeded,
                verification: verification_for_risk(&prepared.record.review.risk_level),
                request_digest: prepared.request_digest,
                result_digest: receipt_output
                    .as_ref()
                    .map(digest_value)
                    .transpose()
                    .map_err(|err| GatewayError::Execution(err.to_string()))?,
                started_at,
                completed_at: Some(completed_at),
                cost_units: prepared.cost_units,
            },
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
    use base64::Engine as _;
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
        let mut request = SubmitAgentRequest {
            provider_id: "provider-1".to_owned(),
            agent_id: "stripe-agent".to_owned(),
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
                "security": [{"oauth2": ["payments:write"]}]
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
                payment_account_binding: None,
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
                        agent_envelope: None,
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
                        agent_envelope: None,
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
                    agent_envelope: None,
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
                        agent_envelope: None,
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
                    agent_envelope: None,
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
                    agent_envelope: None,
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
}
