use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;
use watt_servicenet_protocol::{
    AuthContextRecord, ExecutionReceipt, GetAgentTaskRequest, InvokeAgentRequest,
    InvokeAgentResponse, PublishedAgentRecord, ReceiptStatus, RiskLevel, StoredReceipt,
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
        let record = self
            .registry
            .get_published_agent(agent_id)
            .await
            .map_err(map_registry_error)?;
        let auth_token = self
            .resolve_agent_auth_context(&record, request.auth_context_id)
            .await?
            .or(request.auth_token.clone());
        self.enforce_agent_preflight(&record, &request, auth_token.as_deref())
            .await?;

        let started_at = Utc::now();
        let response = self
            .a2a_jsonrpc_call(
                &record,
                "SendMessage",
                build_a2a_send_message_payload(&request),
                auth_token.as_deref(),
            )
            .await?;
        let completed_at = Utc::now();

        let receipt = StoredReceipt {
            receipt: ExecutionReceipt {
                receipt_id: Uuid::new_v4(),
                agent_id: record.agent_id.clone(),
                provider_id: record.provider_id.clone(),
                status: ReceiptStatus::Succeeded,
                verification: verification_for_risk(&record.review.risk_level),
                request_digest: digest_value(&serde_json::json!({
                    "task_id": request.task_id,
                    "context_id": request.context_id,
                    "message": request.message,
                    "input": request.input,
                    "skill_id": request.skill_id
                }))
                .map_err(|err| GatewayError::Execution(err.to_string()))?,
                result_digest: extract_task_output(&response)
                    .as_ref()
                    .map(digest_value)
                    .transpose()
                    .map_err(|err| GatewayError::Execution(err.to_string()))?,
                started_at,
                completed_at,
                cost_units: request
                    .max_cost_units
                    .and(record.review.cost_per_call_units)
                    .or(record.review.cost_per_call_units),
            },
            output: extract_task_output(&response),
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
            response,
        ))
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
        let response = self
            .a2a_jsonrpc_call(
                &record,
                "GetTask",
                serde_json::json!({
                    "id": task_id,
                    "historyLength": request.history_length.unwrap_or(10),
                }),
                auth_token.as_deref(),
            )
            .await?;
        Ok(build_invoke_agent_response(agent_id, None, response))
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
            && record
                .review
                .cost_per_call_units
                .is_some_and(|cost| cost > max_cost_units)
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
        method: &str,
        params: Value,
        auth_token: Option<&str>,
    ) -> Result<Value, GatewayError> {
        let mut builder = self
            .http_client
            .post(&record.deployment.endpoint.url)
            .header("A2A-Version", &record.deployment.endpoint.protocol_version);
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
            .context("a2a request failed")
            .map_err(|err| GatewayError::Execution(err.to_string()))?;
        let body = response
            .json::<Value>()
            .await
            .context("failed to parse a2a response")
            .map_err(|err| GatewayError::Execution(err.to_string()))?;
        if let Some(error) = body.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("a2a request failed");
            return Err(GatewayError::Execution(message.to_owned()));
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
        return false;
    };
    match security {
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
        Value::Null => false,
        _ => true,
    }
}

fn build_a2a_send_message_payload(request: &InvokeAgentRequest) -> Value {
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
    Value::Object(map)
}

fn build_invoke_agent_response(
    agent_id: &str,
    receipt_id: Option<Uuid>,
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

fn digest_value(value: &Value) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
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
    use axum::{Json, Router, routing::post};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::Arc;
    use watt_servicenet_protocol::{
        AgentArtifacts, AgentAttestations, AgentDeployment, AgentDeploymentEndpoint,
        AgentReviewProfile, ApproveAgentSubmissionRequest, AuthModel, RegisterAuthContextRequest,
        RegisterProviderRequest, RiskLevel, SubmitAgentRequest, build_agent_attestation_payload,
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
            artifacts: AgentArtifacts::default(),
            attestations: AgentAttestations {
                attestation_signature: String::new(),
                provider_attester_did: None,
                delegation_token: None,
                source_commit: None,
                build_digest: None,
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

    async fn approved_gateway() -> (Arc<ServiceRegistry>, GatewayService) {
        let registry = Arc::new(ServiceRegistry::in_memory());
        registry
            .register_provider(provider_request())
            .await
            .expect("provider should register");
        let a2a_url = start_mock_a2a_server().await;
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
                        auth_token: Some("secret-token".to_owned()),
                        auth_context_id: None,
                        region: None,
                        confirm_risky: false,
                        max_cost_units: Some(10),
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
                        auth_token: Some("secret-token".to_owned()),
                        auth_context_id: None,
                        region: None,
                        confirm_risky: false,
                        max_cost_units: Some(10),
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
                    auth_token: None,
                    auth_context_id: Some(auth_context.auth_context_id),
                    region: Some("AU".to_owned()),
                    confirm_risky: true,
                    max_cost_units: Some(10),
                },
            )
            .await
            .expect("invoke should succeed");
        assert_eq!(
            response.output,
            Some(serde_json::json!({ "authorized": true }))
        );
    }
}
