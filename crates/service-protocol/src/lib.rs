use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::json;
use uuid::Uuid;

pub const SERVICE_PROTOCOL_SCHEMA_VERSION: u32 = 1;

fn default_schema_version() -> u32 {
    SERVICE_PROTOCOL_SCHEMA_VERSION
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum AuthModel {
    None,
    ApiKeyHeader { header_name: String },
    BearerToken,
    CapabilityToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderRecord {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub provider_id: String,
    pub provider_did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub status: ProviderStatus,
    pub registered_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Unknown,
    Online,
    Degraded,
    Offline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Succeeded,
    Failed,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationVerdict {
    NotRequired,
    Pending,
    Verified,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub receipt_id: Uuid,
    pub agent_id: String,
    pub provider_id: String,
    pub status: ReceiptStatus,
    pub verification: VerificationVerdict,
    pub request_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_digest: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_units: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredReceipt {
    pub receipt: ExecutionReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ReceiptQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerificationVerdict>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderHealthRecord {
    pub provider_id: String,
    pub status: HealthStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_latency_ms: Option<u64>,
    #[serde(default)]
    pub success_count: u64,
    #[serde(default)]
    pub failure_count: u64,
    pub success_rate: f32,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentHealthRecord {
    pub agent_id: String,
    pub provider_id: String,
    pub status: HealthStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_latency_ms: Option<u64>,
    #[serde(default)]
    pub success_count: u64,
    #[serde(default)]
    pub failure_count: u64,
    pub success_rate: f32,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderTrustRecord {
    pub provider_id: String,
    pub reputation_score: f32,
    pub blocked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_reason: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentTrustRecord {
    pub agent_id: String,
    pub reputation_score: f32,
    pub blocked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_reason: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderOwnershipOperation {
    Register,
    RotateKey,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderOwnershipChallenge {
    pub challenge_id: Uuid,
    pub provider_id: String,
    #[serde(alias = "public_key")]
    pub provider_did: String,
    pub operation: ProviderOwnershipOperation,
    pub challenge: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateProviderOwnershipChallengeRequest {
    pub provider_id: String,
    #[serde(alias = "public_key")]
    pub provider_did: String,
    pub operation: ProviderOwnershipOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAuditKind {
    Registered,
    Revoked,
    KeyRotated,
    Blocked,
    Unblocked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderAuditEvent {
    pub event_id: Uuid,
    pub provider_id: String,
    pub kind: ProviderAuditKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationRecord {
    pub receipt_id: Uuid,
    pub verifier_id: String,
    pub verdict: VerificationVerdict,
    pub automated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub verified_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifyReceiptRequest {
    pub verifier_id: String,
    pub verdict: VerificationVerdict,
    #[serde(default)]
    pub automated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthContextRecord {
    pub auth_context_id: Uuid,
    pub secret_ref: Uuid,
    pub subject_did: String,
    pub provider_id: String,
    pub auth_model: AuthModel,
    pub token_preview: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisterAuthContextRequest {
    pub subject_did: String,
    pub provider_id: String,
    pub auth_model: AuthModel,
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AuthContextQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_did: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunVerifierSweepRequest {
    pub verifier_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationTargetKind {
    Provider,
    Agent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationStatus {
    Open,
    Actioned,
    Resolved,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationAction {
    None,
    ProviderBlocked,
    ProviderUnblocked,
    ProviderRevoked,
    AgentBlocked,
    AgentUnblocked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModerationCase {
    pub case_id: Uuid,
    pub target_kind: ModerationTargetKind,
    pub target_id: String,
    pub created_by: String,
    pub reason: String,
    pub status: ModerationStatus,
    pub action_taken: ModerationAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateModerationCaseRequest {
    pub target_kind: ModerationTargetKind,
    pub target_id: String,
    pub created_by: String,
    pub reason: String,
    #[serde(default)]
    pub auto_block: bool,
    #[serde(default)]
    pub auto_revoke_provider: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolveModerationCaseRequest {
    pub resolved_by: String,
    pub resolution_notes: String,
    #[serde(default)]
    pub clear_block: bool,
    #[serde(default)]
    pub reject_case: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ModerationCaseQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_kind: Option<ModerationTargetKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<ModerationStatus>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct BlockEntityRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSubmissionStatus {
    Draft,
    Submitted,
    InReview,
    Approved,
    Rejected,
    Suspended,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishedAgentStatus {
    Approved,
    Suspended,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentDeploymentEndpoint {
    pub url: String,
    pub protocol_binding: String,
    pub protocol_version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentDeployment {
    pub runtime: String,
    pub endpoint: AgentDeploymentEndpoint,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentReviewProfile {
    pub risk_level: RiskLevel,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data_classes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destructive_actions: Vec<String>,
    #[serde(default)]
    pub human_approval_required: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_regions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_per_call_units: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AgentArtifacts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smoke_test_report_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentAttestations {
    pub attestation_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_attester_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_digest: Option<String>,
}

pub fn build_agent_attestation_payload(request: &SubmitAgentRequest) -> Value {
    json!({
        "provider_id": request.provider_id,
        "agent_id": request.agent_id,
        "version": request.version,
        "agent_card": request.agent_card,
        "deployment": request.deployment,
        "review": request.review,
        "artifacts": request.artifacts,
        "provider_attester_did": request.attestations.provider_attester_did,
        "delegation_token": request.attestations.delegation_token,
        "source_commit": request.attestations.source_commit,
        "build_digest": request.attestations.build_digest,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubmitAgentRequest {
    pub provider_id: String,
    pub agent_id: String,
    pub version: String,
    pub agent_card: Value,
    pub deployment: AgentDeployment,
    pub review: AgentReviewProfile,
    #[serde(default)]
    pub artifacts: AgentArtifacts,
    pub attestations: AgentAttestations,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentSubmissionRecord {
    pub submission_id: Uuid,
    pub provider_id: String,
    pub agent_id: String,
    pub version: String,
    pub status: AgentSubmissionStatus,
    pub agent_card: Value,
    pub deployment: AgentDeployment,
    pub review: AgentReviewProfile,
    pub artifacts: AgentArtifacts,
    pub attestations: AgentAttestations,
    pub submitted_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AgentSubmissionQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<AgentSubmissionStatus>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApproveAgentSubmissionRequest {
    pub reviewed_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RejectAgentSubmissionRequest {
    pub reviewed_by: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublishedAgentRecord {
    pub agent_id: String,
    pub provider_id: String,
    pub version: String,
    pub status: PublishedAgentStatus,
    pub agent_card: Value,
    pub deployment: AgentDeployment,
    pub review: AgentReviewProfile,
    pub approved_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub reviewed_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvokeAgentRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default)]
    pub input: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_context_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default)]
    pub confirm_risky: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_units: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct GetAgentTaskRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_context_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvokeAgentResponse {
    pub agent_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
    pub raw: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisterProviderRequest {
    pub provider_id: String,
    pub provider_did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership_challenge_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership_signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RotateProviderKeyRequest {
    pub new_provider_did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership_challenge_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership_signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RevokeProviderRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_defaults_schema_version_to_v1() {
        let provider: ProviderRecord = serde_json::from_value(serde_json::json!({
            "provider_id": "provider-1",
            "provider_did": "did:key:z6MkpTHR8VNsBxYAAWHut2GeaddA1bbm8CLcfJ4pKzvmWwLp",
            "status": "active",
            "registered_at": "2026-03-22T00:00:00Z"
        }))
        .expect("provider should parse");
        assert_eq!(provider.schema_version, SERVICE_PROTOCOL_SCHEMA_VERSION);
    }

    #[test]
    fn submit_agent_request_round_trips() {
        let request: SubmitAgentRequest = serde_json::from_value(serde_json::json!({
            "provider_id": "acme-labs",
            "agent_id": "stripe-agent",
            "version": "0.1.0",
            "agent_card": {
                "name": "Stripe Agent",
                "description": "Payments",
                "url": "https://example.com",
                "preferredTransport": "JSONRPC",
                "protocolVersion": "1.0",
                "skills": [{"id": "payments.create_link"}],
                "securitySchemes": {"oauth2": {"type": "oauth2"}},
                "security": [{"oauth2": ["payments:write"]}]
            },
            "deployment": {
                "runtime": "remote_http",
                "endpoint": {
                    "url": "https://example.com/a2a",
                    "protocol_binding": "JSONRPC",
                    "protocol_version": "1.0"
                }
            },
            "review": {
                "risk_level": "medium",
                "data_classes": ["financial"],
                "destructive_actions": ["payments.refund"],
                "human_approval_required": true,
                "allowed_regions": ["AU"],
                "cost_per_call_units": 10
            },
            "artifacts": {
                "documentation_url": "https://example.com/docs"
            },
            "attestations": {
                "attestation_signature": "sig",
                "source_commit": "abc123"
            }
        }))
        .expect("submit agent request should parse");
        assert_eq!(request.agent_id, "stripe-agent");
        assert_eq!(request.review.cost_per_call_units, Some(10));
    }

    #[test]
    fn invoke_agent_request_defaults_input_to_null() {
        let request: InvokeAgentRequest = serde_json::from_value(serde_json::json!({
            "message": "hello"
        }))
        .expect("invoke agent request should parse");
        assert_eq!(request.input, Value::Null);
        assert!(!request.confirm_risky);
    }

    #[test]
    fn moderation_target_kind_is_agent_native() {
        let kind: ModerationTargetKind =
            serde_json::from_str("\"agent\"").expect("agent should parse");
        assert_eq!(kind, ModerationTargetKind::Agent);
    }
}
