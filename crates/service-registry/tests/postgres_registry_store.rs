use chrono::Utc;
use serde_json::json;
use uuid::Uuid;
use watt_servicenet_protocol::{
    AgentArtifacts, AgentAttestations, AgentDeployment, AgentDeploymentEndpoint,
    AgentReviewProfile, ApproveAgentSubmissionRequest, ExecutionReceipt, ReceiptQuery,
    ReceiptStatus, RegisterProviderRequest, RiskLevel, RotateProviderKeyRequest, StoredReceipt,
    SubmitAgentRequest, VerificationVerdict,
};
use watt_servicenet_registry::{ServiceRegistry, ServiceRegistryConfig};

fn database_url() -> Option<String> {
    std::env::var("SERVICENET_TEST_DATABASE_URL").ok()
}

fn schema_name(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4().simple())
}

fn provider_request() -> RegisterProviderRequest {
    RegisterProviderRequest {
        provider_id: "provider-pg".to_owned(),
        provider_public_key: "cHJvdmlkZXItcGctZGV2a2V5".to_owned(),
        display_name: Some("Provider PG".to_owned()),
        ownership_challenge_id: None,
        ownership_signature: None,
    }
}

fn agent_submission() -> SubmitAgentRequest {
    SubmitAgentRequest {
        provider_id: "provider-pg".to_owned(),
        agent_id: "stripe-agent".to_owned(),
        version: "0.1.0".to_owned(),
        agent_card: json!({
            "name": "Stripe Agent",
            "description": "PostgreSQL backed payments agent",
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
            cost_per_call_units: Some(7),
        },
        artifacts: AgentArtifacts::default(),
        attestations: AgentAttestations {
            provider_signature: "signed-by-provider".to_owned(),
            source_commit: Some("abc123".to_owned()),
            build_digest: Some("sha256:demo".to_owned()),
        },
    }
}

fn stored_receipt() -> StoredReceipt {
    StoredReceipt {
        receipt: ExecutionReceipt {
            receipt_id: Uuid::new_v4(),
            agent_id: "stripe-agent".to_owned(),
            provider_id: "provider-pg".to_owned(),
            status: ReceiptStatus::Succeeded,
            verification: VerificationVerdict::NotRequired,
            request_digest: "req".to_owned(),
            result_digest: Some("res".to_owned()),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            cost_units: Some(7),
        },
        output: Some(json!({ "ok": true })),
        stderr: None,
    }
}

#[tokio::test]
async fn postgres_store_handles_provider_agent_and_rotation_flow() {
    let Some(database_url) = database_url() else {
        eprintln!("skipping postgres integration test; SERVICENET_TEST_DATABASE_URL is not set");
        return;
    };
    let schema = schema_name("registry_flow");
    let registry = ServiceRegistry::postgres_with_config(
        &database_url,
        &schema,
        ServiceRegistryConfig::default(),
    )
    .await
    .expect("postgres registry should initialize");

    registry
        .register_provider(provider_request())
        .await
        .expect("provider should register");
    let submission = registry
        .submit_agent(agent_submission())
        .await
        .expect("agent should submit");
    let approved = registry
        .approve_agent_submission(
            submission.submission_id,
            ApproveAgentSubmissionRequest {
                reviewed_by: "moderator-a".to_owned(),
                review_notes: Some("approved".to_owned()),
            },
        )
        .await
        .expect("agent should approve");

    let agents = registry
        .list_published_agents()
        .await
        .expect("agent list should succeed");
    assert_eq!(agents.len(), 1);
    assert_eq!(approved.agent_id, "stripe-agent");

    let rotated = registry
        .rotate_provider_key(
            "provider-pg",
            RotateProviderKeyRequest {
                new_public_key: "bmV3LXByb3ZpZGVyLXBnLWtleQ==".to_owned(),
                reason: Some("rotation".to_owned()),
                ownership_challenge_id: None,
                ownership_signature: None,
            },
        )
        .await
        .expect("provider key should rotate");
    assert_eq!(rotated.provider_public_key, "bmV3LXByb3ZpZGVyLXBnLWtleQ==");

    let revoked = registry
        .revoke_provider(
            "provider-pg",
            watt_servicenet_protocol::RevokeProviderRequest {
                reason: Some("compromised".to_owned()),
            },
        )
        .await
        .expect("provider should revoke");
    assert_eq!(
        revoked.status,
        watt_servicenet_protocol::ProviderStatus::Revoked
    );
}

#[tokio::test]
async fn postgres_store_persists_agent_receipts_and_health() {
    let Some(database_url) = database_url() else {
        eprintln!("skipping postgres integration test; SERVICENET_TEST_DATABASE_URL is not set");
        return;
    };
    let schema = schema_name("registry_receipts");
    let registry = ServiceRegistry::postgres_with_config(
        &database_url,
        &schema,
        ServiceRegistryConfig::default(),
    )
    .await
    .expect("postgres registry should initialize");
    registry
        .register_provider(provider_request())
        .await
        .expect("provider should register");
    let submission = registry
        .submit_agent(agent_submission())
        .await
        .expect("agent should submit");
    registry
        .approve_agent_submission(
            submission.submission_id,
            ApproveAgentSubmissionRequest {
                reviewed_by: "moderator-a".to_owned(),
                review_notes: None,
            },
        )
        .await
        .expect("agent should approve");

    registry
        .record_receipt(&stored_receipt())
        .await
        .expect("receipt should persist");

    let receipts = registry
        .list_receipts(&ReceiptQuery {
            agent_id: Some("stripe-agent".to_owned()),
            ..ReceiptQuery::default()
        })
        .await
        .expect("receipt query should succeed");
    assert_eq!(receipts.len(), 1);

    let agent_health = registry
        .list_agent_health()
        .await
        .expect("agent health should load");
    assert_eq!(
        agent_health[0].status,
        watt_servicenet_protocol::HealthStatus::Online
    );
}
