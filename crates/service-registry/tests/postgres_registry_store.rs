use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;
use watt_servicenet_protocol::{
    AgentArtifacts, AgentAttestations, AgentDeployment, AgentDeploymentEndpoint,
    AgentInteractionProtocol, AgentReviewProfile, ApproveAgentSubmissionRequest, ExecutionReceipt,
    InvocationMode, ReceiptQuery, ReceiptStatus, RegisterProviderRequest, RiskLevel,
    RotateProviderKeyRequest, StoredReceipt, SubmitAgentRequest, VerificationVerdict,
    build_agent_attestation_payload,
};
use watt_servicenet_registry::{ServiceRegistry, ServiceRegistryConfig};

fn database_url() -> Option<String> {
    std::env::var("SERVICENET_TEST_DATABASE_URL").ok()
}

fn schema_name(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4().simple())
}

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
        provider_id: "provider-pg".to_owned(),
        provider_did: did_from_signing_key(&provider_signing_key()),
        display_name: Some("Provider PG".to_owned()),
        ownership_challenge_id: None,
        ownership_signature: None,
    }
}

fn agent_submission() -> SubmitAgentRequest {
    let service_key = SigningKey::from_bytes(&[24u8; 32]);
    let service_did = did_from_signing_key(&service_key);
    let mut request = SubmitAgentRequest {
        provider_id: "provider-pg".to_owned(),
        agent_id: "stripe-agent".to_owned(),
        service_did: service_did.clone(),
        service_address: Some("stripe@wattetheria".to_owned()),
        version: "0.1.0".to_owned(),
        agent_card: json!({
            "name": "Stripe Agent",
            "description": "PostgreSQL backed payments agent",
            "url": "https://stripe-agent.example.com",
            "preferredTransport": "JSONRPC",
            "protocolVersion": "1.0",
            "supportsTask": false,
            "skills": [{ "id": "payments.create_link" }],
            "securitySchemes": { "oauth2": { "type": "oauth2" } },
            "security": [{ "oauth2": ["payments:write"] }]
        }),
        deployment: AgentDeployment {
            runtime: "wattetheria_adapter".to_owned(),
            connection_mode: Default::default(),
            endpoint: AgentDeploymentEndpoint {
                url: "https://stripe-agent.example.com/a2a".to_owned(),
                protocol_binding: "JSONRPC".to_owned(),
                protocol_version: "1.0".to_owned(),
                interaction_protocol: AgentInteractionProtocol::A2aV1,
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
            attestation_signature: String::new(),
            provider_attester_did: None,
            delegation_token: None,
            source_commit: Some("abc123".to_owned()),
            build_digest: Some("sha256:demo".to_owned()),
            nonce: None,
            issued_at_ms: None,
            expires_at_ms: None,
        },
    };
    let provider_key = provider_signing_key();
    sign_submission_attestation(&mut request, &provider_key);
    request
}

fn stored_receipt() -> StoredReceipt {
    StoredReceipt {
        receipt: ExecutionReceipt {
            receipt_id: Uuid::new_v4(),
            agent_id: "stripe-agent".to_owned(),
            provider_id: "provider-pg".to_owned(),
            caller_agent_id: Some("did:key:zCallerPg".to_owned()),
            caller_public_id: Some("pub_caller_pg".to_owned()),
            caller_display_name: Some("Postgres Caller".to_owned()),
            caller_node_id: Some("node-caller-pg".to_owned()),
            invoke_mode: InvocationMode::Async,
            status: ReceiptStatus::Succeeded,
            verification: VerificationVerdict::NotRequired,
            request_digest: "req".to_owned(),
            result_digest: Some("res".to_owned()),
            invocation_attestation: None,
            receipt_issuer_did: None,
            receipt_signed_at_ms: None,
            receipt_signature: None,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            cost_units: Some(7),
        },
        output: Some(json!({ "ok": true })),
        stderr: None,
    }
}

fn registry_tables() -> Vec<String> {
    [
        "providers",
        "receipts",
        "provider_health",
        "agent_health",
        "provider_trust",
        "agent_trust",
        "verifications",
        "auth_contexts",
        "auth_context_secrets",
        "provider_ownership_challenges",
        "provider_audit_events",
        "moderation_cases",
        "agent_submissions",
        "published_agents",
        "consumed_attestation_nonces",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect()
}

async fn assert_temporal_columns_exist(database_url: &str, schema: &str) {
    let pool = sqlx::PgPool::connect(database_url)
        .await
        .expect("postgres pool should connect");
    let rows = sqlx::query(
        r#"
        SELECT table_name, column_name
        FROM information_schema.columns
        WHERE table_schema = $1
          AND table_name = ANY($2)
          AND column_name IN ('created_at', 'updated_at')
        "#,
    )
    .bind(schema)
    .bind(registry_tables())
    .fetch_all(&pool)
    .await
    .expect("temporal columns should be queryable");

    assert_eq!(rows.len(), registry_tables().len() * 2);
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
    assert_temporal_columns_exist(&database_url, &schema).await;

    registry
        .register_provider(provider_request())
        .await
        .expect("provider should register");
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("postgres pool should connect");
    let provider_created_at_before: chrono::DateTime<Utc> = sqlx::query(&format!(
        r#"SELECT created_at FROM "{schema}"."providers" WHERE provider_id = $1"#
    ))
    .bind("provider-pg")
    .fetch_one(&pool)
    .await
    .expect("provider timestamp should load")
    .try_get("created_at")
    .expect("created_at should decode");
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

    assert_eq!(
        approved.service_address.as_deref(),
        Some("stripe@wattetheria")
    );
    let mut legacy_record_json: serde_json::Value = sqlx::query_scalar(&format!(
        r#"SELECT record_json FROM "{schema}"."published_agents" WHERE agent_id = $1"#
    ))
    .bind("stripe-agent")
    .fetch_one(&pool)
    .await
    .expect("published agent record_json should load");
    legacy_record_json
        .as_object_mut()
        .expect("published agent record_json should be an object")
        .remove("service_address");
    sqlx::query(&format!(
        r#"UPDATE "{schema}"."published_agents" SET record_json = $1 WHERE agent_id = $2"#
    ))
    .bind(legacy_record_json)
    .bind("stripe-agent")
    .execute(&pool)
    .await
    .expect("legacy record_json update should succeed");

    let agents = registry
        .list_published_agents()
        .await
        .expect("agent list should succeed");
    assert_eq!(agents.len(), 1);
    assert_eq!(approved.agent_id, "stripe-agent");
    assert_eq!(
        agents[0].service_address.as_deref(),
        Some("stripe@wattetheria")
    );
    let (page_agents, known_count) = registry
        .list_published_agents_page(10, 0)
        .await
        .expect("agent page should succeed");
    assert_eq!(known_count, 1);
    assert_eq!(
        page_agents[0].service_address.as_deref(),
        Some("stripe@wattetheria")
    );

    let rotated = registry
        .rotate_provider_key(
            "provider-pg",
            RotateProviderKeyRequest {
                new_provider_did: "did:key:z6MkhY7vL8T5d4w8n8f1M5uH1D2e4Q9zP3n5K7s2V4x6Y8Za"
                    .to_owned(),
                reason: Some("rotation".to_owned()),
                ownership_challenge_id: None,
                ownership_signature: None,
            },
        )
        .await
        .expect("provider key should rotate");
    assert_eq!(
        rotated.provider_did,
        "did:key:z6MkhY7vL8T5d4w8n8f1M5uH1D2e4Q9zP3n5K7s2V4x6Y8Za"
    );
    let provider_created_at_after: chrono::DateTime<Utc> = sqlx::query(&format!(
        r#"SELECT created_at FROM "{schema}"."providers" WHERE provider_id = $1"#
    ))
    .bind("provider-pg")
    .fetch_one(&pool)
    .await
    .expect("provider timestamp should load after upsert")
    .try_get("created_at")
    .expect("created_at should decode after upsert");
    assert_eq!(provider_created_at_after, provider_created_at_before);

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
    assert_eq!(
        receipts[0].receipt.caller_agent_id.as_deref(),
        Some("did:key:zCallerPg")
    );
    assert_eq!(
        receipts[0].receipt.caller_public_id.as_deref(),
        Some("pub_caller_pg")
    );
    assert_eq!(receipts[0].receipt.invoke_mode, InvocationMode::Async);

    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("postgres pool should connect");
    let invoke_mode: String = sqlx::query_scalar(&format!(
        r#"SELECT invoke_mode FROM "{schema}"."receipts" WHERE receipt_id = $1"#
    ))
    .bind(receipts[0].receipt.receipt_id)
    .fetch_one(&pool)
    .await
    .expect("receipt invoke mode column should be queryable");
    assert_eq!(invoke_mode, "async");

    let caller_receipts = registry
        .list_receipts(&ReceiptQuery {
            caller_agent_id: Some("did:key:zCallerPg".to_owned()),
            caller_public_id: Some("pub_caller_pg".to_owned()),
            invoke_mode: Some(InvocationMode::Async),
            ..ReceiptQuery::default()
        })
        .await
        .expect("caller receipt query should succeed");
    assert_eq!(caller_receipts.len(), 1);

    let agent_health = registry
        .list_agent_health()
        .await
        .expect("agent health should load");
    assert_eq!(
        agent_health[0].status,
        watt_servicenet_protocol::HealthStatus::Online
    );
}
