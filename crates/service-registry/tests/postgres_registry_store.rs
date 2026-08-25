use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use postgres::types::{FromSqlOwned, ToSql};
use postgres::{Client, NoTls, Row};
use serde_json::json;
use uuid::Uuid;
use watt_servicenet_protocol::{
    AgentArtifacts, AgentAttestations, AgentDeployment, AgentDeploymentEndpoint,
    AgentInteractionProtocol, AgentReviewProfile, ApproveAgentSubmissionRequest, ExecutionReceipt,
    InvocationMode, InvokeAgentRequest, ReceiptQuery, ReceiptStatus, RegisterProviderRequest,
    RiskLevel, RotateProviderKeyRequest, StoredReceipt, SubmitAgentRequest, VerificationVerdict,
    build_agent_attestation_payload,
};
use watt_servicenet_registry::{InvocationJobKind, ServiceRegistry, ServiceRegistryConfig};

struct PgPool {
    database_url: String,
}

impl PgPool {
    async fn connect(database_url: &str) -> Result<Self, postgres::Error> {
        let database_url = database_url.to_owned();
        tokio::task::spawn_blocking({
            let database_url = database_url.clone();
            move || -> Result<(), postgres::Error> {
                let _client = Client::connect(&database_url, NoTls)?;
                Ok(())
            }
        })
        .await
        .expect("postgres connection task should join")?;
        Ok(Self { database_url })
    }
}

struct Query {
    statement: String,
    parameters: Vec<Box<dyn ToSql + Sync + Send>>,
}

fn query(statement: &str) -> Query {
    Query {
        statement: statement.to_owned(),
        parameters: Vec::new(),
    }
}

struct ScalarQuery(Query);

fn query_scalar(statement: &str) -> ScalarQuery {
    ScalarQuery(query(statement))
}

trait IntoParameter {
    fn into_parameter(self) -> Box<dyn ToSql + Sync + Send>;
}

macro_rules! owned_parameter {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl IntoParameter for $ty {
                fn into_parameter(self) -> Box<dyn ToSql + Sync + Send> {
                    Box::new(self)
                }
            }
        )+
    };
}

owned_parameter!(String, Uuid, serde_json::Value, Vec<String>);

impl IntoParameter for &str {
    fn into_parameter(self) -> Box<dyn ToSql + Sync + Send> {
        Box::new(self.to_owned())
    }
}

impl IntoParameter for &String {
    fn into_parameter(self) -> Box<dyn ToSql + Sync + Send> {
        Box::new(self.clone())
    }
}

impl IntoParameter for &Uuid {
    fn into_parameter(self) -> Box<dyn ToSql + Sync + Send> {
        Box::new(*self)
    }
}

impl Query {
    fn bind<T: IntoParameter>(mut self, value: T) -> Self {
        self.parameters.push(value.into_parameter());
        self
    }

    async fn execute(self, pool: &PgPool) -> Result<u64, postgres::Error> {
        let database_url = pool.database_url.clone();
        let statement = self.statement;
        let parameters = self.parameters;
        tokio::task::spawn_blocking(move || {
            let mut client = Client::connect(&database_url, NoTls)?;
            let parameters = parameter_refs(&parameters);
            client.execute(&statement, &parameters)
        })
        .await
        .expect("postgres query task should join")
    }

    async fn fetch_all(self, pool: &PgPool) -> Result<Vec<Row>, postgres::Error> {
        let database_url = pool.database_url.clone();
        let statement = self.statement;
        let parameters = self.parameters;
        tokio::task::spawn_blocking(move || {
            let mut client = Client::connect(&database_url, NoTls)?;
            let parameters = parameter_refs(&parameters);
            client.query(&statement, &parameters)
        })
        .await
        .expect("postgres query task should join")
    }

    async fn fetch_one(self, pool: &PgPool) -> Result<Row, postgres::Error> {
        let database_url = pool.database_url.clone();
        let statement = self.statement;
        let parameters = self.parameters;
        tokio::task::spawn_blocking(move || {
            let mut client = Client::connect(&database_url, NoTls)?;
            let parameters = parameter_refs(&parameters);
            client.query_one(&statement, &parameters)
        })
        .await
        .expect("postgres query task should join")
    }
}

fn parameter_refs(parameters: &[Box<dyn ToSql + Sync + Send>]) -> Vec<&(dyn ToSql + Sync)> {
    parameters
        .iter()
        .map(|value| value.as_ref() as &(dyn ToSql + Sync))
        .collect()
}

impl ScalarQuery {
    fn bind<T: IntoParameter>(mut self, value: T) -> Self {
        self.0 = self.0.bind(value);
        self
    }

    async fn fetch_one<T: FromSqlOwned>(self, pool: &PgPool) -> Result<T, postgres::Error> {
        Ok(self.0.fetch_one(pool).await?.try_get(0)?)
    }
}

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
            execution_mode: Default::default(),
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
            receipt_id: Uuid::new_v4().to_string(),
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
    let pool = PgPool::connect(database_url)
        .await
        .expect("postgres pool should connect");
    let rows = query(
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
    let pool = PgPool::connect(&database_url)
        .await
        .expect("postgres pool should connect");
    let provider_created_at_before: chrono::DateTime<Utc> = query(&format!(
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
    let mut legacy_record_json: serde_json::Value = query_scalar(&format!(
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
    query(&format!(
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
    let provider_created_at_after: chrono::DateTime<Utc> = query(&format!(
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

    let pool = PgPool::connect(&database_url)
        .await
        .expect("postgres pool should connect");
    let invoke_mode: String = query_scalar(&format!(
        r#"SELECT invoke_mode FROM "{schema}"."receipts" WHERE receipt_id = $1"#
    ))
    .bind(&receipts[0].receipt.receipt_id)
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

#[tokio::test]
async fn postgres_migration_preserves_legacy_uuid_receipts_as_text_ids() {
    let Some(database_url) = database_url() else {
        eprintln!("skipping postgres integration test; SERVICENET_TEST_DATABASE_URL is not set");
        return;
    };
    let schema = schema_name("registry_receipt_migration");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("postgres pool should connect");
    query(&format!(r#"CREATE SCHEMA "{schema}""#))
        .execute(&pool)
        .await
        .expect("legacy schema should create");
    query(&format!(
        r#"CREATE TABLE "{schema}"."receipts" (
            receipt_id UUID PRIMARY KEY,
            agent_id TEXT NOT NULL,
            provider_id TEXT NOT NULL,
            invoke_mode TEXT NOT NULL DEFAULT 'sync',
            caller_agent_id TEXT NULL,
            caller_public_id TEXT NULL,
            caller_display_name TEXT NULL,
            caller_node_id TEXT NULL,
            verification TEXT NOT NULL,
            request_secret_json JSONB NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            stored_json JSONB NOT NULL
        )"#
    ))
    .execute(&pool)
    .await
    .expect("legacy receipts table should create");
    query(&format!(
        r#"CREATE TABLE "{schema}"."verifications" (
            receipt_id UUID PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            record_json JSONB NOT NULL
        )"#
    ))
    .execute(&pool)
    .await
    .expect("legacy verifications table should create");

    let stored = stored_receipt();
    let legacy_id = Uuid::parse_str(&stored.receipt.receipt_id).expect("receipt id should be UUID");
    query(&format!(
        r#"INSERT INTO "{schema}"."receipts"
           (receipt_id, agent_id, provider_id, invoke_mode, verification,
            request_secret_json, stored_json)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#
    ))
    .bind(legacy_id)
    .bind(&stored.receipt.agent_id)
    .bind(&stored.receipt.provider_id)
    .bind("async")
    .bind("NotRequired")
    .bind(json!({"nonce": "legacy", "ciphertext": "legacy"}))
    .bind(serde_json::to_value(&stored).expect("receipt should serialize"))
    .execute(&pool)
    .await
    .expect("legacy receipt should insert");

    let registry = ServiceRegistry::postgres_with_config(
        &database_url,
        &schema,
        ServiceRegistryConfig::default(),
    )
    .await
    .expect("postgres migration should initialize");
    let migrated = registry
        .get_receipt(&stored.receipt.receipt_id)
        .await
        .expect("legacy receipt should remain queryable");
    assert_eq!(migrated.receipt.receipt_id, stored.receipt.receipt_id);

    let column_types = query(
        r#"SELECT table_name, data_type
           FROM information_schema.columns
           WHERE table_schema = $1
             AND table_name IN ('receipts', 'verifications')
             AND column_name = 'receipt_id'
           ORDER BY table_name"#,
    )
    .bind(&schema)
    .fetch_all(&pool)
    .await
    .expect("migrated receipt columns should be queryable");
    assert_eq!(column_types.len(), 2);
    assert!(
        column_types
            .iter()
            .all(|row| row.get::<_, String>("data_type") == "text")
    );
    let job_kind: String = query_scalar(&format!(
        r#"SELECT job_kind FROM "{schema}"."receipts" WHERE receipt_id = $1"#
    ))
    .bind(&stored.receipt.receipt_id)
    .fetch_one(&pool)
    .await
    .expect("legacy async job kind should be backfilled");
    assert_eq!(job_kind, "runtime_invoke");
}

#[tokio::test]
async fn postgres_async_receipt_is_claimed_once_across_workers() {
    let Some(database_url) = database_url() else {
        eprintln!("skipping postgres integration test; SERVICENET_TEST_DATABASE_URL is not set");
        return;
    };
    let schema = schema_name("registry_async_claim");
    let config = ServiceRegistryConfig {
        secret_broker_key: Some(STANDARD.encode([8u8; 32])),
        ..Default::default()
    };
    let registry_a = ServiceRegistry::postgres_with_config(&database_url, &schema, config.clone())
        .await
        .expect("first postgres registry should initialize");
    registry_a
        .register_provider(provider_request())
        .await
        .expect("provider should register");
    registry_a
        .submit_agent(agent_submission())
        .await
        .expect("agent should publish");

    let mut stored = stored_receipt();
    stored.receipt.status = ReceiptStatus::Running;
    stored.receipt.completed_at = None;
    stored.output = None;
    let request = InvokeAgentRequest {
        task_id: None,
        context_id: None,
        message: Some("run once".to_owned()),
        input: json!({"amount": 7}),
        skill_id: None,
        return_immediately: None,
        settlement: None,
        auth_token: Some("postgres-private-token".to_owned()),
        auth_context_id: None,
        region: Some("AU".to_owned()),
        confirm_risky: true,
        max_cost_units: Some(7),
        agent_envelope: Some(json!({"signed": true})),
    };
    registry_a
        .enqueue_customized_task(&stored, &request)
        .await
        .expect("customized task should enqueue");
    let registry_b = ServiceRegistry::postgres_with_config(&database_url, &schema, config)
        .await
        .expect("second postgres registry should initialize");

    let (claim_a, claim_b) = tokio::join!(
        registry_a.claim_async_invocations("worker-a", 60, 1),
        registry_b.claim_async_invocations("worker-b", 60, 1),
    );
    let claim_a = claim_a.expect("worker a claim should succeed");
    let claim_b = claim_b.expect("worker b claim should succeed");
    assert_eq!(claim_a.len() + claim_b.len(), 1);
    let claimed = claim_a
        .first()
        .or_else(|| claim_b.first())
        .expect("one claim");
    assert_eq!(claimed.receipt_id, stored.receipt.receipt_id);
    assert_eq!(claimed.kind, InvocationJobKind::CustomizedTask);
    assert_eq!(claimed.request, request);
    assert_eq!(claimed.attempt_count, 1);

    let pool = PgPool::connect(&database_url)
        .await
        .expect("postgres pool should connect");
    let row = query(&format!(
        r#"SELECT job_kind, request_secret_json, lease_owner, attempt_count
           FROM "{schema}"."receipts" WHERE receipt_id = $1"#
    ))
    .bind(&stored.receipt.receipt_id)
    .fetch_one(&pool)
    .await
    .expect("claimed receipt should load");
    let encrypted: serde_json::Value = row.get("request_secret_json");
    assert_eq!(row.get::<_, String>("job_kind"), "customized_task");
    assert!(!encrypted.to_string().contains("postgres-private-token"));
    assert!(row.get::<_, Option<String>>("lease_owner").is_some());
    assert_eq!(row.get::<_, i32>("attempt_count"), 1);
}
