use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::fs;
use tokio::sync::RwLock;
use uuid::Uuid;
use watt_did::proof::ProofVerifier;
use watt_did::{
    CompactJoseEdDsaVerifier, Did, DidKey, DidKeyPublicKey, JoseValidationOptions, ProofAlgorithm,
    ProofEnvelope, UcanCapability,
};
use watt_servicenet_protocol::{
    AgentDeployment, AgentHealthRecord, AgentReviewProfile, AgentSubmissionQuery,
    AgentSubmissionRecord, AgentSubmissionStatus, AgentTrustRecord, ApproveAgentSubmissionRequest,
    AuthContextQuery, AuthContextRecord, BlockEntityRequest, CreateModerationCaseRequest,
    CreateProviderOwnershipChallengeRequest, ExecutionReceipt, HealthStatus, ModerationAction,
    ModerationCase, ModerationCaseQuery, ModerationStatus, ModerationTargetKind,
    ProviderAuditEvent, ProviderAuditKind, ProviderHealthRecord, ProviderOwnershipChallenge,
    ProviderOwnershipOperation, ProviderRecord, ProviderStatus, ProviderTrustRecord,
    PublishedAgentRecord, PublishedAgentStatus, ReceiptQuery, ReceiptStatus,
    RegisterAuthContextRequest, RegisterProviderRequest, RejectAgentSubmissionRequest,
    ResolveModerationCaseRequest, RevokeProviderRequest, RiskLevel, RotateProviderKeyRequest,
    RunVerifierSweepRequest, SERVICE_PROTOCOL_SCHEMA_VERSION, StoredReceipt, SubmitAgentRequest,
    VerificationRecord, VerificationVerdict, VerifyReceiptRequest, build_agent_attestation_payload,
};

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("provider `{0}` already exists")]
    ProviderAlreadyExists(String),
    #[error("provider `{0}` not found")]
    ProviderNotFound(String),
    #[error("provider `{0}` is revoked")]
    ProviderRevoked(String),
    #[error("provider `{0}` is blocked")]
    ProviderBlocked(String),
    #[error("agent `{0}` not found")]
    PublishedAgentNotFound(String),
    #[error("agent `{0}` is blocked")]
    AgentBlocked(String),
    #[error("receipt `{0}` not found")]
    ReceiptNotFound(Uuid),
    #[error("auth context `{0}` not found")]
    AuthContextNotFound(Uuid),
    #[error("provider ownership challenge `{0}` not found")]
    OwnershipChallengeNotFound(Uuid),
    #[error("provider ownership challenge is invalid: {0}")]
    InvalidOwnershipChallenge(String),
    #[error("moderation case `{0}` not found")]
    ModerationCaseNotFound(Uuid),
    #[error("agent submission `{0}` not found")]
    AgentSubmissionNotFound(Uuid),
    #[error("invalid provider record: {0}")]
    InvalidProvider(String),
    #[error("invalid agent record: {0}")]
    InvalidAgent(String),
    #[error("invalid auth context: {0}")]
    InvalidAuthContext(String),
    #[error("invalid verification request: {0}")]
    InvalidVerification(String),
    #[error("unsupported schema version for {entity}: {version}")]
    UnsupportedSchemaVersion { entity: &'static str, version: u32 },
    #[error("registry storage error: {0}")]
    Storage(String),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Default)]
#[serde(default)]
pub struct RegistryState {
    pub providers: HashMap<String, ProviderRecord>,
    pub receipts: HashMap<Uuid, StoredReceipt>,
    pub provider_health: HashMap<String, ProviderHealthRecord>,
    pub agent_health: HashMap<String, AgentHealthRecord>,
    pub provider_trust: HashMap<String, ProviderTrustRecord>,
    pub agent_trust: HashMap<String, AgentTrustRecord>,
    pub verifications: HashMap<Uuid, Vec<VerificationRecord>>,
    pub auth_contexts: HashMap<Uuid, AuthContextRecord>,
    pub auth_context_secrets: HashMap<Uuid, EncryptedSecretEnvelope>,
    pub provider_ownership_challenges: HashMap<Uuid, ProviderOwnershipChallenge>,
    pub provider_audit_events: Vec<ProviderAuditEvent>,
    pub moderation_cases: HashMap<Uuid, ModerationCase>,
    pub agent_submissions: HashMap<Uuid, AgentSubmissionRecord>,
    pub published_agents: HashMap<String, PublishedAgentRecord>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EncryptedSecretEnvelope {
    pub nonce: String,
    pub ciphertext: String,
}

#[async_trait]
pub trait RegistryStore: Send + Sync {
    async fn load_state(&self) -> Result<RegistryState>;
    async fn save_state(&self, state: &RegistryState) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct InMemoryRegistryStore {
    state: RwLock<RegistryState>,
}

impl InMemoryRegistryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RegistryStore for InMemoryRegistryStore {
    async fn load_state(&self) -> Result<RegistryState> {
        Ok(self.state.read().await.clone())
    }

    async fn save_state(&self, state: &RegistryState) -> Result<()> {
        *self.state.write().await = state.clone();
        Ok(())
    }
}

#[derive(Debug)]
pub struct JsonFileRegistryStore {
    path: PathBuf,
    io_lock: RwLock<()>,
}

impl JsonFileRegistryStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            io_lock: RwLock::new(()),
        }
    }

    async fn ensure_parent_dir(&self) -> Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).await.with_context(|| {
                format!("failed to create registry directory `{}`", parent.display())
            })?;
        }
        Ok(())
    }
}

#[async_trait]
impl RegistryStore for JsonFileRegistryStore {
    async fn load_state(&self) -> Result<RegistryState> {
        let _guard = self.io_lock.read().await;
        if !Path::new(&self.path).exists() {
            return Ok(RegistryState::default());
        }
        let bytes = fs::read(&self.path)
            .await
            .with_context(|| format!("failed to read registry store `{}`", self.path.display()))?;
        if bytes.is_empty() {
            return Ok(RegistryState::default());
        }
        serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse registry store `{}`", self.path.display()))
    }

    async fn save_state(&self, state: &RegistryState) -> Result<()> {
        let _guard = self.io_lock.write().await;
        self.ensure_parent_dir().await?;
        let bytes =
            serde_json::to_vec_pretty(state).context("failed to serialize registry state")?;
        fs::write(&self.path, bytes)
            .await
            .with_context(|| format!("failed to write registry store `{}`", self.path.display()))?;
        Ok(())
    }
}

#[derive(Clone)]
struct SecretBroker {
    cipher: XChaCha20Poly1305,
}

impl SecretBroker {
    fn new(encoded_key: Option<&str>) -> Result<Self, RegistryError> {
        let key = if let Some(encoded_key) = encoded_key {
            let bytes = STANDARD.decode(encoded_key).map_err(|_| {
                RegistryError::InvalidAuthContext("invalid secret broker key encoding".to_owned())
            })?;
            let key: [u8; 32] = bytes.try_into().map_err(|_| {
                RegistryError::InvalidAuthContext("secret broker key must be 32 bytes".to_owned())
            })?;
            key
        } else {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            key
        };
        Ok(Self {
            cipher: XChaCha20Poly1305::new((&key).into()),
        })
    }

    fn seal(&self, secret: &str) -> Result<EncryptedSecretEnvelope, RegistryError> {
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = self.cipher.encrypt(nonce, secret.as_bytes()).map_err(|_| {
            RegistryError::Storage("failed to encrypt auth context secret".to_owned())
        })?;
        Ok(EncryptedSecretEnvelope {
            nonce: STANDARD.encode(nonce_bytes),
            ciphertext: STANDARD.encode(ciphertext),
        })
    }

    fn open(&self, envelope: &EncryptedSecretEnvelope) -> Result<String, RegistryError> {
        let nonce_bytes = STANDARD
            .decode(&envelope.nonce)
            .map_err(|_| RegistryError::Storage("invalid secret broker nonce".to_owned()))?;
        let ciphertext = STANDARD
            .decode(&envelope.ciphertext)
            .map_err(|_| RegistryError::Storage("invalid secret broker ciphertext".to_owned()))?;
        let nonce_bytes: [u8; 24] = nonce_bytes
            .try_into()
            .map_err(|_| RegistryError::Storage("invalid secret broker nonce length".to_owned()))?;
        let plaintext = self
            .cipher
            .decrypt(XNonce::from_slice(&nonce_bytes), ciphertext.as_ref())
            .map_err(|_| {
                RegistryError::Storage("failed to decrypt auth context secret".to_owned())
            })?;
        String::from_utf8(plaintext).map_err(|_| {
            RegistryError::Storage("auth context secret is not valid utf-8".to_owned())
        })
    }
}

#[derive(Debug)]
struct PostgresRegistryStore {
    pool: PgPool,
    schema: String,
}

impl PostgresRegistryStore {
    async fn connect_with_schema(database_url: &str, schema: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .with_context(|| format!("failed to connect to postgres `{database_url}`"))?;
        let store = Self {
            pool,
            schema: schema.to_owned(),
        };
        store.run_migrations().await?;
        Ok(store)
    }

    async fn run_migrations(&self) -> Result<()> {
        let schema = &self.schema;
        let statements = vec![
            format!(r#"CREATE SCHEMA IF NOT EXISTS "{schema}""#),
            format!(
                r#"CREATE TABLE IF NOT EXISTS "{schema}"."providers" (
                    provider_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    record_json JSONB NOT NULL
                )"#
            ),
            format!(
                r#"CREATE TABLE IF NOT EXISTS "{schema}"."receipts" (
                    receipt_id UUID PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    verification TEXT NOT NULL,
                    stored_json JSONB NOT NULL
                )"#
            ),
            format!(
                r#"CREATE TABLE IF NOT EXISTS "{schema}"."provider_health" (
                    provider_id TEXT PRIMARY KEY,
                    record_json JSONB NOT NULL
                )"#
            ),
            format!(
                r#"CREATE TABLE IF NOT EXISTS "{schema}"."agent_health" (
                    agent_id TEXT PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    record_json JSONB NOT NULL
                )"#
            ),
            format!(
                r#"CREATE TABLE IF NOT EXISTS "{schema}"."provider_trust" (
                    provider_id TEXT PRIMARY KEY,
                    blocked BOOLEAN NOT NULL,
                    record_json JSONB NOT NULL
                )"#
            ),
            format!(
                r#"CREATE TABLE IF NOT EXISTS "{schema}"."agent_trust" (
                    agent_id TEXT PRIMARY KEY,
                    blocked BOOLEAN NOT NULL,
                    record_json JSONB NOT NULL
                )"#
            ),
            format!(
                r#"CREATE TABLE IF NOT EXISTS "{schema}"."verifications" (
                    receipt_id UUID PRIMARY KEY,
                    record_json JSONB NOT NULL
                )"#
            ),
            format!(
                r#"CREATE TABLE IF NOT EXISTS "{schema}"."auth_contexts" (
                    auth_context_id UUID PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    subject_did TEXT NOT NULL,
                    expires_at TIMESTAMPTZ NULL,
                    record_json JSONB NOT NULL
                )"#
            ),
            format!(
                r#"CREATE TABLE IF NOT EXISTS "{schema}"."auth_context_secrets" (
                    auth_context_id UUID PRIMARY KEY,
                    secret_json JSONB NOT NULL
                )"#
            ),
            format!(
                r#"CREATE TABLE IF NOT EXISTS "{schema}"."provider_ownership_challenges" (
                    challenge_id UUID PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    challenge_json JSONB NOT NULL
                )"#
            ),
            format!(
                r#"CREATE TABLE IF NOT EXISTS "{schema}"."provider_audit_events" (
                    event_id UUID PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    event_json JSONB NOT NULL
                )"#
            ),
            format!(
                r#"CREATE TABLE IF NOT EXISTS "{schema}"."moderation_cases" (
                    case_id UUID PRIMARY KEY,
                    target_kind TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    case_json JSONB NOT NULL
                )"#
            ),
            format!(
                r#"CREATE TABLE IF NOT EXISTS "{schema}"."agent_submissions" (
                    submission_id UUID PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    record_json JSONB NOT NULL
                )"#
            ),
            format!(
                r#"CREATE TABLE IF NOT EXISTS "{schema}"."published_agents" (
                    agent_id TEXT PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    record_json JSONB NOT NULL
                )"#
            ),
        ];
        for statement in statements {
            sqlx::query(&statement)
                .execute(&self.pool)
                .await
                .with_context(|| format!("failed to run migration: {statement}"))?;
        }
        Ok(())
    }
}

#[async_trait]
impl RegistryStore for PostgresRegistryStore {
    async fn load_state(&self) -> Result<RegistryState> {
        let mut state = RegistryState::default();

        for row in sqlx::query(&format!(
            r#"SELECT record_json FROM "{}"."providers""#,
            self.schema
        ))
        .fetch_all(&self.pool)
        .await?
        {
            let provider: ProviderRecord = serde_json::from_value(row.try_get("record_json")?)?;
            state
                .providers
                .insert(provider.provider_id.clone(), provider);
        }

        for row in sqlx::query(&format!(
            r#"SELECT stored_json FROM "{}"."receipts""#,
            self.schema
        ))
        .fetch_all(&self.pool)
        .await?
        {
            let stored: StoredReceipt = serde_json::from_value(row.try_get("stored_json")?)?;
            state.receipts.insert(stored.receipt.receipt_id, stored);
        }

        for row in sqlx::query(&format!(
            r#"SELECT record_json FROM "{}"."provider_health""#,
            self.schema
        ))
        .fetch_all(&self.pool)
        .await?
        {
            let record: ProviderHealthRecord = serde_json::from_value(row.try_get("record_json")?)?;
            state
                .provider_health
                .insert(record.provider_id.clone(), record);
        }

        for row in sqlx::query(&format!(
            r#"SELECT record_json FROM "{}"."agent_health""#,
            self.schema
        ))
        .fetch_all(&self.pool)
        .await?
        {
            let record: AgentHealthRecord = serde_json::from_value(row.try_get("record_json")?)?;
            state.agent_health.insert(record.agent_id.clone(), record);
        }

        for row in sqlx::query(&format!(
            r#"SELECT record_json FROM "{}"."provider_trust""#,
            self.schema
        ))
        .fetch_all(&self.pool)
        .await?
        {
            let record: ProviderTrustRecord = serde_json::from_value(row.try_get("record_json")?)?;
            state
                .provider_trust
                .insert(record.provider_id.clone(), record);
        }

        for row in sqlx::query(&format!(
            r#"SELECT record_json FROM "{}"."agent_trust""#,
            self.schema
        ))
        .fetch_all(&self.pool)
        .await?
        {
            let record: AgentTrustRecord = serde_json::from_value(row.try_get("record_json")?)?;
            state.agent_trust.insert(record.agent_id.clone(), record);
        }

        for row in sqlx::query(&format!(
            r#"SELECT record_json FROM "{}"."verifications""#,
            self.schema
        ))
        .fetch_all(&self.pool)
        .await?
        {
            let records: Vec<VerificationRecord> =
                serde_json::from_value(row.try_get("record_json")?)?;
            if let Some(receipt_id) = records.first().map(|record| record.receipt_id) {
                state.verifications.insert(receipt_id, records);
            }
        }

        for row in sqlx::query(&format!(
            r#"SELECT record_json FROM "{}"."auth_contexts""#,
            self.schema
        ))
        .fetch_all(&self.pool)
        .await?
        {
            let record: AuthContextRecord = serde_json::from_value(row.try_get("record_json")?)?;
            state.auth_contexts.insert(record.auth_context_id, record);
        }

        for row in sqlx::query(&format!(
            r#"SELECT auth_context_id, secret_json FROM "{}"."auth_context_secrets""#,
            self.schema
        ))
        .fetch_all(&self.pool)
        .await?
        {
            let auth_context_id: Uuid = row.try_get("auth_context_id")?;
            let envelope: EncryptedSecretEnvelope =
                serde_json::from_value(row.try_get("secret_json")?)?;
            state.auth_context_secrets.insert(auth_context_id, envelope);
        }

        for row in sqlx::query(&format!(
            r#"SELECT challenge_json FROM "{}"."provider_ownership_challenges""#,
            self.schema
        ))
        .fetch_all(&self.pool)
        .await?
        {
            let challenge: ProviderOwnershipChallenge =
                serde_json::from_value(row.try_get("challenge_json")?)?;
            state
                .provider_ownership_challenges
                .insert(challenge.challenge_id, challenge);
        }

        for row in sqlx::query(&format!(
            r#"SELECT event_json FROM "{}"."provider_audit_events" ORDER BY created_at ASC"#,
            self.schema
        ))
        .fetch_all(&self.pool)
        .await?
        {
            let event: ProviderAuditEvent = serde_json::from_value(row.try_get("event_json")?)?;
            state.provider_audit_events.push(event);
        }

        for row in sqlx::query(&format!(
            r#"SELECT case_json FROM "{}"."moderation_cases""#,
            self.schema
        ))
        .fetch_all(&self.pool)
        .await?
        {
            let case: ModerationCase = serde_json::from_value(row.try_get("case_json")?)?;
            state.moderation_cases.insert(case.case_id, case);
        }

        for row in sqlx::query(&format!(
            r#"SELECT record_json FROM "{}"."agent_submissions""#,
            self.schema
        ))
        .fetch_all(&self.pool)
        .await?
        {
            let record: AgentSubmissionRecord =
                serde_json::from_value(row.try_get("record_json")?)?;
            state.agent_submissions.insert(record.submission_id, record);
        }

        for row in sqlx::query(&format!(
            r#"SELECT record_json FROM "{}"."published_agents""#,
            self.schema
        ))
        .fetch_all(&self.pool)
        .await?
        {
            let record: PublishedAgentRecord = serde_json::from_value(row.try_get("record_json")?)?;
            state
                .published_agents
                .insert(record.agent_id.clone(), record);
        }

        Ok(state)
    }

    async fn save_state(&self, state: &RegistryState) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for table in [
            "published_agents",
            "agent_submissions",
            "moderation_cases",
            "provider_audit_events",
            "provider_ownership_challenges",
            "auth_context_secrets",
            "auth_contexts",
            "verifications",
            "agent_trust",
            "provider_trust",
            "agent_health",
            "provider_health",
            "receipts",
            "providers",
        ] {
            sqlx::query(&format!(r#"DELETE FROM "{}"."{}""#, self.schema, table))
                .execute(&mut *tx)
                .await?;
        }

        for provider in state.providers.values() {
            sqlx::query(&format!(
                r#"INSERT INTO "{}"."providers" (provider_id, status, record_json) VALUES ($1, $2, $3)"#,
                self.schema
            ))
            .bind(&provider.provider_id)
            .bind(format!("{:?}", provider.status))
            .bind(serde_json::to_value(provider)?)
            .execute(&mut *tx)
            .await?;
        }

        for stored in state.receipts.values() {
            sqlx::query(&format!(
                r#"INSERT INTO "{}"."receipts" (receipt_id, agent_id, provider_id, verification, stored_json) VALUES ($1, $2, $3, $4, $5)"#,
                self.schema
            ))
            .bind(stored.receipt.receipt_id)
            .bind(&stored.receipt.agent_id)
            .bind(&stored.receipt.provider_id)
            .bind(format!("{:?}", stored.receipt.verification))
            .bind(serde_json::to_value(stored)?)
            .execute(&mut *tx)
            .await?;
        }

        for record in state.provider_health.values() {
            sqlx::query(&format!(
                r#"INSERT INTO "{}"."provider_health" (provider_id, record_json) VALUES ($1, $2)"#,
                self.schema
            ))
            .bind(&record.provider_id)
            .bind(serde_json::to_value(record)?)
            .execute(&mut *tx)
            .await?;
        }

        for record in state.agent_health.values() {
            sqlx::query(&format!(
                r#"INSERT INTO "{}"."agent_health" (agent_id, provider_id, record_json) VALUES ($1, $2, $3)"#,
                self.schema
            ))
            .bind(&record.agent_id)
            .bind(&record.provider_id)
            .bind(serde_json::to_value(record)?)
            .execute(&mut *tx)
            .await?;
        }

        for record in state.provider_trust.values() {
            sqlx::query(&format!(
                r#"INSERT INTO "{}"."provider_trust" (provider_id, blocked, record_json) VALUES ($1, $2, $3)"#,
                self.schema
            ))
            .bind(&record.provider_id)
            .bind(record.blocked)
            .bind(serde_json::to_value(record)?)
            .execute(&mut *tx)
            .await?;
        }

        for record in state.agent_trust.values() {
            sqlx::query(&format!(
                r#"INSERT INTO "{}"."agent_trust" (agent_id, blocked, record_json) VALUES ($1, $2, $3)"#,
                self.schema
            ))
            .bind(&record.agent_id)
            .bind(record.blocked)
            .bind(serde_json::to_value(record)?)
            .execute(&mut *tx)
            .await?;
        }

        for records in state.verifications.values() {
            sqlx::query(&format!(
                r#"INSERT INTO "{}"."verifications" (receipt_id, record_json) VALUES ($1, $2)"#,
                self.schema
            ))
            .bind(records[0].receipt_id)
            .bind(serde_json::to_value(records)?)
            .execute(&mut *tx)
            .await?;
        }

        for record in state.auth_contexts.values() {
            sqlx::query(&format!(
                r#"INSERT INTO "{}"."auth_contexts" (auth_context_id, provider_id, subject_did, expires_at, record_json) VALUES ($1, $2, $3, $4, $5)"#,
                self.schema
            ))
            .bind(record.auth_context_id)
            .bind(&record.provider_id)
            .bind(&record.subject_did)
            .bind(record.expires_at)
            .bind(serde_json::to_value(record)?)
            .execute(&mut *tx)
            .await?;
        }

        for (auth_context_id, envelope) in &state.auth_context_secrets {
            sqlx::query(&format!(
                r#"INSERT INTO "{}"."auth_context_secrets" (auth_context_id, secret_json) VALUES ($1, $2)"#,
                self.schema
            ))
            .bind(auth_context_id)
            .bind(serde_json::to_value(envelope)?)
            .execute(&mut *tx)
            .await?;
        }

        for challenge in state.provider_ownership_challenges.values() {
            sqlx::query(&format!(
                r#"INSERT INTO "{}"."provider_ownership_challenges" (challenge_id, provider_id, operation, expires_at, challenge_json) VALUES ($1, $2, $3, $4, $5)"#,
                self.schema
            ))
            .bind(challenge.challenge_id)
            .bind(&challenge.provider_id)
            .bind(format!("{:?}", challenge.operation))
            .bind(challenge.expires_at)
            .bind(serde_json::to_value(challenge)?)
            .execute(&mut *tx)
            .await?;
        }

        for event in &state.provider_audit_events {
            sqlx::query(&format!(
                r#"INSERT INTO "{}"."provider_audit_events" (event_id, provider_id, created_at, event_json) VALUES ($1, $2, $3, $4)"#,
                self.schema
            ))
            .bind(event.event_id)
            .bind(&event.provider_id)
            .bind(event.created_at)
            .bind(serde_json::to_value(event)?)
            .execute(&mut *tx)
            .await?;
        }

        for case in state.moderation_cases.values() {
            sqlx::query(&format!(
                r#"INSERT INTO "{}"."moderation_cases" (case_id, target_kind, target_id, status, case_json) VALUES ($1, $2, $3, $4, $5)"#,
                self.schema
            ))
            .bind(case.case_id)
            .bind(format!("{:?}", case.target_kind))
            .bind(&case.target_id)
            .bind(format!("{:?}", case.status))
            .bind(serde_json::to_value(case)?)
            .execute(&mut *tx)
            .await?;
        }

        for record in state.agent_submissions.values() {
            sqlx::query(&format!(
                r#"INSERT INTO "{}"."agent_submissions" (submission_id, provider_id, agent_id, status, record_json) VALUES ($1, $2, $3, $4, $5)"#,
                self.schema
            ))
            .bind(record.submission_id)
            .bind(&record.provider_id)
            .bind(&record.agent_id)
            .bind(format!("{:?}", record.status))
            .bind(serde_json::to_value(record)?)
            .execute(&mut *tx)
            .await?;
        }

        for record in state.published_agents.values() {
            sqlx::query(&format!(
                r#"INSERT INTO "{}"."published_agents" (agent_id, provider_id, status, record_json) VALUES ($1, $2, $3, $4)"#,
                self.schema
            ))
            .bind(&record.agent_id)
            .bind(&record.provider_id)
            .bind(format!("{:?}", record.status))
            .bind(serde_json::to_value(record)?)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct ServiceRegistry {
    store: Arc<dyn RegistryStore>,
    require_provider_ownership_challenges: bool,
    provider_challenge_ttl_secs: i64,
    secret_broker: Arc<SecretBroker>,
}

#[derive(Debug, Clone, Default)]
pub struct ServiceRegistryConfig {
    pub require_provider_ownership_challenges: bool,
    pub provider_challenge_ttl_secs: u64,
    pub secret_broker_key: Option<String>,
}

impl ServiceRegistry {
    pub fn new(store: Arc<dyn RegistryStore>, config: ServiceRegistryConfig) -> Self {
        let provider_challenge_ttl_secs = if config.provider_challenge_ttl_secs == 0 {
            300
        } else {
            config.provider_challenge_ttl_secs
        };
        let secret_broker = SecretBroker::new(config.secret_broker_key.as_deref())
            .expect("invalid secret broker configuration");
        Self {
            store,
            require_provider_ownership_challenges: config.require_provider_ownership_challenges,
            provider_challenge_ttl_secs: provider_challenge_ttl_secs as i64,
            secret_broker: Arc::new(secret_broker),
        }
    }

    pub fn in_memory() -> Self {
        Self::in_memory_with_config(ServiceRegistryConfig::default())
    }

    pub fn in_memory_with_config(config: ServiceRegistryConfig) -> Self {
        Self::new(Arc::new(InMemoryRegistryStore::new()), config)
    }

    pub fn json_file(path: impl Into<PathBuf>) -> Self {
        Self::json_file_with_config(path, ServiceRegistryConfig::default())
    }

    pub fn json_file_with_config(path: impl Into<PathBuf>, config: ServiceRegistryConfig) -> Self {
        Self::new(Arc::new(JsonFileRegistryStore::new(path)), config)
    }

    pub async fn postgres(database_url: &str) -> Result<Self, RegistryError> {
        Self::postgres_with_config(database_url, "servicenet", ServiceRegistryConfig::default())
            .await
    }

    pub async fn postgres_with_config(
        database_url: &str,
        schema: &str,
        config: ServiceRegistryConfig,
    ) -> Result<Self, RegistryError> {
        let store = PostgresRegistryStore::connect_with_schema(database_url, schema)
            .await
            .map_err(|err| RegistryError::Storage(err.to_string()))?;
        Ok(Self::new(Arc::new(store), config))
    }

    async fn load_state(&self) -> Result<RegistryState, RegistryError> {
        self.store
            .load_state()
            .await
            .map_err(|err| RegistryError::Storage(err.to_string()))
    }

    async fn save_state(&self, state: &RegistryState) -> Result<(), RegistryError> {
        self.store
            .save_state(state)
            .await
            .map_err(|err| RegistryError::Storage(err.to_string()))
    }

    pub async fn create_provider_ownership_challenge(
        &self,
        request: CreateProviderOwnershipChallengeRequest,
    ) -> Result<ProviderOwnershipChallenge, RegistryError> {
        if request.provider_id.trim().is_empty() {
            return Err(RegistryError::InvalidOwnershipChallenge(
                "provider_id must not be empty".to_owned(),
            ));
        }
        if request.provider_did.trim().is_empty() {
            return Err(RegistryError::InvalidOwnershipChallenge(
                "provider_did must not be empty".to_owned(),
            ));
        }
        validate_provider_did(&request.provider_did)?;
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let now = Utc::now();
        let challenge = ProviderOwnershipChallenge {
            challenge_id: Uuid::new_v4(),
            provider_id: request.provider_id,
            provider_did: request.provider_did,
            operation: request.operation,
            challenge: STANDARD.encode(nonce),
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(self.provider_challenge_ttl_secs),
            completed_at: None,
        };
        let mut state = self.load_state().await?;
        state
            .provider_ownership_challenges
            .insert(challenge.challenge_id, challenge.clone());
        self.save_state(&state).await?;
        Ok(challenge)
    }

    pub async fn get_provider_ownership_challenge(
        &self,
        challenge_id: Uuid,
    ) -> Result<ProviderOwnershipChallenge, RegistryError> {
        self.load_state()
            .await?
            .provider_ownership_challenges
            .get(&challenge_id)
            .cloned()
            .ok_or(RegistryError::OwnershipChallengeNotFound(challenge_id))
    }

    pub async fn register_provider(
        &self,
        request: RegisterProviderRequest,
    ) -> Result<ProviderRecord, RegistryError> {
        if request.provider_id.trim().is_empty() {
            return Err(RegistryError::InvalidProvider(
                "provider_id must not be empty".to_owned(),
            ));
        }
        if request.provider_did.trim().is_empty() {
            return Err(RegistryError::InvalidProvider(
                "provider_did must not be empty".to_owned(),
            ));
        }
        validate_provider_did(&request.provider_did)?;
        let mut state = self.load_state().await?;
        if state.providers.contains_key(&request.provider_id) {
            return Err(RegistryError::ProviderAlreadyExists(request.provider_id));
        }
        self.consume_provider_ownership_challenge(
            &mut state,
            &request.provider_id,
            &request.provider_did,
            ProviderOwnershipOperation::Register,
            request.ownership_challenge_id,
            request.ownership_signature.as_deref(),
        )?;

        let provider = ProviderRecord {
            schema_version: SERVICE_PROTOCOL_SCHEMA_VERSION,
            provider_id: request.provider_id,
            provider_did: request.provider_did,
            display_name: request.display_name,
            status: ProviderStatus::Active,
            registered_at: Utc::now(),
            revoked_at: None,
            revoke_reason: None,
        };
        validate_provider_record(&provider)?;
        state.provider_health.insert(
            provider.provider_id.clone(),
            default_provider_health(&provider.provider_id),
        );
        state.provider_trust.insert(
            provider.provider_id.clone(),
            default_provider_trust(&provider.provider_id),
        );
        push_provider_audit_event(
            &mut state,
            &provider.provider_id,
            ProviderAuditKind::Registered,
            None,
        );
        state
            .providers
            .insert(provider.provider_id.clone(), provider.clone());
        self.save_state(&state).await?;
        Ok(provider)
    }

    pub async fn upsert_provider_record(
        &self,
        provider: ProviderRecord,
    ) -> Result<ProviderRecord, RegistryError> {
        validate_provider_record(&provider)?;
        let mut state = self.load_state().await?;
        state
            .provider_health
            .entry(provider.provider_id.clone())
            .or_insert_with(|| default_provider_health(&provider.provider_id));
        state
            .provider_trust
            .entry(provider.provider_id.clone())
            .or_insert_with(|| default_provider_trust(&provider.provider_id));
        state
            .providers
            .insert(provider.provider_id.clone(), provider.clone());
        if provider.status == ProviderStatus::Revoked {
            mark_provider_agents_offline(&mut state, &provider.provider_id);
        }
        self.save_state(&state).await?;
        Ok(provider)
    }

    pub async fn rotate_provider_key(
        &self,
        provider_id: &str,
        request: RotateProviderKeyRequest,
    ) -> Result<ProviderRecord, RegistryError> {
        if request.new_provider_did.trim().is_empty() {
            return Err(RegistryError::InvalidProvider(
                "new_provider_did must not be empty".to_owned(),
            ));
        }
        validate_provider_did(&request.new_provider_did)?;
        let mut state = self.load_state().await?;
        self.consume_provider_ownership_challenge(
            &mut state,
            provider_id,
            &request.new_provider_did,
            ProviderOwnershipOperation::RotateKey,
            request.ownership_challenge_id,
            request.ownership_signature.as_deref(),
        )?;
        let provider = state
            .providers
            .get_mut(provider_id)
            .ok_or_else(|| RegistryError::ProviderNotFound(provider_id.to_owned()))?;
        provider.provider_did = request.new_provider_did;
        provider.revoked_at = None;
        provider.revoke_reason = None;
        let provider = provider.clone();
        push_provider_audit_event(
            &mut state,
            provider_id,
            ProviderAuditKind::KeyRotated,
            request.reason,
        );
        self.save_state(&state).await?;
        Ok(provider)
    }

    pub async fn get_provider(&self, provider_id: &str) -> Result<ProviderRecord, RegistryError> {
        self.load_state()
            .await?
            .providers
            .get(provider_id)
            .cloned()
            .ok_or_else(|| RegistryError::ProviderNotFound(provider_id.to_owned()))
    }

    pub async fn list_providers(&self) -> Result<Vec<ProviderRecord>, RegistryError> {
        let mut providers = self
            .load_state()
            .await?
            .providers
            .into_values()
            .collect::<Vec<_>>();
        providers.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
        Ok(providers)
    }

    pub async fn revoke_provider(
        &self,
        provider_id: &str,
        request: RevokeProviderRequest,
    ) -> Result<ProviderRecord, RegistryError> {
        let mut state = self.load_state().await?;
        let provider = state
            .providers
            .get_mut(provider_id)
            .ok_or_else(|| RegistryError::ProviderNotFound(provider_id.to_owned()))?;
        provider.status = ProviderStatus::Revoked;
        provider.revoked_at = Some(Utc::now());
        provider.revoke_reason = request.reason.clone();
        let provider = provider.clone();
        mark_provider_agents_offline(&mut state, provider_id);
        push_provider_audit_event(
            &mut state,
            provider_id,
            ProviderAuditKind::Revoked,
            request.reason,
        );
        self.save_state(&state).await?;
        Ok(provider)
    }

    pub async fn list_receipts(
        &self,
        query: &ReceiptQuery,
    ) -> Result<Vec<StoredReceipt>, RegistryError> {
        let mut receipts = self
            .load_state()
            .await?
            .receipts
            .into_values()
            .filter(|stored| {
                query
                    .agent_id
                    .as_deref()
                    .is_none_or(|agent_id| stored.receipt.agent_id == agent_id)
            })
            .filter(|stored| {
                query
                    .provider_id
                    .as_deref()
                    .is_none_or(|provider_id| stored.receipt.provider_id == provider_id)
            })
            .filter(|stored| {
                query
                    .verification
                    .as_ref()
                    .is_none_or(|verification| &stored.receipt.verification == verification)
            })
            .collect::<Vec<_>>();
        receipts.sort_by(|left, right| right.receipt.completed_at.cmp(&left.receipt.completed_at));
        if let Some(limit) = query.limit {
            receipts.truncate(limit);
        }
        Ok(receipts)
    }

    pub async fn get_receipt(&self, receipt_id: Uuid) -> Result<StoredReceipt, RegistryError> {
        self.load_state()
            .await?
            .receipts
            .get(&receipt_id)
            .cloned()
            .ok_or(RegistryError::ReceiptNotFound(receipt_id))
    }

    pub async fn record_receipt(
        &self,
        stored: &StoredReceipt,
    ) -> Result<StoredReceipt, RegistryError> {
        let mut state = self.load_state().await?;
        if !state
            .published_agents
            .contains_key(&stored.receipt.agent_id)
        {
            return Err(RegistryError::PublishedAgentNotFound(
                stored.receipt.agent_id.clone(),
            ));
        }
        state
            .receipts
            .insert(stored.receipt.receipt_id, stored.clone());
        update_health_for_receipt(&mut state, &stored.receipt);
        update_trust_for_receipt(&mut state, &stored.receipt);
        if stored.receipt.verification == VerificationVerdict::Pending {
            state.verifications.insert(
                stored.receipt.receipt_id,
                vec![VerificationRecord {
                    receipt_id: stored.receipt.receipt_id,
                    verifier_id: "system-queue".to_owned(),
                    verdict: VerificationVerdict::Pending,
                    automated: true,
                    reason: Some("receipt queued for verifier adjudication".to_owned()),
                    verified_at: Utc::now(),
                }],
            );
        } else {
            state.verifications.remove(&stored.receipt.receipt_id);
        }
        self.save_state(&state).await?;
        Ok(stored.clone())
    }

    pub async fn verify_receipt(
        &self,
        receipt_id: Uuid,
        request: VerifyReceiptRequest,
    ) -> Result<StoredReceipt, RegistryError> {
        if request.verifier_id.trim().is_empty() {
            return Err(RegistryError::InvalidVerification(
                "verifier_id must not be empty".to_owned(),
            ));
        }
        let mut state = self.load_state().await?;
        let updated_receipt = {
            let stored = state
                .receipts
                .get_mut(&receipt_id)
                .ok_or(RegistryError::ReceiptNotFound(receipt_id))?;
            stored.receipt.verification = request.verdict.clone();
            stored.clone()
        };
        state
            .verifications
            .entry(receipt_id)
            .or_default()
            .push(VerificationRecord {
                receipt_id,
                verifier_id: request.verifier_id,
                verdict: request.verdict,
                automated: request.automated,
                reason: request.reason,
                verified_at: Utc::now(),
            });
        update_trust_for_verification(&mut state, &updated_receipt.receipt);
        self.save_state(&state).await?;
        Ok(updated_receipt)
    }

    pub async fn list_verifications(
        &self,
        receipt_id: Uuid,
    ) -> Result<Vec<VerificationRecord>, RegistryError> {
        let mut items = self
            .load_state()
            .await?
            .verifications
            .get(&receipt_id)
            .cloned()
            .ok_or(RegistryError::ReceiptNotFound(receipt_id))?;
        items.sort_by(|left, right| left.verified_at.cmp(&right.verified_at));
        Ok(items)
    }

    pub async fn run_verifier_sweep(
        &self,
        request: RunVerifierSweepRequest,
    ) -> Result<Vec<StoredReceipt>, RegistryError> {
        if request.verifier_id.trim().is_empty() {
            return Err(RegistryError::InvalidVerification(
                "verifier_id must not be empty".to_owned(),
            ));
        }
        let mut state = self.load_state().await?;
        let mut updated = Vec::new();
        let receipt_ids = state
            .receipts
            .iter()
            .filter_map(|(receipt_id, stored)| {
                (stored.receipt.verification == VerificationVerdict::Pending).then_some(*receipt_id)
            })
            .collect::<Vec<_>>();

        for receipt_id in receipt_ids {
            let Some(stored) = state.receipts.get(&receipt_id).cloned() else {
                continue;
            };
            let risk_level = state
                .published_agents
                .get(&stored.receipt.agent_id)
                .map(|record| record.review.risk_level.clone());
            let verdict = match (stored.receipt.status.clone(), risk_level) {
                (ReceiptStatus::Failed, _) | (ReceiptStatus::Rejected, _) => {
                    VerificationVerdict::Failed
                }
                (_, Some(RiskLevel::High)) => VerificationVerdict::Pending,
                _ => VerificationVerdict::Verified,
            };
            let reason = match verdict {
                VerificationVerdict::Verified => Some("automated verifier sweep passed".to_owned()),
                VerificationVerdict::Failed => {
                    Some("automated verifier sweep detected failed execution".to_owned())
                }
                VerificationVerdict::Pending => {
                    Some("high-risk receipt requires manual adjudication".to_owned())
                }
                VerificationVerdict::NotRequired => None,
            };
            state
                .verifications
                .entry(receipt_id)
                .or_default()
                .push(VerificationRecord {
                    receipt_id,
                    verifier_id: request.verifier_id.clone(),
                    verdict: verdict.clone(),
                    automated: true,
                    reason,
                    verified_at: Utc::now(),
                });
            if let Some(receipt) = state.receipts.get_mut(&receipt_id) {
                receipt.receipt.verification = verdict;
            }
            if let Some(updated_receipt) = state.receipts.get(&receipt_id).cloned() {
                update_trust_for_verification(&mut state, &updated_receipt.receipt);
                updated.push(updated_receipt);
            }
        }
        self.save_state(&state).await?;
        Ok(updated)
    }

    pub async fn list_provider_health(&self) -> Result<Vec<ProviderHealthRecord>, RegistryError> {
        let mut items = self
            .load_state()
            .await?
            .provider_health
            .into_values()
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
        Ok(items)
    }

    pub async fn list_agent_health(&self) -> Result<Vec<AgentHealthRecord>, RegistryError> {
        let mut items = self
            .load_state()
            .await?
            .agent_health
            .into_values()
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.agent_id.cmp(&right.agent_id));
        Ok(items)
    }

    pub async fn list_provider_trust(&self) -> Result<Vec<ProviderTrustRecord>, RegistryError> {
        let mut items = self
            .load_state()
            .await?
            .provider_trust
            .into_values()
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
        Ok(items)
    }

    pub async fn list_agent_trust(&self) -> Result<Vec<AgentTrustRecord>, RegistryError> {
        let mut items = self
            .load_state()
            .await?
            .agent_trust
            .into_values()
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.agent_id.cmp(&right.agent_id));
        Ok(items)
    }

    pub async fn get_provider_trust(
        &self,
        provider_id: &str,
    ) -> Result<ProviderTrustRecord, RegistryError> {
        self.load_state()
            .await?
            .provider_trust
            .get(provider_id)
            .cloned()
            .ok_or_else(|| RegistryError::ProviderNotFound(provider_id.to_owned()))
    }

    pub async fn get_agent_trust(&self, agent_id: &str) -> Result<AgentTrustRecord, RegistryError> {
        self.load_state()
            .await?
            .agent_trust
            .get(agent_id)
            .cloned()
            .ok_or_else(|| RegistryError::PublishedAgentNotFound(agent_id.to_owned()))
    }

    pub async fn block_provider(
        &self,
        provider_id: &str,
        request: BlockEntityRequest,
    ) -> Result<ProviderTrustRecord, RegistryError> {
        let mut state = self.load_state().await?;
        if !state.providers.contains_key(provider_id) {
            return Err(RegistryError::ProviderNotFound(provider_id.to_owned()));
        }
        {
            let trust = state
                .provider_trust
                .entry(provider_id.to_owned())
                .or_insert_with(|| default_provider_trust(provider_id));
            trust.blocked = true;
            trust.block_reason = request.reason.clone();
            trust.updated_at = Utc::now();
        }
        mark_provider_agents_offline(&mut state, provider_id);
        push_provider_audit_event(
            &mut state,
            provider_id,
            ProviderAuditKind::Blocked,
            request.reason,
        );
        let trust = state
            .provider_trust
            .get(provider_id)
            .cloned()
            .expect("provider trust should exist");
        self.save_state(&state).await?;
        Ok(trust)
    }

    pub async fn unblock_provider(
        &self,
        provider_id: &str,
    ) -> Result<ProviderTrustRecord, RegistryError> {
        let mut state = self.load_state().await?;
        if !state.providers.contains_key(provider_id) {
            return Err(RegistryError::ProviderNotFound(provider_id.to_owned()));
        }
        {
            let trust = state
                .provider_trust
                .entry(provider_id.to_owned())
                .or_insert_with(|| default_provider_trust(provider_id));
            trust.blocked = false;
            trust.block_reason = None;
            trust.updated_at = Utc::now();
        }
        push_provider_audit_event(&mut state, provider_id, ProviderAuditKind::Unblocked, None);
        let trust = state
            .provider_trust
            .get(provider_id)
            .cloned()
            .expect("provider trust should exist");
        self.save_state(&state).await?;
        Ok(trust)
    }

    pub async fn list_provider_audit_events(
        &self,
        provider_id: &str,
    ) -> Result<Vec<ProviderAuditEvent>, RegistryError> {
        let mut items = self
            .load_state()
            .await?
            .provider_audit_events
            .into_iter()
            .filter(|event| event.provider_id == provider_id)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        Ok(items)
    }

    pub async fn block_agent(
        &self,
        agent_id: &str,
        request: BlockEntityRequest,
    ) -> Result<AgentTrustRecord, RegistryError> {
        let mut state = self.load_state().await?;
        let provider_id = state
            .published_agents
            .get(agent_id)
            .map(|record| record.provider_id.clone())
            .ok_or_else(|| RegistryError::PublishedAgentNotFound(agent_id.to_owned()))?;
        {
            let trust = state
                .agent_trust
                .entry(agent_id.to_owned())
                .or_insert_with(|| default_agent_trust(agent_id));
            trust.blocked = true;
            trust.block_reason = request.reason;
            trust.updated_at = Utc::now();
        }
        {
            let health = state
                .agent_health
                .entry(agent_id.to_owned())
                .or_insert_with(|| default_agent_health(agent_id, &provider_id));
            health.status = HealthStatus::Offline;
            health.updated_at = Utc::now();
        }
        let trust = state
            .agent_trust
            .get(agent_id)
            .cloned()
            .expect("agent trust should exist");
        self.save_state(&state).await?;
        Ok(trust)
    }

    pub async fn unblock_agent(&self, agent_id: &str) -> Result<AgentTrustRecord, RegistryError> {
        let mut state = self.load_state().await?;
        let provider_id = state
            .published_agents
            .get(agent_id)
            .map(|record| record.provider_id.clone())
            .ok_or_else(|| RegistryError::PublishedAgentNotFound(agent_id.to_owned()))?;
        {
            let trust = state
                .agent_trust
                .entry(agent_id.to_owned())
                .or_insert_with(|| default_agent_trust(agent_id));
            trust.blocked = false;
            trust.block_reason = None;
            trust.updated_at = Utc::now();
        }
        state
            .agent_health
            .entry(agent_id.to_owned())
            .or_insert_with(|| default_agent_health(agent_id, &provider_id));
        let trust = state
            .agent_trust
            .get(agent_id)
            .cloned()
            .expect("agent trust should exist");
        self.save_state(&state).await?;
        Ok(trust)
    }

    pub async fn create_moderation_case(
        &self,
        request: CreateModerationCaseRequest,
    ) -> Result<ModerationCase, RegistryError> {
        if request.created_by.trim().is_empty() {
            return Err(RegistryError::InvalidProvider(
                "created_by must not be empty".to_owned(),
            ));
        }
        if request.reason.trim().is_empty() {
            return Err(RegistryError::InvalidProvider(
                "reason must not be empty".to_owned(),
            ));
        }
        let mut state = self.load_state().await?;
        let now = Utc::now();
        let mut action_taken = ModerationAction::None;

        match request.target_kind {
            ModerationTargetKind::Provider => {
                if !state.providers.contains_key(&request.target_id) {
                    return Err(RegistryError::ProviderNotFound(request.target_id));
                }
                if request.auto_revoke_provider {
                    let provider = state
                        .providers
                        .get_mut(&request.target_id)
                        .expect("provider exists");
                    provider.status = ProviderStatus::Revoked;
                    provider.revoked_at = Some(now);
                    provider.revoke_reason = Some(request.reason.clone());
                    mark_provider_agents_offline(&mut state, &request.target_id);
                    action_taken = ModerationAction::ProviderRevoked;
                } else if request.auto_block {
                    let trust = state
                        .provider_trust
                        .entry(request.target_id.clone())
                        .or_insert_with(|| default_provider_trust(&request.target_id));
                    trust.blocked = true;
                    trust.block_reason = Some(request.reason.clone());
                    trust.updated_at = now;
                    mark_provider_agents_offline(&mut state, &request.target_id);
                    action_taken = ModerationAction::ProviderBlocked;
                }
            }
            ModerationTargetKind::Agent => {
                let provider_id = state
                    .published_agents
                    .get(&request.target_id)
                    .map(|record| record.provider_id.clone())
                    .ok_or_else(|| {
                        RegistryError::PublishedAgentNotFound(request.target_id.clone())
                    })?;
                if request.auto_revoke_provider {
                    return Err(RegistryError::InvalidProvider(
                        "auto_revoke_provider is only valid for provider cases".to_owned(),
                    ));
                }
                if request.auto_block {
                    let trust = state
                        .agent_trust
                        .entry(request.target_id.clone())
                        .or_insert_with(|| default_agent_trust(&request.target_id));
                    trust.blocked = true;
                    trust.block_reason = Some(request.reason.clone());
                    trust.updated_at = now;
                    let health = state
                        .agent_health
                        .entry(request.target_id.clone())
                        .or_insert_with(|| default_agent_health(&request.target_id, &provider_id));
                    health.status = HealthStatus::Offline;
                    health.updated_at = now;
                    action_taken = ModerationAction::AgentBlocked;
                }
            }
        }

        let case = ModerationCase {
            case_id: Uuid::new_v4(),
            target_kind: request.target_kind,
            target_id: request.target_id,
            created_by: request.created_by,
            reason: request.reason,
            status: if action_taken == ModerationAction::None {
                ModerationStatus::Open
            } else {
                ModerationStatus::Actioned
            },
            action_taken,
            resolution_notes: None,
            resolved_by: None,
            created_at: now,
            updated_at: now,
        };
        state.moderation_cases.insert(case.case_id, case.clone());
        self.save_state(&state).await?;
        Ok(case)
    }

    pub async fn resolve_moderation_case(
        &self,
        case_id: Uuid,
        request: ResolveModerationCaseRequest,
    ) -> Result<ModerationCase, RegistryError> {
        if request.resolved_by.trim().is_empty() {
            return Err(RegistryError::InvalidProvider(
                "resolved_by must not be empty".to_owned(),
            ));
        }
        if request.resolution_notes.trim().is_empty() {
            return Err(RegistryError::InvalidProvider(
                "resolution_notes must not be empty".to_owned(),
            ));
        }
        let mut state = self.load_state().await?;
        let target_snapshot = {
            let case = state
                .moderation_cases
                .get(&case_id)
                .cloned()
                .ok_or(RegistryError::ModerationCaseNotFound(case_id))?;
            (case.target_kind, case.target_id)
        };
        if request.clear_block {
            match target_snapshot.0 {
                ModerationTargetKind::Provider => {
                    if let Some(trust) = state.provider_trust.get_mut(&target_snapshot.1) {
                        trust.blocked = false;
                        trust.block_reason = None;
                        trust.updated_at = Utc::now();
                    }
                }
                ModerationTargetKind::Agent => {
                    if let Some(trust) = state.agent_trust.get_mut(&target_snapshot.1) {
                        trust.blocked = false;
                        trust.block_reason = None;
                        trust.updated_at = Utc::now();
                    }
                }
            }
        }
        let case = state
            .moderation_cases
            .get_mut(&case_id)
            .expect("moderation case should exist");
        case.status = if request.reject_case {
            ModerationStatus::Rejected
        } else {
            ModerationStatus::Resolved
        };
        case.resolution_notes = Some(request.resolution_notes);
        case.resolved_by = Some(request.resolved_by);
        case.updated_at = Utc::now();
        let case = case.clone();
        self.save_state(&state).await?;
        Ok(case)
    }

    pub async fn list_moderation_cases(
        &self,
        query: &ModerationCaseQuery,
    ) -> Result<Vec<ModerationCase>, RegistryError> {
        let mut items = self
            .load_state()
            .await?
            .moderation_cases
            .into_values()
            .filter(|case| {
                query
                    .target_kind
                    .as_ref()
                    .is_none_or(|target_kind| &case.target_kind == target_kind)
            })
            .filter(|case| {
                query
                    .target_id
                    .as_deref()
                    .is_none_or(|target_id| case.target_id == target_id)
            })
            .filter(|case| {
                query
                    .status
                    .as_ref()
                    .is_none_or(|status| &case.status == status)
            })
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        Ok(items)
    }

    pub async fn submit_agent(
        &self,
        request: SubmitAgentRequest,
    ) -> Result<AgentSubmissionRecord, RegistryError> {
        let mut state = self.load_state().await?;
        validate_submit_agent_request(&request, &state)?;
        if state
            .published_agents
            .get(&request.agent_id)
            .is_some_and(|record| record.provider_id != request.provider_id)
        {
            return Err(RegistryError::InvalidAgent(
                "agent_id is already owned by another provider".to_owned(),
            ));
        }
        let now = Utc::now();
        let record = AgentSubmissionRecord {
            submission_id: Uuid::new_v4(),
            provider_id: request.provider_id,
            agent_id: request.agent_id,
            version: request.version,
            status: AgentSubmissionStatus::Submitted,
            agent_card: request.agent_card,
            deployment: request.deployment,
            review: request.review,
            artifacts: request.artifacts,
            attestations: request.attestations,
            submitted_at: now,
            updated_at: now,
            reviewed_by: None,
            review_notes: None,
            rejection_reason: None,
        };
        state
            .agent_submissions
            .insert(record.submission_id, record.clone());
        self.save_state(&state).await?;
        Ok(record)
    }

    pub async fn get_agent_submission(
        &self,
        submission_id: Uuid,
    ) -> Result<AgentSubmissionRecord, RegistryError> {
        self.load_state()
            .await?
            .agent_submissions
            .get(&submission_id)
            .cloned()
            .ok_or(RegistryError::AgentSubmissionNotFound(submission_id))
    }

    pub async fn list_agent_submissions(
        &self,
        query: &AgentSubmissionQuery,
    ) -> Result<Vec<AgentSubmissionRecord>, RegistryError> {
        let mut items = self
            .load_state()
            .await?
            .agent_submissions
            .into_values()
            .filter(|record| {
                query
                    .provider_id
                    .as_deref()
                    .is_none_or(|provider_id| record.provider_id == provider_id)
            })
            .filter(|record| {
                query
                    .agent_id
                    .as_deref()
                    .is_none_or(|agent_id| record.agent_id == agent_id)
            })
            .filter(|record| {
                query
                    .status
                    .as_ref()
                    .is_none_or(|status| &record.status == status)
            })
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.submitted_at.cmp(&right.submitted_at));
        Ok(items)
    }

    pub async fn approve_agent_submission(
        &self,
        submission_id: Uuid,
        request: ApproveAgentSubmissionRequest,
    ) -> Result<PublishedAgentRecord, RegistryError> {
        if request.reviewed_by.trim().is_empty() {
            return Err(RegistryError::InvalidProvider(
                "reviewed_by must not be empty".to_owned(),
            ));
        }
        let mut state = self.load_state().await?;
        let now = Utc::now();
        let (provider_id, agent_id, version, agent_card, deployment, review) = {
            let submission = state
                .agent_submissions
                .get_mut(&submission_id)
                .ok_or(RegistryError::AgentSubmissionNotFound(submission_id))?;
            match submission.status {
                AgentSubmissionStatus::Approved => {
                    return Err(RegistryError::InvalidAgent(
                        "agent submission is already approved".to_owned(),
                    ));
                }
                AgentSubmissionStatus::Rejected | AgentSubmissionStatus::Revoked => {
                    return Err(RegistryError::InvalidAgent(
                        "agent submission cannot be approved from its current state".to_owned(),
                    ));
                }
                AgentSubmissionStatus::Draft
                | AgentSubmissionStatus::Submitted
                | AgentSubmissionStatus::InReview
                | AgentSubmissionStatus::Suspended => {}
            }
            submission.status = AgentSubmissionStatus::Approved;
            submission.reviewed_by = Some(request.reviewed_by.clone());
            submission.review_notes = request.review_notes.clone();
            submission.rejection_reason = None;
            submission.updated_at = now;
            (
                submission.provider_id.clone(),
                submission.agent_id.clone(),
                submission.version.clone(),
                submission.agent_card.clone(),
                submission.deployment.clone(),
                submission.review.clone(),
            )
        };
        validate_published_agent(
            &provider_id,
            &agent_id,
            &agent_card,
            &deployment,
            &review,
            &state,
        )?;
        let record = PublishedAgentRecord {
            agent_id: agent_id.clone(),
            provider_id,
            version,
            status: PublishedAgentStatus::Approved,
            agent_card,
            deployment,
            review,
            approved_at: now,
            updated_at: now,
            reviewed_by: request.reviewed_by,
            review_notes: request.review_notes,
        };
        state
            .agent_health
            .entry(agent_id.clone())
            .or_insert_with(|| default_agent_health(&record.agent_id, &record.provider_id));
        state
            .agent_trust
            .entry(agent_id.clone())
            .or_insert_with(|| default_agent_trust(&record.agent_id));
        state.published_agents.insert(agent_id, record.clone());
        self.save_state(&state).await?;
        Ok(record)
    }

    pub async fn reject_agent_submission(
        &self,
        submission_id: Uuid,
        request: RejectAgentSubmissionRequest,
    ) -> Result<AgentSubmissionRecord, RegistryError> {
        if request.reviewed_by.trim().is_empty() {
            return Err(RegistryError::InvalidProvider(
                "reviewed_by must not be empty".to_owned(),
            ));
        }
        if request.reason.trim().is_empty() {
            return Err(RegistryError::InvalidProvider(
                "reason must not be empty".to_owned(),
            ));
        }
        let mut state = self.load_state().await?;
        let record = state
            .agent_submissions
            .get_mut(&submission_id)
            .ok_or(RegistryError::AgentSubmissionNotFound(submission_id))?;
        record.status = AgentSubmissionStatus::Rejected;
        record.reviewed_by = Some(request.reviewed_by);
        record.review_notes = None;
        record.rejection_reason = Some(request.reason);
        record.updated_at = Utc::now();
        let record = record.clone();
        self.save_state(&state).await?;
        Ok(record)
    }

    pub async fn list_published_agents(&self) -> Result<Vec<PublishedAgentRecord>, RegistryError> {
        let mut items = self
            .load_state()
            .await?
            .published_agents
            .into_values()
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.agent_id.cmp(&right.agent_id));
        Ok(items)
    }

    pub async fn get_published_agent(
        &self,
        agent_id: &str,
    ) -> Result<PublishedAgentRecord, RegistryError> {
        self.load_state()
            .await?
            .published_agents
            .get(agent_id)
            .cloned()
            .ok_or_else(|| RegistryError::PublishedAgentNotFound(agent_id.to_owned()))
    }

    pub async fn upsert_published_agent(
        &self,
        record: PublishedAgentRecord,
    ) -> Result<PublishedAgentRecord, RegistryError> {
        let mut state = self.load_state().await?;
        validate_published_agent(
            &record.provider_id,
            &record.agent_id,
            &record.agent_card,
            &record.deployment,
            &record.review,
            &state,
        )?;
        state
            .agent_health
            .entry(record.agent_id.clone())
            .or_insert_with(|| default_agent_health(&record.agent_id, &record.provider_id));
        state
            .agent_trust
            .entry(record.agent_id.clone())
            .or_insert_with(|| default_agent_trust(&record.agent_id));
        state
            .published_agents
            .insert(record.agent_id.clone(), record.clone());
        self.save_state(&state).await?;
        Ok(record)
    }

    pub async fn register_auth_context(
        &self,
        request: RegisterAuthContextRequest,
    ) -> Result<AuthContextRecord, RegistryError> {
        if request.subject_did.trim().is_empty() {
            return Err(RegistryError::InvalidAuthContext(
                "subject_did must not be empty".to_owned(),
            ));
        }
        validate_subject_did(&request.subject_did)?;
        if request.token.trim().is_empty() {
            return Err(RegistryError::InvalidAuthContext(
                "token must not be empty".to_owned(),
            ));
        }
        let mut state = self.load_state().await?;
        if !state.providers.contains_key(&request.provider_id) {
            return Err(RegistryError::ProviderNotFound(request.provider_id));
        }
        let auth_context_id = Uuid::new_v4();
        let secret_ref = Uuid::new_v4();
        let record = AuthContextRecord {
            auth_context_id,
            secret_ref,
            subject_did: request.subject_did,
            provider_id: request.provider_id,
            auth_model: request.auth_model,
            token_preview: mask_secret(&request.token),
            created_at: Utc::now(),
            expires_at: request.expires_at,
        };
        let envelope = self.secret_broker.seal(&request.token)?;
        state
            .auth_contexts
            .insert(record.auth_context_id, record.clone());
        state
            .auth_context_secrets
            .insert(record.auth_context_id, envelope);
        self.save_state(&state).await?;
        Ok(record)
    }

    pub async fn get_auth_context(
        &self,
        auth_context_id: Uuid,
    ) -> Result<AuthContextRecord, RegistryError> {
        self.load_state()
            .await?
            .auth_contexts
            .get(&auth_context_id)
            .cloned()
            .ok_or(RegistryError::AuthContextNotFound(auth_context_id))
    }

    pub async fn resolve_auth_context_token(
        &self,
        auth_context_id: Uuid,
    ) -> Result<String, RegistryError> {
        let state = self.load_state().await?;
        let envelope = state
            .auth_context_secrets
            .get(&auth_context_id)
            .ok_or(RegistryError::AuthContextNotFound(auth_context_id))?;
        self.secret_broker.open(envelope)
    }

    pub async fn list_auth_contexts(
        &self,
        query: &AuthContextQuery,
    ) -> Result<Vec<AuthContextRecord>, RegistryError> {
        let mut items = self
            .load_state()
            .await?
            .auth_contexts
            .into_values()
            .filter(|record| {
                query
                    .provider_id
                    .as_deref()
                    .is_none_or(|provider_id| record.provider_id == provider_id)
            })
            .filter(|record| {
                query
                    .subject_did
                    .as_deref()
                    .is_none_or(|subject_did| record.subject_did == subject_did)
            })
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        Ok(items)
    }

    fn consume_provider_ownership_challenge(
        &self,
        state: &mut RegistryState,
        provider_id: &str,
        provider_did: &str,
        operation: ProviderOwnershipOperation,
        challenge_id: Option<Uuid>,
        signature: Option<&str>,
    ) -> Result<(), RegistryError> {
        if !self.require_provider_ownership_challenges {
            return Ok(());
        }
        let challenge_id = challenge_id.ok_or_else(|| {
            RegistryError::InvalidOwnershipChallenge(
                "ownership_challenge_id is required".to_owned(),
            )
        })?;
        let signature = signature.ok_or_else(|| {
            RegistryError::InvalidOwnershipChallenge("ownership_signature is required".to_owned())
        })?;
        let challenge = state
            .provider_ownership_challenges
            .get_mut(&challenge_id)
            .ok_or(RegistryError::OwnershipChallengeNotFound(challenge_id))?;
        if challenge.provider_id != provider_id {
            return Err(RegistryError::InvalidOwnershipChallenge(
                "challenge provider_id does not match".to_owned(),
            ));
        }
        if challenge.provider_did != provider_did {
            return Err(RegistryError::InvalidOwnershipChallenge(
                "challenge provider_did does not match".to_owned(),
            ));
        }
        if challenge.operation != operation {
            return Err(RegistryError::InvalidOwnershipChallenge(
                "challenge operation does not match".to_owned(),
            ));
        }
        if challenge.completed_at.is_some() {
            return Err(RegistryError::InvalidOwnershipChallenge(
                "challenge already completed".to_owned(),
            ));
        }
        if challenge.expires_at <= Utc::now() {
            return Err(RegistryError::InvalidOwnershipChallenge(
                "challenge expired".to_owned(),
            ));
        }
        verify_challenge_signature(provider_did, &challenge.challenge, signature)?;
        challenge.completed_at = Some(Utc::now());
        Ok(())
    }
}

fn validate_provider_record(provider: &ProviderRecord) -> Result<(), RegistryError> {
    if provider.schema_version != SERVICE_PROTOCOL_SCHEMA_VERSION {
        return Err(RegistryError::UnsupportedSchemaVersion {
            entity: "provider",
            version: provider.schema_version,
        });
    }
    if provider.provider_id.trim().is_empty() {
        return Err(RegistryError::InvalidProvider(
            "provider_id must not be empty".to_owned(),
        ));
    }
    if provider.provider_did.trim().is_empty() {
        return Err(RegistryError::InvalidProvider(
            "provider_did must not be empty".to_owned(),
        ));
    }
    validate_provider_did(&provider.provider_did)?;
    Ok(())
}

fn validate_provider_did(provider_did: &str) -> Result<(), RegistryError> {
    let did = Did::parse(provider_did).map_err(|error| {
        RegistryError::InvalidProvider(format!("invalid provider_did: {error}"))
    })?;
    if did.method() != "key" {
        return Err(RegistryError::InvalidProvider(
            "provider_did must use did:key".to_owned(),
        ));
    }
    let did_key = DidKey::from_did(did).map_err(|error| {
        RegistryError::InvalidProvider(format!("invalid provider_did: {error}"))
    })?;
    match did_key
        .decode_public_key()
        .map_err(|error| RegistryError::InvalidProvider(format!("invalid provider_did: {error}")))?
    {
        DidKeyPublicKey::Ed25519(_) => Ok(()),
        _ => Err(RegistryError::InvalidProvider(
            "provider_did must resolve to an Ed25519 verification key".to_owned(),
        )),
    }
}

fn validate_subject_did(subject_did: &str) -> Result<(), RegistryError> {
    Did::parse(subject_did)
        .map(|_| ())
        .map_err(|error| RegistryError::InvalidAuthContext(format!("invalid subject_did: {error}")))
}

fn validate_agent_attestations(
    request: &SubmitAgentRequest,
    provider: &ProviderRecord,
) -> Result<(), RegistryError> {
    let attester_did = request
        .attestations
        .provider_attester_did
        .as_deref()
        .unwrap_or(&provider.provider_did);
    validate_provider_did(attester_did)?;

    if attester_did != provider.provider_did {
        let delegation_token =
            request
                .attestations
                .delegation_token
                .as_deref()
                .ok_or_else(|| {
                    RegistryError::InvalidAgent(
                        "delegation_token is required when provider_attester_did differs from provider_did"
                            .to_owned(),
                    )
                })?;
        verify_provider_attestation_delegation(
            &provider.provider_did,
            attester_did,
            delegation_token,
        )?;
    }

    verify_agent_attestation_signature(attester_did, request)?;
    Ok(())
}

fn verify_provider_attestation_delegation(
    provider_did: &str,
    attester_did: &str,
    delegation_token: &str,
) -> Result<(), RegistryError> {
    let issuer = Did::parse(provider_did)
        .map_err(|error| RegistryError::InvalidAgent(format!("invalid provider_did: {error}")))?;
    let attester = Did::parse(attester_did).map_err(|error| {
        RegistryError::InvalidAgent(format!("invalid provider_attester_did: {error}"))
    })?;
    let document = DidKey::from_did(issuer.clone())
        .map_err(|error| RegistryError::InvalidAgent(format!("invalid provider_did: {error}")))?
        .to_document()
        .map_err(|error| RegistryError::InvalidAgent(format!("invalid provider_did: {error}")))?;
    let verifier = CompactJoseEdDsaVerifier::new(JoseValidationOptions {
        expected_issuer: Some(issuer.to_string()),
        expected_subject: Some(attester.to_string()),
        expected_audience: vec!["watt:servicenet:public-agent-attestation".to_owned()],
        current_time_ms: Some(Utc::now().timestamp_millis().max(0) as u64),
        require_exp: true,
        require_sub: true,
    });
    verifier
        .verify(
            &ProofEnvelope {
                algorithm: ProofAlgorithm::Jwt,
                value: delegation_token.to_owned(),
                verification_method: None,
                challenge: None,
                nonce: None,
                created_at: None,
                expires_at: None,
            },
            &issuer,
            &document,
        )
        .map_err(|error| {
            RegistryError::InvalidAgent(format!("invalid attestation delegation token: {error}"))
        })?;

    let capabilities = extract_capabilities_from_token(delegation_token)?;
    let allows_attestation = capabilities.iter().any(|capability| {
        (capability.resource == "*"
            || capability.resource == "urn:watt:servicenet:public-agent-attestation")
            && (capability.ability == "*" || capability.ability == "attest")
    });
    if !allows_attestation {
        return Err(RegistryError::InvalidAgent(
            "delegation_token missing public-agent attestation capability".to_owned(),
        ));
    }

    Ok(())
}

fn verify_agent_attestation_signature(
    attester_did: &str,
    request: &SubmitAgentRequest,
) -> Result<(), RegistryError> {
    let public_key_bytes = public_key_bytes_from_ref(attester_did)?;
    let signature_bytes = STANDARD
        .decode(&request.attestations.attestation_signature)
        .map_err(|_| {
            RegistryError::InvalidAgent("invalid attestation signature encoding".to_owned())
        })?;
    let public_key_bytes: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
        RegistryError::InvalidAgent("invalid attester public key length".to_owned())
    })?;
    let signature_bytes: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        RegistryError::InvalidAgent("invalid attestation signature length".to_owned())
    })?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| RegistryError::InvalidAgent("invalid attester public key bytes".to_owned()))?;
    let payload =
        serde_jcs::to_vec(&build_agent_attestation_payload(request)).map_err(|error| {
            RegistryError::InvalidAgent(format!("canonicalize attestation payload: {error}"))
        })?;
    verifying_key
        .verify(&payload, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| {
            RegistryError::InvalidAgent("attestation signature verification failed".to_owned())
        })
}

fn extract_capabilities_from_token(
    delegation_token: &str,
) -> Result<Vec<UcanCapability>, RegistryError> {
    let payload_b64 = delegation_token.split('.').nth(1).ok_or_else(|| {
        RegistryError::InvalidAgent("delegation_token must be compact JWT".to_owned())
    })?;
    #[derive(serde::Deserialize)]
    struct DelegationClaims {
        #[serde(default)]
        capabilities: Vec<UcanCapability>,
    }
    let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| {
            RegistryError::InvalidAgent("invalid delegation_token payload encoding".to_owned())
        })?;
    let claims: DelegationClaims = serde_json::from_slice(&payload_json)
        .map_err(|_| RegistryError::InvalidAgent("invalid delegation_token payload".to_owned()))?;
    Ok(claims.capabilities)
}

fn validate_submit_agent_request(
    request: &SubmitAgentRequest,
    state: &RegistryState,
) -> Result<(), RegistryError> {
    if request.provider_id.trim().is_empty() {
        return Err(RegistryError::InvalidAgent(
            "provider_id must not be empty".to_owned(),
        ));
    }
    if request.agent_id.trim().is_empty() {
        return Err(RegistryError::InvalidAgent(
            "agent_id must not be empty".to_owned(),
        ));
    }
    if request.version.trim().is_empty() {
        return Err(RegistryError::InvalidAgent(
            "version must not be empty".to_owned(),
        ));
    }
    let provider = state
        .providers
        .get(&request.provider_id)
        .ok_or_else(|| RegistryError::ProviderNotFound(request.provider_id.clone()))?;
    if provider.status == ProviderStatus::Revoked {
        return Err(RegistryError::ProviderRevoked(request.provider_id.clone()));
    }
    if state
        .provider_trust
        .get(&request.provider_id)
        .is_some_and(|trust| trust.blocked)
    {
        return Err(RegistryError::ProviderBlocked(request.provider_id.clone()));
    }
    let provider = state
        .providers
        .get(&request.provider_id)
        .ok_or_else(|| RegistryError::ProviderNotFound(request.provider_id.clone()))?;
    if request.attestations.attestation_signature.trim().is_empty() {
        return Err(RegistryError::InvalidAgent(
            "attestations.attestation_signature must not be empty".to_owned(),
        ));
    }
    validate_agent_card(&request.agent_card)?;
    validate_agent_deployment(&request.deployment)?;
    validate_agent_review_profile(&request.review)?;
    validate_agent_attestations(request, provider)?;
    Ok(())
}

fn validate_published_agent(
    provider_id: &str,
    agent_id: &str,
    agent_card: &serde_json::Value,
    deployment: &AgentDeployment,
    review: &AgentReviewProfile,
    state: &RegistryState,
) -> Result<(), RegistryError> {
    if agent_id.trim().is_empty() {
        return Err(RegistryError::InvalidAgent(
            "agent_id must not be empty".to_owned(),
        ));
    }
    let provider = state
        .providers
        .get(provider_id)
        .ok_or_else(|| RegistryError::ProviderNotFound(provider_id.to_owned()))?;
    if provider.status == ProviderStatus::Revoked {
        return Err(RegistryError::ProviderRevoked(provider_id.to_owned()));
    }
    if state
        .provider_trust
        .get(provider_id)
        .is_some_and(|trust| trust.blocked)
    {
        return Err(RegistryError::ProviderBlocked(provider_id.to_owned()));
    }
    validate_agent_card(agent_card)?;
    validate_agent_deployment(deployment)?;
    validate_agent_review_profile(review)?;
    Ok(())
}

fn validate_agent_review_profile(review: &AgentReviewProfile) -> Result<(), RegistryError> {
    for region in &review.allowed_regions {
        if region.trim().is_empty() {
            return Err(RegistryError::InvalidAgent(
                "allowed_regions must not contain empty values".to_owned(),
            ));
        }
    }
    if review.cost_per_call_units.is_some_and(|cost| cost == 0) {
        return Err(RegistryError::InvalidAgent(
            "cost_per_call_units must be greater than zero".to_owned(),
        ));
    }
    Ok(())
}

fn validate_agent_deployment(deployment: &AgentDeployment) -> Result<(), RegistryError> {
    if deployment.runtime.trim().is_empty() {
        return Err(RegistryError::InvalidAgent(
            "deployment.runtime must not be empty".to_owned(),
        ));
    }
    if deployment.endpoint.protocol_binding.trim().is_empty() {
        return Err(RegistryError::InvalidAgent(
            "deployment.endpoint.protocol_binding must not be empty".to_owned(),
        ));
    }
    if !deployment
        .endpoint
        .protocol_binding
        .eq_ignore_ascii_case("JSONRPC")
    {
        return Err(RegistryError::InvalidAgent(
            "only JSONRPC protocol_binding is supported".to_owned(),
        ));
    }
    if deployment.endpoint.protocol_version.trim().is_empty() {
        return Err(RegistryError::InvalidAgent(
            "deployment.endpoint.protocol_version must not be empty".to_owned(),
        ));
    }
    if !is_secure_or_loopback_url(&deployment.endpoint.url) {
        return Err(RegistryError::InvalidAgent(
            "deployment.endpoint.url must be https or localhost http".to_owned(),
        ));
    }
    Ok(())
}

fn validate_agent_card(agent_card: &serde_json::Value) -> Result<(), RegistryError> {
    require_card_string_field(agent_card, "name")?;
    require_card_string_field(agent_card, "description")?;
    let url = require_card_string_field(agent_card, "url")?;
    if !is_secure_or_loopback_url(url) {
        return Err(RegistryError::InvalidAgent(
            "agent_card.url must be https or localhost http".to_owned(),
        ));
    }
    let preferred_transport = require_card_string_field(agent_card, "preferredTransport")?;
    if !preferred_transport.eq_ignore_ascii_case("JSONRPC") {
        return Err(RegistryError::InvalidAgent(
            "agent_card.preferredTransport must be JSONRPC".to_owned(),
        ));
    }
    require_card_string_field(agent_card, "protocolVersion")?;
    if agent_card
        .get("skills")
        .and_then(serde_json::Value::as_array)
        .is_none_or(|skills| skills.is_empty())
    {
        return Err(RegistryError::InvalidAgent(
            "agent_card.skills must contain at least one skill".to_owned(),
        ));
    }
    if agent_card
        .get("securitySchemes")
        .and_then(serde_json::Value::as_object)
        .is_none_or(|schemes| schemes.is_empty())
    {
        return Err(RegistryError::InvalidAgent(
            "agent_card.securitySchemes must not be empty".to_owned(),
        ));
    }
    Ok(())
}

fn require_card_string_field<'a>(
    agent_card: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, RegistryError> {
    let value = agent_card
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            RegistryError::InvalidAgent(format!("agent_card.{field} must be a string"))
        })?;
    if value.trim().is_empty() {
        return Err(RegistryError::InvalidAgent(format!(
            "agent_card.{field} must not be empty"
        )));
    }
    Ok(value)
}

fn is_secure_or_loopback_url(url: &str) -> bool {
    url.starts_with("https://")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost")
}

fn verify_challenge_signature(
    provider_did: &str,
    challenge: &str,
    signature: &str,
) -> Result<(), RegistryError> {
    let public_key_bytes = public_key_bytes_from_ref(provider_did)?;
    let signature_bytes = STANDARD.decode(signature).map_err(|_| {
        RegistryError::InvalidOwnershipChallenge("invalid signature encoding".to_owned())
    })?;
    let public_key_bytes: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
        RegistryError::InvalidOwnershipChallenge("invalid public key length".to_owned())
    })?;
    let signature_bytes: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        RegistryError::InvalidOwnershipChallenge("invalid signature length".to_owned())
    })?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| {
        RegistryError::InvalidOwnershipChallenge("invalid public key bytes".to_owned())
    })?;
    verifying_key
        .verify(
            challenge.as_bytes(),
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| {
            RegistryError::InvalidOwnershipChallenge(
                "challenge signature verification failed".to_owned(),
            )
        })
}

fn public_key_bytes_from_ref(provider_did: &str) -> Result<Vec<u8>, RegistryError> {
    if provider_did.starts_with("did:") {
        let did = Did::parse(provider_did).map_err(|error| {
            RegistryError::InvalidOwnershipChallenge(format!("invalid DID key reference: {error}"))
        })?;
        let did_key = DidKey::from_did(did).map_err(|error| {
            RegistryError::InvalidOwnershipChallenge(format!(
                "unsupported DID key reference: {error}"
            ))
        })?;
        let public_key = match did_key.decode_public_key().map_err(|error| {
            RegistryError::InvalidOwnershipChallenge(format!("invalid DID key reference: {error}"))
        })? {
            DidKeyPublicKey::Ed25519(bytes) => bytes.to_vec(),
            _ => {
                return Err(RegistryError::InvalidOwnershipChallenge(
                    "provider DID must resolve to an Ed25519 verification key".to_owned(),
                ));
            }
        };
        return Ok(public_key);
    }

    Err(RegistryError::InvalidOwnershipChallenge(
        "provider_did must be a valid did:key".to_owned(),
    ))
}

fn default_provider_health(provider_id: &str) -> ProviderHealthRecord {
    ProviderHealthRecord {
        provider_id: provider_id.to_owned(),
        status: HealthStatus::Unknown,
        last_seen_at: None,
        last_latency_ms: None,
        success_count: 0,
        failure_count: 0,
        success_rate: 1.0,
        updated_at: Utc::now(),
    }
}

fn default_agent_health(agent_id: &str, provider_id: &str) -> AgentHealthRecord {
    AgentHealthRecord {
        agent_id: agent_id.to_owned(),
        provider_id: provider_id.to_owned(),
        status: HealthStatus::Unknown,
        last_seen_at: None,
        last_latency_ms: None,
        success_count: 0,
        failure_count: 0,
        success_rate: 1.0,
        updated_at: Utc::now(),
    }
}

fn default_provider_trust(provider_id: &str) -> ProviderTrustRecord {
    ProviderTrustRecord {
        provider_id: provider_id.to_owned(),
        reputation_score: 0.5,
        blocked: false,
        block_reason: None,
        updated_at: Utc::now(),
    }
}

fn default_agent_trust(agent_id: &str) -> AgentTrustRecord {
    AgentTrustRecord {
        agent_id: agent_id.to_owned(),
        reputation_score: 0.5,
        blocked: false,
        block_reason: None,
        updated_at: Utc::now(),
    }
}

fn push_provider_audit_event(
    state: &mut RegistryState,
    provider_id: &str,
    kind: ProviderAuditKind,
    reason: Option<String>,
) {
    state.provider_audit_events.push(ProviderAuditEvent {
        event_id: Uuid::new_v4(),
        provider_id: provider_id.to_owned(),
        kind,
        reason,
        created_at: Utc::now(),
    });
}

fn mark_provider_agents_offline(state: &mut RegistryState, provider_id: &str) {
    for record in state.published_agents.values() {
        if record.provider_id != provider_id {
            continue;
        }
        if let Some(health) = state.agent_health.get_mut(&record.agent_id) {
            health.status = HealthStatus::Offline;
            health.updated_at = Utc::now();
        }
    }
}

fn update_health_for_receipt(state: &mut RegistryState, receipt: &ExecutionReceipt) {
    let latency_ms = (receipt.completed_at - receipt.started_at)
        .num_milliseconds()
        .max(0) as u64;

    {
        let agent_health = state
            .agent_health
            .entry(receipt.agent_id.clone())
            .or_insert_with(|| default_agent_health(&receipt.agent_id, &receipt.provider_id));
        update_health_record(
            &mut agent_health.status,
            &mut agent_health.success_count,
            &mut agent_health.failure_count,
            &mut agent_health.success_rate,
            &mut agent_health.last_seen_at,
            &mut agent_health.last_latency_ms,
            &mut agent_health.updated_at,
            receipt,
            latency_ms,
        );
    }

    {
        let provider_health = state
            .provider_health
            .entry(receipt.provider_id.clone())
            .or_insert_with(|| default_provider_health(&receipt.provider_id));
        update_health_record(
            &mut provider_health.status,
            &mut provider_health.success_count,
            &mut provider_health.failure_count,
            &mut provider_health.success_rate,
            &mut provider_health.last_seen_at,
            &mut provider_health.last_latency_ms,
            &mut provider_health.updated_at,
            receipt,
            latency_ms,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn update_health_record(
    status: &mut HealthStatus,
    success_count: &mut u64,
    failure_count: &mut u64,
    success_rate: &mut f32,
    last_seen_at: &mut Option<DateTime<Utc>>,
    last_latency_ms: &mut Option<u64>,
    updated_at: &mut DateTime<Utc>,
    receipt: &ExecutionReceipt,
    latency_ms: u64,
) {
    let now = Utc::now();
    match receipt.status {
        watt_servicenet_protocol::ReceiptStatus::Succeeded => {
            *success_count += 1;
            *status = HealthStatus::Online;
        }
        watt_servicenet_protocol::ReceiptStatus::Rejected
        | watt_servicenet_protocol::ReceiptStatus::Failed => {
            *failure_count += 1;
            *status = HealthStatus::Degraded;
        }
    }
    let total = (*success_count + *failure_count).max(1) as f32;
    *success_rate = *success_count as f32 / total;
    *last_seen_at = Some(now);
    *last_latency_ms = Some(latency_ms);
    *updated_at = now;
}

fn update_trust_for_receipt(state: &mut RegistryState, receipt: &ExecutionReceipt) {
    let delta = match receipt.status {
        watt_servicenet_protocol::ReceiptStatus::Succeeded => 0.02,
        watt_servicenet_protocol::ReceiptStatus::Rejected => -0.05,
        watt_servicenet_protocol::ReceiptStatus::Failed => -0.1,
    };
    let provider_trust = state
        .provider_trust
        .entry(receipt.provider_id.clone())
        .or_insert_with(|| default_provider_trust(&receipt.provider_id));
    provider_trust.reputation_score = clamp_score(provider_trust.reputation_score + delta);
    provider_trust.updated_at = Utc::now();

    let agent_trust = state
        .agent_trust
        .entry(receipt.agent_id.clone())
        .or_insert_with(|| default_agent_trust(&receipt.agent_id));
    agent_trust.reputation_score = clamp_score(agent_trust.reputation_score + delta);
    agent_trust.updated_at = Utc::now();
}

fn update_trust_for_verification(state: &mut RegistryState, receipt: &ExecutionReceipt) {
    let delta = match receipt.verification {
        VerificationVerdict::Verified => 0.05,
        VerificationVerdict::Failed => -0.2,
        VerificationVerdict::NotRequired | VerificationVerdict::Pending => 0.0,
    };
    if delta == 0.0 {
        return;
    }
    let provider_trust = state
        .provider_trust
        .entry(receipt.provider_id.clone())
        .or_insert_with(|| default_provider_trust(&receipt.provider_id));
    provider_trust.reputation_score = clamp_score(provider_trust.reputation_score + delta);
    provider_trust.updated_at = Utc::now();

    let agent_trust = state
        .agent_trust
        .entry(receipt.agent_id.clone())
        .or_insert_with(|| default_agent_trust(&receipt.agent_id));
    agent_trust.reputation_score = clamp_score(agent_trust.reputation_score + delta);
    agent_trust.updated_at = Utc::now();
}

fn mask_secret(secret: &str) -> String {
    let visible = secret.chars().rev().take(4).collect::<String>();
    let visible = visible.chars().rev().collect::<String>();
    format!("***{}", visible)
}

fn clamp_score(score: f32) -> f32 {
    score.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use tempfile::tempdir;
    use watt_servicenet_protocol::{
        AgentArtifacts, AgentAttestations, ApproveAgentSubmissionRequest, AuthModel,
        CreateProviderOwnershipChallengeRequest, ProviderOwnershipOperation,
        RegisterAuthContextRequest, RiskLevel, RunVerifierSweepRequest,
    };

    fn provider_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[21u8; 32])
    }

    fn delegated_attester_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[22u8; 32])
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

    fn sign_delegation_token(
        issuer_signing_key: &SigningKey,
        issuer_did: &str,
        subject_did: &str,
    ) -> String {
        let header_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "alg": "EdDSA",
                "typ": "JWT",
                "kid": "#key-1",
            }))
            .unwrap(),
        );
        let payload_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "iss": issuer_did,
                "sub": subject_did,
                "aud": ["watt:servicenet:public-agent-attestation"],
                "iat": 1000_u64,
                "nbf": 1000_u64,
                "exp": 9_999_999_999_999_u64,
                "capabilities": [{
                    "resource": "urn:watt:servicenet:public-agent-attestation",
                    "ability": "attest"
                }]
            }))
            .unwrap(),
        );
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = issuer_signing_key.sign(signing_input.as_bytes());
        format!(
            "{header_b64}.{payload_b64}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    fn sign_submission_attestation(
        request: &mut SubmitAgentRequest,
        attester_signing_key: &SigningKey,
        provider_attester_did: Option<String>,
        delegation_token: Option<String>,
    ) {
        request.attestations.provider_attester_did = provider_attester_did;
        request.attestations.delegation_token = delegation_token;
        let payload = serde_jcs::to_vec(&build_agent_attestation_payload(request)).unwrap();
        request.attestations.attestation_signature =
            STANDARD.encode(attester_signing_key.sign(&payload).to_bytes());
    }

    fn demo_provider() -> RegisterProviderRequest {
        RegisterProviderRequest {
            provider_id: "provider-1".to_owned(),
            provider_did: did_from_signing_key(&provider_signing_key()),
            display_name: Some("Provider One".to_owned()),
            ownership_challenge_id: None,
            ownership_signature: None,
        }
    }

    fn demo_agent_submission(agent_id: &str) -> SubmitAgentRequest {
        let mut request = SubmitAgentRequest {
            provider_id: "provider-1".to_owned(),
            agent_id: agent_id.to_owned(),
            version: "0.1.0".to_owned(),
            agent_card: json!({
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
                endpoint: watt_servicenet_protocol::AgentDeploymentEndpoint {
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
        sign_submission_attestation(&mut request, &provider_key, None, None);
        request
    }

    fn demo_receipt() -> StoredReceipt {
        StoredReceipt {
            receipt: ExecutionReceipt {
                receipt_id: Uuid::new_v4(),
                agent_id: "stripe-agent".to_owned(),
                provider_id: "provider-1".to_owned(),
                status: watt_servicenet_protocol::ReceiptStatus::Succeeded,
                verification: VerificationVerdict::Pending,
                request_digest: "req".to_owned(),
                result_digest: Some("res".to_owned()),
                started_at: Utc::now(),
                completed_at: Utc::now(),
                cost_units: Some(5),
            },
            output: Some(json!({ "ok": true })),
            stderr: None,
        }
    }

    #[tokio::test]
    async fn register_provider_and_approve_agent() {
        let registry = ServiceRegistry::in_memory();
        registry
            .register_provider(demo_provider())
            .await
            .expect("provider should register");
        let submission = registry
            .submit_agent(demo_agent_submission("stripe-agent"))
            .await
            .expect("agent should submit");
        let record = registry
            .approve_agent_submission(
                submission.submission_id,
                ApproveAgentSubmissionRequest {
                    reviewed_by: "moderator-a".to_owned(),
                    review_notes: Some("approved".to_owned()),
                },
            )
            .await
            .expect("agent should approve");
        assert_eq!(record.agent_id, "stripe-agent");
    }

    #[tokio::test]
    async fn invalid_agent_submission_is_rejected() {
        let registry = ServiceRegistry::in_memory();
        registry
            .register_provider(demo_provider())
            .await
            .expect("provider should register");
        let mut request = demo_agent_submission("stripe-agent");
        request.agent_card["preferredTransport"] = json!("HTTP+JSON");
        let err = registry
            .submit_agent(request)
            .await
            .expect_err("submission should fail");
        assert!(matches!(err, RegistryError::InvalidAgent(_)));
    }

    #[tokio::test]
    async fn record_receipt_updates_health_and_queryable_receipts() {
        let registry = ServiceRegistry::in_memory();
        registry
            .register_provider(demo_provider())
            .await
            .expect("provider should register");
        let submission = registry
            .submit_agent(demo_agent_submission("stripe-agent"))
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
        let stored = demo_receipt();
        registry
            .record_receipt(&stored)
            .await
            .expect("receipt should persist");
        let receipts = registry
            .list_receipts(&ReceiptQuery {
                agent_id: Some("stripe-agent".to_owned()),
                ..Default::default()
            })
            .await
            .expect("receipt query should succeed");
        assert_eq!(receipts.len(), 1);
        let health = registry
            .list_agent_health()
            .await
            .expect("agent health should load");
        assert_eq!(health[0].status, HealthStatus::Online);
    }

    #[tokio::test]
    async fn blocklists_and_audit_events_are_recorded() {
        let registry = ServiceRegistry::in_memory();
        registry
            .register_provider(demo_provider())
            .await
            .expect("provider should register");
        registry
            .block_provider(
                "provider-1",
                BlockEntityRequest {
                    reason: Some("manual".to_owned()),
                },
            )
            .await
            .expect("provider should block");
        let trust = registry
            .get_provider_trust("provider-1")
            .await
            .expect("trust should load");
        assert!(trust.blocked);
        let audit = registry
            .list_provider_audit_events("provider-1")
            .await
            .expect("audit should load");
        assert!(
            audit
                .iter()
                .any(|event| event.kind == ProviderAuditKind::Blocked)
        );
    }

    #[tokio::test]
    async fn provider_ownership_challenge_is_required_and_verified() {
        let signing_key = SigningKey::from_bytes(&[31u8; 32]);
        let registry = ServiceRegistry::in_memory_with_config(ServiceRegistryConfig {
            require_provider_ownership_challenges: true,
            ..Default::default()
        });
        let challenge = registry
            .create_provider_ownership_challenge(CreateProviderOwnershipChallengeRequest {
                provider_id: "provider-challenge".to_owned(),
                provider_did: format!(
                    "did:key:z{}",
                    bs58::encode(
                        [
                            &[0xed, 0x01][..],
                            &signing_key.verifying_key().to_bytes()[..]
                        ]
                        .concat()
                    )
                    .into_string()
                ),
                operation: ProviderOwnershipOperation::Register,
            })
            .await
            .expect("challenge should issue");
        let signature =
            STANDARD.encode(signing_key.sign(challenge.challenge.as_bytes()).to_bytes());

        let provider = registry
            .register_provider(RegisterProviderRequest {
                provider_id: "provider-challenge".to_owned(),
                provider_did: challenge.provider_did.clone(),
                display_name: Some("Provider Challenge".to_owned()),
                ownership_challenge_id: Some(challenge.challenge_id),
                ownership_signature: Some(signature),
            })
            .await
            .expect("provider should register");
        assert_eq!(provider.provider_id, "provider-challenge");
    }

    #[tokio::test]
    async fn provider_ownership_challenge_accepts_did_key_reference() {
        let signing_key = SigningKey::from_bytes(&[32u8; 32]);
        let public_key_bytes = signing_key.verifying_key().to_bytes();
        let provider_did = format!(
            "did:key:z{}",
            bs58::encode([&[0xed, 0x01][..], &public_key_bytes[..]].concat()).into_string()
        );
        let registry = ServiceRegistry::in_memory_with_config(ServiceRegistryConfig {
            require_provider_ownership_challenges: true,
            ..Default::default()
        });
        let challenge = registry
            .create_provider_ownership_challenge(CreateProviderOwnershipChallengeRequest {
                provider_id: "provider-did".to_owned(),
                provider_did: provider_did.clone(),
                operation: ProviderOwnershipOperation::Register,
            })
            .await
            .expect("challenge should issue");
        let signature =
            STANDARD.encode(signing_key.sign(challenge.challenge.as_bytes()).to_bytes());

        let provider = registry
            .register_provider(RegisterProviderRequest {
                provider_id: "provider-did".to_owned(),
                provider_did,
                display_name: Some("Provider DID".to_owned()),
                ownership_challenge_id: Some(challenge.challenge_id),
                ownership_signature: Some(signature),
            })
            .await
            .expect("provider should register");
        assert_eq!(provider.provider_id, "provider-did");
    }

    #[tokio::test]
    async fn auth_context_secret_is_not_persisted_in_plaintext() {
        let dir = tempdir().expect("temp dir should exist");
        let path = dir.path().join("registry.json");
        let registry = ServiceRegistry::json_file_with_config(
            &path,
            ServiceRegistryConfig {
                secret_broker_key: Some(STANDARD.encode([7u8; 32])),
                ..Default::default()
            },
        );
        registry
            .register_provider(demo_provider())
            .await
            .expect("provider should register");
        let record = registry
            .register_auth_context(RegisterAuthContextRequest {
                subject_did: "did:key:z6MkfZ7QWbG4zY4C8z8c2jv7b6hJ6x9o4D7hS1x2T3y4Z5k6".to_owned(),
                provider_id: "provider-1".to_owned(),
                auth_model: AuthModel::BearerToken,
                token: "super-secret-token".to_owned(),
                expires_at: None,
            })
            .await
            .expect("auth context should register");
        assert_eq!(record.token_preview, "***oken");
        let resolved = registry
            .resolve_auth_context_token(record.auth_context_id)
            .await
            .expect("secret should resolve");
        assert_eq!(resolved, "super-secret-token");
        let bytes = std::fs::read(path).expect("registry file should exist");
        let content = String::from_utf8(bytes).expect("registry file should be utf8");
        assert!(!content.contains("super-secret-token"));
    }

    #[tokio::test]
    async fn delegated_attester_can_submit_public_agent_with_valid_token() {
        let registry = ServiceRegistry::in_memory();
        registry
            .register_provider(demo_provider())
            .await
            .expect("provider should register");

        let provider_key = provider_signing_key();
        let provider_did = did_from_signing_key(&provider_key);
        let attester_key = delegated_attester_signing_key();
        let attester_did = did_from_signing_key(&attester_key);
        let delegation_token = sign_delegation_token(&provider_key, &provider_did, &attester_did);

        let mut request = demo_agent_submission("delegated-agent");
        sign_submission_attestation(
            &mut request,
            &attester_key,
            Some(attester_did),
            Some(delegation_token),
        );

        let submission = registry
            .submit_agent(request)
            .await
            .expect("delegated attester should submit");
        assert_eq!(submission.agent_id, "delegated-agent");
    }

    #[tokio::test]
    async fn verifier_sweep_and_adjudication_update_receipt_status() {
        let registry = ServiceRegistry::in_memory();
        registry
            .register_provider(demo_provider())
            .await
            .expect("provider should register");
        let submission = registry
            .submit_agent(demo_agent_submission("risk-medium"))
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

        let stored = StoredReceipt {
            receipt: ExecutionReceipt {
                receipt_id: Uuid::new_v4(),
                agent_id: "risk-medium".to_owned(),
                provider_id: "provider-1".to_owned(),
                status: watt_servicenet_protocol::ReceiptStatus::Succeeded,
                verification: VerificationVerdict::Pending,
                request_digest: "req".to_owned(),
                result_digest: Some("res".to_owned()),
                started_at: Utc::now(),
                completed_at: Utc::now(),
                cost_units: Some(1),
            },
            output: Some(json!({ "ok": true })),
            stderr: None,
        };
        let stored = registry
            .record_receipt(&stored)
            .await
            .expect("receipt should persist");
        let sweep = registry
            .run_verifier_sweep(RunVerifierSweepRequest {
                verifier_id: "auto-verifier".to_owned(),
            })
            .await
            .expect("sweep should succeed");
        assert_eq!(sweep.len(), 1);
        assert_eq!(sweep[0].receipt.verification, VerificationVerdict::Verified);

        let verified = registry
            .verify_receipt(
                stored.receipt.receipt_id,
                VerifyReceiptRequest {
                    verifier_id: "manual-verifier".to_owned(),
                    verdict: VerificationVerdict::Verified,
                    automated: false,
                    reason: Some("manual approval".to_owned()),
                },
            )
            .await
            .expect("manual verification should succeed");
        assert_eq!(verified.receipt.verification, VerificationVerdict::Verified);
    }

    #[tokio::test]
    async fn moderation_case_can_block_and_resolve_agent() {
        let registry = ServiceRegistry::in_memory();
        registry
            .register_provider(demo_provider())
            .await
            .expect("provider should register");
        let submission = registry
            .submit_agent(demo_agent_submission("stripe-agent"))
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
        let case = registry
            .create_moderation_case(CreateModerationCaseRequest {
                target_kind: ModerationTargetKind::Agent,
                target_id: "stripe-agent".to_owned(),
                created_by: "moderator-a".to_owned(),
                reason: "abuse report".to_owned(),
                auto_block: true,
                auto_revoke_provider: false,
            })
            .await
            .expect("moderation case should create");
        assert_eq!(case.status, ModerationStatus::Actioned);
        assert!(
            registry
                .get_agent_trust("stripe-agent")
                .await
                .expect("trust should exist")
                .blocked
        );
        let resolved = registry
            .resolve_moderation_case(
                case.case_id,
                ResolveModerationCaseRequest {
                    resolved_by: "moderator-b".to_owned(),
                    resolution_notes: "issue cleared".to_owned(),
                    clear_block: true,
                    reject_case: false,
                },
            )
            .await
            .expect("moderation case should resolve");
        assert_eq!(resolved.status, ModerationStatus::Resolved);
        assert!(
            !registry
                .get_agent_trust("stripe-agent")
                .await
                .expect("trust should exist")
                .blocked
        );
    }
}
