use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant, timeout};
use uuid::Uuid;
use watt_servicenet_gateway::{GatewayError, GatewayPolicyConfig, GatewayService};
use watt_servicenet_p2p::{
    NetworkNodeId, ServiceNetworkNode, ServiceNetworkP2pConfig, ServiceNetworkRecordSummary,
    ServiceNetworkRuntime, ServiceNetworkRuntimeEvent, ServiceNetworkSyncManifest,
    provider_record_summary, published_agent_record_summary,
};
use watt_servicenet_protocol::{
    AgentSubmissionQuery, AgentSubmissionStatus, ApproveAgentSubmissionRequest, AuthContextQuery,
    BlockEntityRequest, CreateModerationCaseRequest, CreateProviderOwnershipChallengeRequest,
    GetAgentTaskRequest, InvokeAgentRequest, ModerationCaseQuery, ProviderRecord,
    PublishedAgentRecord, ReceiptQuery, RegisterAuthContextRequest, RegisterProviderRequest,
    RejectAgentSubmissionRequest, ResolveModerationCaseRequest, RevokeProviderRequest,
    RotateProviderKeyRequest, RunVerifierSweepRequest, SubmitAgentRequest, UnpublishAgentRequest,
    VerifyReceiptRequest,
};
use watt_servicenet_registry::{RegistryError, ServiceRegistry, ServiceRegistryConfig};

const DEFAULT_AGENT_LIST_LIMIT: usize = 50;
const MAX_AGENT_LIST_LIMIT: usize = 100;
const P2P_BACKFILL_PAGE_SIZE: usize = 256;
const DEFAULT_P2P_ANTI_ENTROPY_INTERVAL_SECS: u64 = 60;
const PUBLIC_SERVICENET_NETWORK_ID: &str = "mainnet.watt-etheria";
const SERVICENET_FEDERATION_MODE_ENV: &str = "SERVICENET_FEDERATION_MODE";
const SERVICENET_FEDERATION_TRUSTED_PEERS_ENV: &str = "SERVICENET_FEDERATION_TRUSTED_PEERS";
const SERVICENET_P2P_ANTI_ENTROPY_INTERVAL_SECS_ENV: &str =
    "SERVICENET_P2P_ANTI_ENTROPY_INTERVAL_SECS";

#[derive(Debug, Clone, PartialEq, Eq)]
enum FederationTrustMode {
    Open,
    Trusted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FederationTrustPolicy {
    mode: FederationTrustMode,
    trusted_peers: BTreeSet<String>,
}

impl FederationTrustPolicy {
    fn from_env() -> Self {
        let mode = match std::env::var(SERVICENET_FEDERATION_MODE_ENV)
            .ok()
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("trusted" | "allowlist" | "allow-list") => FederationTrustMode::Trusted,
            _ => FederationTrustMode::Open,
        };
        Self {
            mode,
            trusted_peers: std::env::var(SERVICENET_FEDERATION_TRUSTED_PEERS_ENV)
                .ok()
                .map(|value| split_csv(&value).into_iter().collect())
                .unwrap_or_default(),
        }
    }

    fn allows_peer(&self, peer: &impl Display) -> bool {
        match self.mode {
            FederationTrustMode::Open => true,
            FederationTrustMode::Trusted => self.trusted_peers.contains(&peer.to_string()),
        }
    }
}

#[derive(Clone)]
struct AppState {
    registry: Arc<ServiceRegistry>,
    gateway: GatewayService,
    p2p_commands: Option<mpsc::Sender<P2pCommand>>,
}

#[derive(Debug, serde::Deserialize)]
struct AgentListQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

pub async fn build_default_app() -> anyhow::Result<Router> {
    Ok(build_app(build_default_state().await?))
}

pub async fn build_default_state() -> anyhow::Result<RouterState> {
    let database_url = std::env::var("SERVICENET_DATABASE_URL").ok();
    let secret_broker_key = std::env::var("SERVICENET_SECRET_BROKER_KEY").ok();
    if database_url.is_some() && secret_broker_key.is_none() {
        anyhow::bail!("SERVICENET_SECRET_BROKER_KEY is required for database-backed deployments");
    }
    let registry_config = ServiceRegistryConfig {
        require_provider_ownership_challenges: std::env::var(
            "SERVICENET_REQUIRE_PROVIDER_OWNERSHIP_CHALLENGES",
        )
        .ok()
        .map(|value| parse_env_flag(Some(value.as_str())))
        .unwrap_or(database_url.is_some()),
        provider_challenge_ttl_secs: std::env::var("SERVICENET_PROVIDER_CHALLENGE_TTL_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(300),
        secret_broker_key,
    };

    let registry = if let Some(database_url) = database_url {
        let schema =
            std::env::var("SERVICENET_DATABASE_SCHEMA").unwrap_or_else(|_| "public".to_owned());
        Arc::new(
            ServiceRegistry::postgres_with_config(&database_url, &schema, registry_config).await?,
        )
    } else if let Ok(path) = std::env::var("SERVICENET_REGISTRY_FILE") {
        Arc::new(ServiceRegistry::json_file_with_config(
            path,
            registry_config,
        ))
    } else {
        Arc::new(ServiceRegistry::in_memory_with_config(registry_config))
    };

    let p2p_commands = start_p2p_sync_if_enabled(registry.clone()).await?;
    Ok(RouterState {
        registry,
        p2p_commands,
        gateway_policy: GatewayPolicyConfig {
            default_max_cost_units: std::env::var("SERVICENET_GATEWAY_MAX_COST_UNITS")
                .ok()
                .and_then(|value| value.parse().ok()),
        },
    })
}

pub fn build_local_app(registry: Arc<ServiceRegistry>) -> Router {
    build_app(RouterState {
        registry,
        p2p_commands: None,
        gateway_policy: GatewayPolicyConfig::default(),
    })
}

pub struct RouterState {
    pub registry: Arc<ServiceRegistry>,
    p2p_commands: Option<mpsc::Sender<P2pCommand>>,
    gateway_policy: GatewayPolicyConfig,
}

fn build_app(state: RouterState) -> Router {
    let gateway = GatewayService::with_policy(state.registry.clone(), state.gateway_policy);
    let state = AppState {
        registry: state.registry,
        gateway,
        p2p_commands: state.p2p_commands,
    };
    Router::new()
        .route("/health", get(health))
        .route("/v1/providers", get(list_providers))
        .route("/v1/providers/register", post(register_provider))
        .route(
            "/v1/providers/ownership-challenges",
            post(create_provider_ownership_challenge),
        )
        .route("/v1/providers/:provider_id", get(get_provider))
        .route(
            "/v1/providers/ownership-challenges/:challenge_id",
            get(get_provider_ownership_challenge),
        )
        .route("/v1/providers/:provider_id/revoke", post(revoke_provider))
        .route(
            "/v1/providers/:provider_id/rotate-key",
            post(rotate_provider_key),
        )
        .route("/v1/agents", get(list_agents))
        .route("/v1/agents/:agent_id", get(get_agent))
        .route("/v1/agents/:agent_id/unpublish", post(unpublish_agent))
        .route("/v1/agents/:agent_id/invoke", post(invoke_agent))
        .route(
            "/v1/agents/:agent_id/invoke-async",
            post(invoke_agent_async),
        )
        .route(
            "/v1/agents/:agent_id/tasks/:task_id/get",
            post(get_agent_task),
        )
        .route("/v1/agent-submissions", get(list_agent_submissions))
        .route("/v1/agent-submissions", post(submit_agent))
        .route(
            "/v1/agent-submissions/:submission_id",
            get(get_agent_submission),
        )
        .route(
            "/v1/admin/agent-submissions/:submission_id/approve",
            post(approve_agent_submission),
        )
        .route(
            "/v1/admin/agent-submissions/:submission_id/reject",
            post(reject_agent_submission),
        )
        .route("/v1/receipts", get(list_receipts))
        .route("/v1/receipts/:receipt_id", get(get_receipt))
        .route("/v1/receipts/:receipt_id/verify", post(verify_receipt))
        .route(
            "/v1/receipts/:receipt_id/verifications",
            get(list_receipt_verifications),
        )
        .route("/v1/verifier/run", post(run_verifier_sweep))
        .route("/v1/health/providers", get(list_provider_health))
        .route("/v1/health/agents", get(list_agent_health))
        .route("/v1/trust/providers", get(list_provider_trust))
        .route("/v1/trust/agents", get(list_agent_trust))
        .route("/v1/auth-contexts", get(list_auth_contexts))
        .route("/v1/auth-contexts/register", post(register_auth_context))
        .route(
            "/v1/admin/providers/:provider_id/block",
            post(block_provider),
        )
        .route(
            "/v1/admin/providers/:provider_id/unblock",
            post(unblock_provider),
        )
        .route(
            "/v1/admin/providers/:provider_id/audit",
            get(list_provider_audit),
        )
        .route("/v1/admin/agents/:agent_id/block", post(block_agent))
        .route("/v1/admin/agents/:agent_id/unblock", post(unblock_agent))
        .route("/v1/admin/moderation/cases", get(list_moderation_cases))
        .route("/v1/admin/moderation/cases", post(create_moderation_case))
        .route(
            "/v1/admin/moderation/cases/:case_id/resolve",
            post(resolve_moderation_case),
        )
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "watt-servicenet-node"
    }))
}

async fn register_provider(
    State(state): State<AppState>,
    Json(request): Json<RegisterProviderRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let provider = state
        .registry
        .register_provider(request)
        .await
        .map_err(AppError::from)?;
    if let Some(sender) = &state.p2p_commands {
        let _ = sender.try_send(P2pCommand::PublishProvider(Box::new(provider.clone())));
    }
    Ok((StatusCode::CREATED, Json(serde_json::json!(provider))))
}

async fn create_provider_ownership_challenge(
    State(state): State<AppState>,
    Json(request): Json<CreateProviderOwnershipChallengeRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let challenge = state
        .registry
        .create_provider_ownership_challenge(request)
        .await
        .map_err(AppError::from)?;
    Ok((StatusCode::CREATED, Json(serde_json::json!(challenge))))
}

async fn list_providers(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let providers = state
        .registry
        .list_providers()
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!({ "items": providers })))
}

async fn get_provider(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let provider = state
        .registry
        .get_provider(&provider_id)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!(provider)))
}

async fn get_provider_ownership_challenge(
    State(state): State<AppState>,
    Path(challenge_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let challenge = state
        .registry
        .get_provider_ownership_challenge(challenge_id)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!(challenge)))
}

async fn rotate_provider_key(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
    Json(request): Json<RotateProviderKeyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let provider = state
        .registry
        .rotate_provider_key(&provider_id, request)
        .await
        .map_err(AppError::from)?;
    if let Some(sender) = &state.p2p_commands {
        let _ = sender.try_send(P2pCommand::PublishProvider(Box::new(provider.clone())));
    }
    Ok(Json(serde_json::json!(provider)))
}

async fn revoke_provider(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
    Json(request): Json<RevokeProviderRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let provider = state
        .registry
        .revoke_provider(&provider_id, request)
        .await
        .map_err(AppError::from)?;
    if let Some(sender) = &state.p2p_commands {
        let _ = sender.try_send(P2pCommand::PublishProvider(Box::new(provider.clone())));
    }
    Ok(Json(serde_json::json!(provider)))
}

async fn list_agents(
    State(state): State<AppState>,
    Query(query): Query<AgentListQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let limit = query
        .limit
        .unwrap_or(DEFAULT_AGENT_LIST_LIMIT)
        .clamp(1, MAX_AGENT_LIST_LIMIT);
    let offset = query.offset.unwrap_or(0);
    let (items, known_count) = state
        .registry
        .list_published_agents_page(limit, offset)
        .await
        .map_err(AppError::from)?;
    let next_offset = offset.saturating_add(items.len());
    let has_more = next_offset < known_count;
    let public_items = items
        .iter()
        .map(public_published_agent_view)
        .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({
        "items": public_items,
        "count": items.len(),
        "limit": limit,
        "offset": offset,
        "next_offset": if has_more { Some(next_offset) } else { None },
        "has_more": has_more,
        "known_count": known_count,
    })))
}

async fn get_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let agent = state
        .registry
        .get_published_agent(&agent_id)
        .await
        .map_err(AppError::from)?;
    Ok(Json(public_published_agent_view(&agent)))
}

fn public_published_agent_view(agent: &PublishedAgentRecord) -> serde_json::Value {
    let mut view = serde_json::to_value(agent).unwrap_or(serde_json::Value::Null);
    if let Some(object) = view.as_object_mut() {
        if let Some(agent_card) = object
            .get_mut("agent_card")
            .and_then(serde_json::Value::as_object_mut)
        {
            agent_card.remove("url");
        }
        if let Some(endpoint) = object
            .get_mut("deployment")
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|deployment| deployment.get_mut("endpoint"))
            .and_then(serde_json::Value::as_object_mut)
        {
            endpoint.remove("url");
        }
        object.insert(
            "invoke".to_owned(),
            serde_json::json!({
                "transport": "servicenet",
                "sync_url": format!("/v1/agents/{}/invoke", agent.agent_id),
                "async_url": format!("/v1/agents/{}/invoke-async", agent.agent_id),
            }),
        );
        object.insert(
            "address".to_owned(),
            serde_json::json!(format!(
                "wattetheria://{PUBLIC_SERVICENET_NETWORK_ID}/service/{}",
                agent.agent_id
            )),
        );
        if let Some(service_address) = agent.service_address.as_deref() {
            object.insert(
                "alsoKnownAs".to_owned(),
                serde_json::json!([service_address]),
            );
        }
    }
    view
}

async fn unpublish_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(request): Json<UnpublishAgentRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let agent = state
        .registry
        .unpublish_agent(&agent_id, request)
        .await
        .map_err(AppError::from)?;
    queue_published_agent(&state.p2p_commands, agent.clone());
    Ok(Json(serde_json::json!(agent)))
}

async fn submit_agent(
    State(state): State<AppState>,
    Json(request): Json<SubmitAgentRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let record = state
        .registry
        .submit_agent(request)
        .await
        .map_err(AppError::from)?;
    publish_auto_approved_agent(&state, &record.agent_id, &record.status).await?;
    Ok((StatusCode::CREATED, Json(serde_json::json!(record))))
}

async fn list_agent_submissions(
    State(state): State<AppState>,
    Query(query): Query<AgentSubmissionQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let items = state
        .registry
        .list_agent_submissions(&query)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

async fn get_agent_submission(
    State(state): State<AppState>,
    Path(submission_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let item = state
        .registry
        .get_agent_submission(submission_id)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!(item)))
}

async fn approve_agent_submission(
    State(state): State<AppState>,
    Path(submission_id): Path<Uuid>,
    Json(request): Json<ApproveAgentSubmissionRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let item = state
        .registry
        .approve_agent_submission(submission_id, request)
        .await
        .map_err(AppError::from)?;
    queue_published_agent(&state.p2p_commands, item.clone());
    Ok(Json(serde_json::json!(item)))
}

async fn reject_agent_submission(
    State(state): State<AppState>,
    Path(submission_id): Path<Uuid>,
    Json(request): Json<RejectAgentSubmissionRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let item = state
        .registry
        .reject_agent_submission(submission_id, request)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!(item)))
}

async fn invoke_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(request): Json<InvokeAgentRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let response = state
        .gateway
        .invoke_agent(&agent_id, request)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!(response)))
}

async fn invoke_agent_async(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(request): Json<InvokeAgentRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let response = state
        .gateway
        .invoke_agent_async(&agent_id, request)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!(response)))
}

async fn get_agent_task(
    State(state): State<AppState>,
    Path((agent_id, task_id)): Path<(String, String)>,
    Json(request): Json<GetAgentTaskRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let response = state
        .gateway
        .get_agent_task(&agent_id, &task_id, request)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!(response)))
}

async fn list_receipts(
    State(state): State<AppState>,
    Query(query): Query<ReceiptQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let receipts = state
        .registry
        .list_receipts(&query)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!({ "items": receipts })))
}

async fn get_receipt(
    State(state): State<AppState>,
    Path(receipt_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let receipt = state
        .registry
        .get_receipt(receipt_id)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!(receipt)))
}

async fn verify_receipt(
    State(state): State<AppState>,
    Path(receipt_id): Path<Uuid>,
    Json(request): Json<VerifyReceiptRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let receipt = state
        .registry
        .verify_receipt(receipt_id, request)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!(receipt)))
}

async fn list_receipt_verifications(
    State(state): State<AppState>,
    Path(receipt_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let items = state
        .registry
        .list_verifications(receipt_id)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

async fn run_verifier_sweep(
    State(state): State<AppState>,
    Json(request): Json<RunVerifierSweepRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let items = state
        .registry
        .run_verifier_sweep(request)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

async fn list_provider_health(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let items = state
        .registry
        .list_provider_health()
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

async fn list_agent_health(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let items = state
        .registry
        .list_agent_health()
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

async fn list_provider_trust(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let items = state
        .registry
        .list_provider_trust()
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

async fn list_agent_trust(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let items = state
        .registry
        .list_agent_trust()
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

async fn register_auth_context(
    State(state): State<AppState>,
    Json(request): Json<RegisterAuthContextRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let record = state
        .registry
        .register_auth_context(request)
        .await
        .map_err(AppError::from)?;
    Ok((StatusCode::CREATED, Json(serde_json::json!(record))))
}

async fn list_auth_contexts(
    State(state): State<AppState>,
    Query(query): Query<AuthContextQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let items = state
        .registry
        .list_auth_contexts(&query)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

async fn block_provider(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
    Json(request): Json<BlockEntityRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let trust = state
        .registry
        .block_provider(&provider_id, request)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!(trust)))
}

async fn unblock_provider(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let trust = state
        .registry
        .unblock_provider(&provider_id)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!(trust)))
}

async fn list_provider_audit(
    State(state): State<AppState>,
    Path(provider_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let items = state
        .registry
        .list_provider_audit_events(&provider_id)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

async fn block_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(request): Json<BlockEntityRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let trust = state
        .registry
        .block_agent(&agent_id, request)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!(trust)))
}

async fn unblock_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let trust = state
        .registry
        .unblock_agent(&agent_id)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!(trust)))
}

async fn create_moderation_case(
    State(state): State<AppState>,
    Json(request): Json<CreateModerationCaseRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let case = state
        .registry
        .create_moderation_case(request)
        .await
        .map_err(AppError::from)?;
    Ok((StatusCode::CREATED, Json(serde_json::json!(case))))
}

async fn list_moderation_cases(
    State(state): State<AppState>,
    Query(query): Query<ModerationCaseQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let items = state
        .registry
        .list_moderation_cases(&query)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

async fn resolve_moderation_case(
    State(state): State<AppState>,
    Path(case_id): Path<Uuid>,
    Json(request): Json<ResolveModerationCaseRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let case = state
        .registry
        .resolve_moderation_case(case_id, request)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!(case)))
}

enum AppError {
    Registry(RegistryError),
    Gateway(GatewayError),
}

#[derive(Debug)]
enum P2pCommand {
    PublishProvider(Box<watt_servicenet_protocol::ProviderRecord>),
    PublishAgent(Box<watt_servicenet_protocol::PublishedAgentRecord>),
}

async fn publish_auto_approved_agent(
    state: &AppState,
    agent_id: &str,
    status: &AgentSubmissionStatus,
) -> Result<(), AppError> {
    if status != &AgentSubmissionStatus::Approved || state.p2p_commands.is_none() {
        return Ok(());
    }
    let record = state
        .registry
        .get_published_agent(agent_id)
        .await
        .map_err(AppError::from)?;
    queue_published_agent(&state.p2p_commands, record);
    Ok(())
}

fn queue_published_agent(
    p2p_commands: &Option<mpsc::Sender<P2pCommand>>,
    record: PublishedAgentRecord,
) {
    if let Some(sender) = p2p_commands {
        let _ = sender.try_send(P2pCommand::PublishAgent(Box::new(record)));
    }
}

async fn start_p2p_sync_if_enabled(
    registry: Arc<ServiceRegistry>,
) -> anyhow::Result<Option<mpsc::Sender<P2pCommand>>> {
    let enabled = matches!(
        std::env::var("SERVICENET_P2P_ENABLED").ok().as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES")
    );
    if !enabled {
        return Ok(None);
    }

    let mut config = ServiceNetworkP2pConfig {
        state_dir: std::env::var("SERVICENET_P2P_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_p2p_state_dir()),
        ..ServiceNetworkP2pConfig::default()
    };
    if let Ok(listen_addrs) = std::env::var("SERVICENET_P2P_LISTEN_ADDRS") {
        config.listen_addrs = split_csv(&listen_addrs);
    }
    if let Ok(bootstrap_peers) = std::env::var("SERVICENET_P2P_BOOTSTRAP_PEERS") {
        config.bootstrap_peers = split_csv(&bootstrap_peers);
    }
    if let Ok(network_id) = std::env::var("SERVICENET_P2P_NETWORK_ID") {
        config.namespace.network_id = network_id;
    }
    config.validate()?;
    let federation_policy = FederationTrustPolicy::from_env();

    let mut runtime = ServiceNetworkRuntime::new(ServiceNetworkNode::generate(config)?)?;
    runtime.subscribe_global()?;
    let (tx, mut rx) = mpsc::channel::<P2pCommand>(128);
    let anti_entropy_interval = p2p_anti_entropy_interval();

    tokio::spawn(async move {
        let mut connected_peers = BTreeMap::<String, NetworkNodeId>::new();
        let mut next_anti_entropy_at = Instant::now() + anti_entropy_interval;

        loop {
            while let Ok(command) = rx.try_recv() {
                if let Err(err) = handle_p2p_command(&mut runtime, command) {
                    eprintln!("servicenet p2p command failed: {err}");
                }
            }

            if Instant::now() >= next_anti_entropy_at {
                if connected_peers.is_empty() {
                    next_anti_entropy_at = Instant::now() + anti_entropy_interval;
                    continue;
                }
                if let Err(err) = publish_local_sync_manifest(&registry, &mut runtime).await {
                    eprintln!("servicenet p2p anti-entropy publish failed: {err}");
                }
                next_anti_entropy_at = Instant::now() + anti_entropy_interval;
            }

            let poll_timeout = next_anti_entropy_at
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(250));
            match timeout(poll_timeout, runtime.next_event()).await {
                Ok(Ok(event)) => {
                    if let Err(err) = handle_p2p_event(
                        &registry,
                        &federation_policy,
                        &mut runtime,
                        &mut connected_peers,
                        event,
                    )
                    .await
                    {
                        eprintln!("servicenet p2p event handling failed: {err}");
                    }
                }
                Ok(Err(err)) => {
                    eprintln!("servicenet p2p runtime error: {err}");
                }
                Err(_) => {}
            }
        }
    });

    Ok(Some(tx))
}

fn p2p_anti_entropy_interval() -> Duration {
    let seconds = std::env::var(SERVICENET_P2P_ANTI_ENTROPY_INTERVAL_SECS_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_P2P_ANTI_ENTROPY_INTERVAL_SECS)
        .max(1);
    Duration::from_secs(seconds)
}

fn default_p2p_state_dir() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".servicenet-p2p-state")
}

fn handle_p2p_command(
    runtime: &mut ServiceNetworkRuntime,
    command: P2pCommand,
) -> anyhow::Result<()> {
    match command {
        P2pCommand::PublishProvider(provider) => runtime.publish_provider(&provider),
        P2pCommand::PublishAgent(record) => runtime.publish_published_agent_record(&record),
    }
}

async fn handle_p2p_event(
    registry: &ServiceRegistry,
    federation_policy: &FederationTrustPolicy,
    runtime: &mut ServiceNetworkRuntime,
    connected_peers: &mut BTreeMap<String, NetworkNodeId>,
    event: ServiceNetworkRuntimeEvent,
) -> anyhow::Result<()> {
    match event {
        ServiceNetworkRuntimeEvent::NewListenAddr { address } => {
            println!("servicenet p2p listening on {address}");
        }
        ServiceNetworkRuntimeEvent::ConnectionEstablished { peer } => {
            connected_peers.insert(peer.to_string(), peer.clone());
            if federation_policy.allows_peer(&peer) {
                request_full_sync_from_peer(runtime, &peer)?;
            }
        }
        ServiceNetworkRuntimeEvent::ProviderPublished { peer, provider } => {
            if federation_policy.allows_peer(&peer) {
                merge_provider_record(registry, provider).await?;
            }
        }
        ServiceNetworkRuntimeEvent::PublishedAgentRecordPublished { peer, record } => {
            if federation_policy.allows_peer(&peer)
                && let Err(err) = merge_published_agent_record(registry, record).await
            {
                if matches!(
                    err.downcast_ref::<RegistryError>(),
                    Some(RegistryError::ProviderNotFound(_))
                ) && runtime.allows_outbound_backfill_to(&peer)
                {
                    let _ = runtime.send_provider_sync_request(&peer, P2P_BACKFILL_PAGE_SIZE);
                }
                return Err(err);
            }
        }
        ServiceNetworkRuntimeEvent::ProviderSyncRequest {
            peer,
            from_event_seq,
            limit,
            channel,
        } => {
            if federation_policy.allows_peer(&peer) {
                let providers = registry
                    .list_providers()
                    .await?
                    .into_iter()
                    .skip(backfill_offset(from_event_seq))
                    .take(limit)
                    .collect::<Vec<_>>();
                runtime.send_provider_sync_response_from(channel, from_event_seq, &providers)?;
            }
        }
        ServiceNetworkRuntimeEvent::ProviderSyncResponse {
            peer,
            request_id: _,
            next_from_event_seq,
            providers,
        } => {
            if federation_policy.allows_peer(&peer) {
                let should_continue = providers.len() >= P2P_BACKFILL_PAGE_SIZE;
                for provider in providers {
                    merge_provider_record(registry, provider).await?;
                }
                if should_continue && runtime.allows_outbound_backfill_to(&peer) {
                    let _ = runtime.send_provider_sync_request_from(
                        &peer,
                        next_from_event_seq,
                        P2P_BACKFILL_PAGE_SIZE,
                    );
                }
            }
        }
        ServiceNetworkRuntimeEvent::PublishedAgentSyncRequest {
            peer,
            from_event_seq,
            limit,
            channel,
        } => {
            if federation_policy.allows_peer(&peer) {
                let records = registry
                    .list_published_agents()
                    .await?
                    .into_iter()
                    .skip(backfill_offset(from_event_seq))
                    .take(limit)
                    .collect::<Vec<_>>();
                runtime.send_published_agent_sync_response_from(
                    channel,
                    from_event_seq,
                    &records,
                )?;
            }
        }
        ServiceNetworkRuntimeEvent::PublishedAgentSyncResponse {
            peer,
            request_id: _,
            next_from_event_seq,
            records,
        } => {
            if federation_policy.allows_peer(&peer) {
                let should_continue = records.len() >= P2P_BACKFILL_PAGE_SIZE;
                for record in records {
                    merge_published_agent_record(registry, record).await?;
                }
                if should_continue && runtime.allows_outbound_backfill_to(&peer) {
                    let _ = runtime.send_published_agent_sync_request_from(
                        &peer,
                        next_from_event_seq,
                        P2P_BACKFILL_PAGE_SIZE,
                    );
                }
            }
        }
        ServiceNetworkRuntimeEvent::SyncManifestPublished { peer, manifest } => {
            connected_peers.insert(peer.to_string(), peer.clone());
            if federation_policy.allows_peer(&peer) && runtime.allows_outbound_backfill_to(&peer) {
                request_backfill_for_manifest_gaps(registry, runtime, &peer, &manifest).await?;
            }
        }
    }
    Ok(())
}

fn backfill_offset(from_event_seq: u64) -> usize {
    usize::try_from(from_event_seq).unwrap_or(usize::MAX)
}

fn request_full_sync_from_peer(
    runtime: &mut ServiceNetworkRuntime,
    peer: &NetworkNodeId,
) -> anyhow::Result<()> {
    if runtime.allows_outbound_backfill_to(peer) {
        let _ = runtime.send_provider_sync_request(peer, P2P_BACKFILL_PAGE_SIZE)?;
        let _ = runtime.send_published_agent_sync_request(peer, P2P_BACKFILL_PAGE_SIZE)?;
    }
    Ok(())
}

async fn publish_local_sync_manifest(
    registry: &ServiceRegistry,
    runtime: &mut ServiceNetworkRuntime,
) -> anyhow::Result<()> {
    let providers = registry.list_providers().await?;
    let records = registry.list_published_agents().await?;
    let manifest = runtime.build_sync_manifest(&providers, &records)?;
    runtime.publish_sync_manifest(&manifest)?;
    Ok(())
}

async fn request_backfill_for_manifest_gaps(
    registry: &ServiceRegistry,
    runtime: &mut ServiceNetworkRuntime,
    peer: &NetworkNodeId,
    manifest: &ServiceNetworkSyncManifest,
) -> anyhow::Result<()> {
    if provider_manifest_has_remote_winner(registry, manifest).await? {
        let _ = runtime.send_provider_sync_request(peer, P2P_BACKFILL_PAGE_SIZE)?;
    }
    if published_agent_manifest_has_remote_winner(registry, manifest).await? {
        let _ = runtime.send_published_agent_sync_request(peer, P2P_BACKFILL_PAGE_SIZE)?;
    }
    Ok(())
}

async fn provider_manifest_has_remote_winner(
    registry: &ServiceRegistry,
    manifest: &ServiceNetworkSyncManifest,
) -> anyhow::Result<bool> {
    let mut local = BTreeMap::new();
    for provider in registry.list_providers().await? {
        let summary = provider_record_summary(&provider)?;
        local.insert(summary.record_id.clone(), summary);
    }
    Ok(manifest
        .providers
        .iter()
        .any(|remote| summary_wins(local.get(&remote.record_id), remote, SummaryKind::Provider)))
}

async fn published_agent_manifest_has_remote_winner(
    registry: &ServiceRegistry,
    manifest: &ServiceNetworkSyncManifest,
) -> anyhow::Result<bool> {
    let mut local = BTreeMap::new();
    for record in registry.list_published_agents().await? {
        let summary = published_agent_record_summary(&record)?;
        local.insert(summary.record_id.clone(), summary);
    }
    Ok(manifest.published_agents.iter().any(|remote| {
        summary_wins(
            local.get(&remote.record_id),
            remote,
            SummaryKind::PublishedAgent,
        )
    }))
}

async fn merge_provider_record(
    registry: &ServiceRegistry,
    incoming: ProviderRecord,
) -> anyhow::Result<bool> {
    let should_merge = match registry.get_provider(&incoming.provider_id).await {
        Ok(local) => provider_record_wins(&local, &incoming)?,
        Err(RegistryError::ProviderNotFound(_)) => true,
        Err(err) => return Err(err.into()),
    };
    if should_merge {
        registry.upsert_provider_record(incoming).await?;
    }
    Ok(should_merge)
}

async fn merge_published_agent_record(
    registry: &ServiceRegistry,
    incoming: PublishedAgentRecord,
) -> anyhow::Result<bool> {
    let local = registry
        .list_published_agents()
        .await?
        .into_iter()
        .find(|record| record.agent_id == incoming.agent_id);
    let should_merge = match local {
        Some(local) => published_agent_record_wins(&local, &incoming)?,
        None => true,
    };
    if should_merge {
        registry.upsert_published_agent(incoming).await?;
    }
    Ok(should_merge)
}

fn provider_record_wins(local: &ProviderRecord, incoming: &ProviderRecord) -> anyhow::Result<bool> {
    let local_summary = provider_record_summary(local)?;
    let incoming_summary = provider_record_summary(incoming)?;
    Ok(summary_wins(
        Some(&local_summary),
        &incoming_summary,
        SummaryKind::Provider,
    ))
}

fn published_agent_record_wins(
    local: &PublishedAgentRecord,
    incoming: &PublishedAgentRecord,
) -> anyhow::Result<bool> {
    let local_summary = published_agent_record_summary(local)?;
    let incoming_summary = published_agent_record_summary(incoming)?;
    Ok(summary_wins(
        Some(&local_summary),
        &incoming_summary,
        SummaryKind::PublishedAgent,
    ))
}

#[derive(Clone, Copy)]
enum SummaryKind {
    Provider,
    PublishedAgent,
}

fn summary_wins(
    local: Option<&ServiceNetworkRecordSummary>,
    remote: &ServiceNetworkRecordSummary,
    kind: SummaryKind,
) -> bool {
    let Some(local) = local else {
        return true;
    };
    if local.digest == remote.digest {
        return false;
    }
    let local_rank = status_rank(kind, &local.status);
    let remote_rank = status_rank(kind, &remote.status);
    if matches!(kind, SummaryKind::Provider) && local_rank != remote_rank {
        return remote_rank > local_rank;
    }
    if local.version_ms != remote.version_ms {
        return remote.version_ms > local.version_ms;
    }
    if local_rank != remote_rank {
        return remote_rank > local_rank;
    }
    remote.digest > local.digest
}

fn status_rank(kind: SummaryKind, status: &str) -> u8 {
    match kind {
        SummaryKind::Provider => match status {
            "revoked" => 2,
            "active" => 1,
            _ => 0,
        },
        SummaryKind::PublishedAgent => match status {
            "revoked" => 3,
            "suspended" => 2,
            "approved" => 1,
            _ => 0,
        },
    }
}

fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_env_flag(value: Option<&str>) -> bool {
    matches!(value, Some("1" | "true" | "TRUE" | "yes" | "YES"))
}

impl From<RegistryError> for AppError {
    fn from(value: RegistryError) -> Self {
        Self::Registry(value)
    }
}

impl From<GatewayError> for AppError {
    fn from(value: GatewayError) -> Self {
        Self::Gateway(value)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, body) = match self {
            Self::Registry(RegistryError::ProviderAlreadyExists(message)) => (
                StatusCode::CONFLICT,
                serde_json::json!({ "error": message }),
            ),
            Self::Registry(RegistryError::ProviderNotFound(message)) => (
                StatusCode::NOT_FOUND,
                serde_json::json!({ "error": message }),
            ),
            Self::Registry(RegistryError::ReceiptNotFound(receipt_id)) => (
                StatusCode::NOT_FOUND,
                serde_json::json!({ "error": format!("receipt `{receipt_id}` not found") }),
            ),
            Self::Registry(RegistryError::AuthContextNotFound(auth_context_id)) => (
                StatusCode::NOT_FOUND,
                serde_json::json!({ "error": format!("auth context `{auth_context_id}` not found") }),
            ),
            Self::Registry(RegistryError::OwnershipChallengeNotFound(challenge_id)) => (
                StatusCode::NOT_FOUND,
                serde_json::json!({ "error": format!("provider ownership challenge `{challenge_id}` not found") }),
            ),
            Self::Registry(RegistryError::ModerationCaseNotFound(case_id)) => (
                StatusCode::NOT_FOUND,
                serde_json::json!({ "error": format!("moderation case `{case_id}` not found") }),
            ),
            Self::Registry(RegistryError::AgentSubmissionNotFound(submission_id)) => (
                StatusCode::NOT_FOUND,
                serde_json::json!({ "error": format!("agent submission `{submission_id}` not found") }),
            ),
            Self::Registry(RegistryError::PublishedAgentNotFound(agent_id)) => (
                StatusCode::NOT_FOUND,
                serde_json::json!({ "error": format!("published agent `{agent_id}` not found") }),
            ),
            Self::Registry(RegistryError::ProviderRevoked(message))
            | Self::Registry(RegistryError::ProviderBlocked(message))
            | Self::Registry(RegistryError::AgentBlocked(message)) => (
                StatusCode::FORBIDDEN,
                serde_json::json!({ "error": message }),
            ),
            Self::Registry(RegistryError::InvalidProvider(message))
            | Self::Registry(RegistryError::InvalidAgent(message))
            | Self::Registry(RegistryError::InvalidAuthContext(message))
            | Self::Registry(RegistryError::InvalidVerification(message))
            | Self::Registry(RegistryError::InvalidOwnershipChallenge(message)) => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({ "error": message }),
            ),
            Self::Registry(RegistryError::UnsupportedSchemaVersion { entity, version }) => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({ "error": format!("unsupported schema version for {entity}: {version}") }),
            ),
            Self::Registry(RegistryError::Storage(message)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": message }),
            ),
            Self::Gateway(GatewayError::NotFound(message)) => (
                StatusCode::NOT_FOUND,
                serde_json::json!({ "error": message }),
            ),
            Self::Gateway(GatewayError::Rejected(message)) => (
                StatusCode::FORBIDDEN,
                serde_json::json!({ "error": message }),
            ),
            Self::Gateway(GatewayError::Execution(message)) => (
                StatusCode::BAD_GATEWAY,
                serde_json::json!({ "error": message }),
            ),
        };
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AppState, FederationTrustMode, FederationTrustPolicy, P2pCommand,
        ServiceNetworkSyncManifest, SummaryKind, backfill_offset, parse_env_flag,
        provider_manifest_has_remote_winner, provider_record_wins, public_published_agent_view,
        publish_auto_approved_agent, published_agent_record_wins, split_csv, summary_wins,
    };
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use watt_servicenet_gateway::{GatewayPolicyConfig, GatewayService};
    use watt_servicenet_p2p::{
        ServiceNetworkRecordSummary, provider_record_summary, published_agent_record_summary,
    };
    use watt_servicenet_protocol::{
        AgentSubmissionStatus, ProviderRecord, PublishedAgentRecord, RegisterProviderRequest,
    };
    use watt_servicenet_registry::ServiceRegistry;

    #[test]
    fn split_csv_discards_empty_entries() {
        assert_eq!(
            split_csv("a, b, ,c"),
            vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]
        );
    }

    #[test]
    fn parse_env_flag_parses_common_truthy_values() {
        assert!(parse_env_flag(Some("true")));
        assert!(parse_env_flag(Some("YES")));
        assert!(!parse_env_flag(Some("0")));
        assert!(!parse_env_flag(None));
    }

    #[test]
    fn open_federation_policy_allows_any_peer() {
        let policy = FederationTrustPolicy {
            mode: FederationTrustMode::Open,
            trusted_peers: BTreeSet::new(),
        };
        assert!(policy.allows_peer(&"peer-a"));
        assert!(policy.allows_peer(&"peer-b"));
    }

    #[test]
    fn trusted_federation_policy_only_allows_configured_peers() {
        let policy = FederationTrustPolicy {
            mode: FederationTrustMode::Trusted,
            trusted_peers: BTreeSet::from(["peer-a".to_owned()]),
        };
        assert!(policy.allows_peer(&"peer-a"));
        assert!(!policy.allows_peer(&"peer-b"));
    }

    #[tokio::test]
    async fn auto_approved_submission_queues_published_agent_for_p2p() {
        let registry = Arc::new(ServiceRegistry::in_memory());
        registry
            .register_provider(RegisterProviderRequest {
                provider_id: "provider-local".to_owned(),
                provider_did: "did:key:z6MkpTHR8VNsBxYAAWHut2GeaddA1bbm8CLcfJ4pKzvmWwLp".to_owned(),
                display_name: Some("Provider Local".to_owned()),
                ownership_challenge_id: None,
                ownership_signature: None,
            })
            .await
            .expect("provider should register");
        let published: PublishedAgentRecord = serde_json::from_value(serde_json::json!({
            "agent_id": "agent-auto-approved",
            "provider_id": "provider-local",
            "version": "0.1.0",
            "status": "approved",
            "agent_card": {
                "name": "Auto Approved Agent",
                "description": "Test agent",
                "url": "https://agent.example.com",
                "preferredTransport": "JSONRPC",
                "protocolVersion": "1.0",
                "supportsTask": false,
                "skills": [{ "id": "demo.run", "name": "Run Demo" }],
                "securitySchemes": { "none": { "type": "none" } },
                "security": [{ "none": [] }]
            },
            "deployment": {
                "runtime": "remote_http",
                "endpoint": {
                    "url": "https://agent.example.com/a2a",
                    "protocol_binding": "JSONRPC",
                    "protocol_version": "1.0",
                    "interaction_protocol": "google_a2a"
                }
            },
            "review": {
                "risk_level": "low",
                "data_classes": [],
                "destructive_actions": [],
                "human_approval_required": false,
                "allowed_regions": []
            },
            "approved_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "reviewed_by": "auto-approve",
            "review_notes": "auto-approved for test"
        }))
        .expect("published agent fixture should parse");
        registry
            .upsert_published_agent(published)
            .await
            .expect("published agent should persist");
        let (tx, mut rx) = mpsc::channel(1);
        let state = AppState {
            registry,
            gateway: GatewayService::with_policy(
                Arc::new(ServiceRegistry::in_memory()),
                GatewayPolicyConfig::default(),
            ),
            p2p_commands: Some(tx),
        };

        assert!(
            publish_auto_approved_agent(
                &state,
                "agent-auto-approved",
                &AgentSubmissionStatus::Approved,
            )
            .await
            .is_ok()
        );

        let command = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("p2p command should be queued")
            .expect("p2p channel should contain command");
        match command {
            P2pCommand::PublishAgent(record) => {
                assert_eq!(record.agent_id, "agent-auto-approved");
                assert_eq!(record.provider_id, "provider-local");
            }
            P2pCommand::PublishProvider(_) => panic!("expected published agent command"),
        }
    }

    #[test]
    fn provider_revocation_wins_over_active_record() {
        let active = provider_fixture(
            "active",
            "did:key:z6MkpTHR8VNsBxYAAWHut2GeaddA1bbm8CLcfJ4pKzvmWwLp",
            None,
        );
        let revoked = provider_fixture(
            "revoked",
            "did:key:z6MkpTHR8VNsBxYAAWHut2GeaddA1bbm8CLcfJ4pKzvmWwLp",
            Some("2026-01-02T00:00:00Z"),
        );

        assert!(provider_record_wins(&active, &revoked).expect("compare provider records"));
        assert!(!provider_record_wins(&revoked, &active).expect("compare provider records"));
    }

    #[test]
    fn published_agent_newer_record_wins_old_record_does_not() {
        let older = published_agent_fixture("approved", "2026-01-01T00:00:00Z", "older");
        let newer = published_agent_fixture("approved", "2026-01-02T00:00:00Z", "newer");

        assert!(published_agent_record_wins(&older, &newer).expect("compare agent records"));
        assert!(!published_agent_record_wins(&newer, &older).expect("compare agent records"));
    }

    #[test]
    fn same_version_summary_uses_digest_tie_break() {
        let local = ServiceNetworkRecordSummary {
            record_id: "provider-local".to_owned(),
            status: "active".to_owned(),
            version_ms: 1,
            digest: "sha256:aaa".to_owned(),
        };
        let remote = ServiceNetworkRecordSummary {
            record_id: "provider-local".to_owned(),
            status: "active".to_owned(),
            version_ms: 1,
            digest: "sha256:bbb".to_owned(),
        };

        assert!(summary_wins(Some(&local), &remote, SummaryKind::Provider));
        assert!(!summary_wins(Some(&remote), &local, SummaryKind::Provider));
    }

    #[test]
    fn backfill_offset_saturates_unrepresentable_values() {
        assert_eq!(backfill_offset(7), 7);
        assert_eq!(backfill_offset(u64::MAX), usize::MAX);
    }

    #[tokio::test]
    async fn provider_manifest_gap_detection_ignores_remote_loser() {
        let registry = ServiceRegistry::in_memory();
        let local_revoked = provider_fixture(
            "revoked",
            "did:key:z6MkpTHR8VNsBxYAAWHut2GeaddA1bbm8CLcfJ4pKzvmWwLp",
            Some("2026-01-02T00:00:00Z"),
        );
        registry
            .upsert_provider_record(local_revoked)
            .await
            .expect("local provider should persist");
        let remote_active = provider_fixture(
            "active",
            "did:key:z6MkpTHR8VNsBxYAAWHut2GeaddA1bbm8CLcfJ4pKzvmWwLp",
            None,
        );
        let manifest = ServiceNetworkSyncManifest {
            generated_at_ms: 1,
            producer: "peer-a".to_owned(),
            providers: vec![
                provider_record_summary(&remote_active).expect("provider summary should build"),
            ],
            published_agents: Vec::new(),
        };

        assert!(
            !provider_manifest_has_remote_winner(&registry, &manifest)
                .await
                .expect("manifest should compare")
        );
    }

    #[test]
    fn published_agent_summary_digest_changes_with_content() {
        let first = published_agent_fixture("approved", "2026-01-01T00:00:00Z", "first");
        let second = published_agent_fixture("approved", "2026-01-01T00:00:00Z", "second");
        let first_summary =
            published_agent_record_summary(&first).expect("first summary should build");
        let second_summary =
            published_agent_record_summary(&second).expect("second summary should build");

        assert_ne!(first_summary.digest, second_summary.digest);
        assert_eq!(first_summary.version_ms, second_summary.version_ms);
    }

    #[test]
    fn public_published_agent_view_exposes_service_address() {
        let agent = published_agent_fixture("approved", "2026-01-01T00:00:00Z", "first");
        let view = public_published_agent_view(&agent);

        assert_eq!(
            view["service_address"].as_str(),
            Some("agent-auto-approved@wattetheria")
        );
        assert_eq!(
            view["alsoKnownAs"][0].as_str(),
            Some("agent-auto-approved@wattetheria")
        );
    }

    fn provider_fixture(
        status: &str,
        provider_did: &str,
        revoked_at: Option<&str>,
    ) -> ProviderRecord {
        serde_json::from_value(serde_json::json!({
            "provider_id": "provider-local",
            "provider_did": provider_did,
            "display_name": "Provider Local",
            "status": status,
            "registered_at": "2026-01-01T00:00:00Z",
            "revoked_at": revoked_at,
            "revoke_reason": if revoked_at.is_some() { Some("compromised") } else { None::<&str> }
        }))
        .expect("provider fixture should parse")
    }

    fn published_agent_fixture(
        status: &str,
        updated_at: &str,
        review_notes: &str,
    ) -> PublishedAgentRecord {
        serde_json::from_value(serde_json::json!({
            "agent_id": "agent-auto-approved",
            "provider_id": "provider-local",
            "service_address": "agent-auto-approved@wattetheria",
            "version": "0.1.0",
            "status": status,
            "agent_card": {
                "name": "Auto Approved Agent",
                "description": "Test agent",
                "url": "https://agent.example.com",
                "preferredTransport": "JSONRPC",
                "protocolVersion": "1.0",
                "supportsTask": false,
                "skills": [{ "id": "demo.run", "name": "Run Demo" }],
                "securitySchemes": { "none": { "type": "none" } },
                "security": [{ "none": [] }]
            },
            "deployment": {
                "runtime": "remote_http",
                "endpoint": {
                    "url": "https://agent.example.com/a2a",
                    "protocol_binding": "JSONRPC",
                    "protocol_version": "1.0",
                    "interaction_protocol": "google_a2a"
                }
            },
            "review": {
                "risk_level": "low",
                "data_classes": [],
                "destructive_actions": [],
                "human_approval_required": false,
                "allowed_regions": []
            },
            "approved_at": "2026-01-01T00:00:00Z",
            "updated_at": updated_at,
            "reviewed_by": "auto-approve",
            "review_notes": review_notes
        }))
        .expect("published agent fixture should parse")
    }
}
