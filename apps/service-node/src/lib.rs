use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};
use uuid::Uuid;
use watt_servicenet_gateway::{GatewayError, GatewayPolicyConfig, GatewayService};
use watt_servicenet_p2p::{
    PeerHandshakeMetadata, ServiceNetworkNode, ServiceNetworkP2pConfig, ServiceNetworkRuntime,
    ServiceNetworkRuntimeEvent, encode_servicenet_agent_version,
};
use watt_servicenet_protocol::{
    AgentSubmissionQuery, ApproveAgentSubmissionRequest, AuthContextQuery, BlockEntityRequest,
    CreateModerationCaseRequest, CreateProviderOwnershipChallengeRequest, GetAgentTaskRequest,
    InvokeAgentRequest, ModerationCaseQuery, ReceiptQuery, RegisterAuthContextRequest,
    RegisterProviderRequest, RejectAgentSubmissionRequest, ResolveModerationCaseRequest,
    RevokeProviderRequest, RotateProviderKeyRequest, RunVerifierSweepRequest, SubmitAgentRequest,
    VerifyReceiptRequest,
};
use watt_servicenet_registry::{RegistryError, ServiceRegistry, ServiceRegistryConfig};

#[derive(Clone)]
struct AppState {
    registry: Arc<ServiceRegistry>,
    gateway: GatewayService,
    p2p_commands: Option<mpsc::Sender<P2pCommand>>,
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
        .route("/v1/agents/:agent_id/invoke", post(invoke_agent))
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

async fn list_agents(State(state): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    let items = state
        .registry
        .list_published_agents()
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!({ "items": items })))
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
    if let Some(sender) = &state.p2p_commands {
        let _ = sender.try_send(P2pCommand::PublishAgent(Box::new(item.clone())));
    }
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

    let mut config = ServiceNetworkP2pConfig::default();
    config.state_dir = std::env::var("SERVICENET_P2P_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_p2p_state_dir());
    if let Ok(listen_addrs) = std::env::var("SERVICENET_P2P_LISTEN_ADDRS") {
        config.listen_addrs = split_csv(&listen_addrs);
    }
    if let Ok(bootstrap_peers) = std::env::var("SERVICENET_P2P_BOOTSTRAP_PEERS") {
        config.bootstrap_peers = split_csv(&bootstrap_peers);
    }
    if let Ok(network_id) = std::env::var("SERVICENET_P2P_NETWORK_ID") {
        config.namespace.network_id = network_id.clone();
        config.identify_agent_version = encode_servicenet_agent_version(&PeerHandshakeMetadata {
            network_id,
            params_version: 1,
            params_hash: "servicenet-v1".to_owned(),
        });
    }
    config.validate()?;

    let mut runtime = ServiceNetworkRuntime::new(ServiceNetworkNode::generate(config)?)?;
    runtime.subscribe_global()?;
    let (tx, mut rx) = mpsc::channel::<P2pCommand>(128);

    tokio::spawn(async move {
        loop {
            while let Ok(command) = rx.try_recv() {
                if let Err(err) = handle_p2p_command(&mut runtime, command) {
                    eprintln!("servicenet p2p command failed: {err}");
                }
            }

            match timeout(Duration::from_millis(250), runtime.next_event()).await {
                Ok(Ok(event)) => {
                    if let Err(err) = handle_p2p_event(&registry, &mut runtime, event).await {
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
    runtime: &mut ServiceNetworkRuntime,
    event: ServiceNetworkRuntimeEvent,
) -> anyhow::Result<()> {
    match event {
        ServiceNetworkRuntimeEvent::NewListenAddr { address } => {
            println!("servicenet p2p listening on {address}");
        }
        ServiceNetworkRuntimeEvent::ConnectionEstablished { peer } => {
            if runtime.allows_outbound_backfill_to(&peer) {
                let _ = runtime.send_provider_sync_request(&peer, 256);
                let _ = runtime.send_published_agent_sync_request(&peer, 256);
            }
        }
        ServiceNetworkRuntimeEvent::ProviderPublished { peer: _, provider } => {
            registry.upsert_provider_record(provider).await?;
        }
        ServiceNetworkRuntimeEvent::PublishedAgentRecordPublished { peer: _, record } => {
            registry.upsert_published_agent(record).await?;
        }
        ServiceNetworkRuntimeEvent::ProviderSyncRequest {
            peer: _,
            limit,
            channel,
        } => {
            let providers = registry
                .list_providers()
                .await?
                .into_iter()
                .take(limit)
                .collect::<Vec<_>>();
            runtime.send_provider_sync_response(channel, &providers)?;
        }
        ServiceNetworkRuntimeEvent::ProviderSyncResponse {
            peer: _,
            request_id: _,
            providers,
        } => {
            for provider in providers {
                registry.upsert_provider_record(provider).await?;
            }
        }
        ServiceNetworkRuntimeEvent::PublishedAgentSyncRequest {
            peer: _,
            limit,
            channel,
        } => {
            let records = registry
                .list_published_agents()
                .await?
                .into_iter()
                .take(limit)
                .collect::<Vec<_>>();
            runtime.send_published_agent_sync_response(channel, &records)?;
        }
        ServiceNetworkRuntimeEvent::PublishedAgentSyncResponse {
            peer: _,
            request_id: _,
            records,
        } => {
            for record in records {
                registry.upsert_published_agent(record).await?;
            }
        }
    }
    Ok(())
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
    use super::{parse_env_flag, split_csv};

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
}
