use axum::body::{self, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use uuid::Uuid;
use watt_servicenet_node::build_local_app;
use watt_servicenet_registry::{ServiceRegistry, ServiceRegistryConfig};

fn database_url() -> Option<String> {
    std::env::var("SERVICENET_TEST_DATABASE_URL").ok()
}

fn schema_name(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4().simple())
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should read");
    serde_json::from_slice(&body).expect("json should parse")
}

#[tokio::test]
async fn postgres_http_flow_persists_published_agents() {
    let Some(database_url) = database_url() else {
        eprintln!(
            "skipping postgres HTTP integration test; SERVICENET_TEST_DATABASE_URL is not set"
        );
        return;
    };
    let schema = schema_name("node_http");
    let registry = ServiceRegistry::postgres_with_config(
        &database_url,
        &schema,
        ServiceRegistryConfig::default(),
    )
    .await
    .expect("postgres registry should initialize");
    let app = build_local_app(std::sync::Arc::new(registry));

    let register_provider = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/providers/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "provider_id": "provider-pg-http",
                        "provider_public_key": "cHJvdmlkZXItcGctaHR0cC1rZXk=",
                        "display_name": "Provider PG HTTP"
                    })
                    .to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("provider register should succeed");
    assert_eq!(register_provider.status(), StatusCode::CREATED);

    let submit = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/agent-submissions")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "provider_id": "provider-pg-http",
                        "agent_id": "stripe-agent-pg",
                        "version": "0.1.0",
                        "agent_card": {
                            "name": "Stripe Agent PG",
                            "description": "Payments",
                            "url": "https://stripe-agent.example.com",
                            "preferredTransport": "JSONRPC",
                            "protocolVersion": "1.0",
                            "skills": [{ "id": "payments.create_link" }],
                            "securitySchemes": { "oauth2": { "type": "oauth2" } },
                            "security": [{ "oauth2": ["payments:write"] }]
                        },
                        "deployment": {
                            "runtime": "remote_http",
                            "endpoint": {
                                "url": "https://stripe-agent.example.com/a2a",
                                "protocol_binding": "JSONRPC",
                                "protocol_version": "1.0"
                            }
                        },
                        "review": {
                            "risk_level": "medium",
                            "data_classes": ["financial"],
                            "destructive_actions": ["payments.refund"],
                            "human_approval_required": true,
                            "allowed_regions": ["AU"]
                        },
                        "artifacts": {},
                        "attestations": {
                            "provider_signature": "sig"
                        }
                    })
                    .to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("submission should succeed");
    assert_eq!(submit.status(), StatusCode::CREATED);
    let submit_json = response_json(submit).await;
    let submission_id = submit_json["submission_id"]
        .as_str()
        .expect("submission id should exist");

    let approve = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/admin/agent-submissions/{submission_id}/approve"
                ))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "reviewed_by": "moderator-pg"
                    })
                    .to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("approval should succeed");
    assert_eq!(approve.status(), StatusCode::OK);

    let agents = app
        .oneshot(
            Request::builder()
                .uri("/v1/agents")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("agent list should succeed");
    assert_eq!(agents.status(), StatusCode::OK);
    let agents_json = response_json(agents).await;
    assert_eq!(agents_json["items"][0]["agent_id"], "stripe-agent-pg");
}
