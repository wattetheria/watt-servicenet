use axum::body::{self, Body};
use axum::http::{Request, StatusCode};
use axum::{Json, Router, routing::post};
use std::sync::Arc;
use tower::ServiceExt;
use wattswarm_servicenet_node::build_local_app;
use wattswarm_servicenet_registry::ServiceRegistry;

fn provider_payload() -> serde_json::Value {
    serde_json::json!({
        "provider_id": "provider-local",
        "provider_public_key": "cHJvdmlkZXItbG9jYWwtZGV2a2V5",
        "display_name": "Provider Local"
    })
}

fn valid_agent_submission_payload(url_base: &str, endpoint_url: &str) -> serde_json::Value {
    serde_json::json!({
        "provider_id": "provider-local",
        "agent_id": "stripe-agent",
        "version": "0.1.0",
        "agent_card": {
            "name": "Stripe Agent",
            "description": "Handles Stripe payment flows",
            "url": url_base,
            "preferredTransport": "JSONRPC",
            "protocolVersion": "1.0",
            "skills": [
                {
                    "id": "payments.create_link",
                    "name": "Create Payment Link",
                    "description": "Creates a Stripe payment link"
                }
            ],
            "securitySchemes": {
                "oauth2": { "type": "oauth2" }
            },
            "security": [
                { "oauth2": ["payments:write"] }
            ]
        },
        "deployment": {
            "runtime": "remote_http",
            "endpoint": {
                "url": endpoint_url,
                "protocol_binding": "JSONRPC",
                "protocol_version": "1.0"
            }
        },
        "review": {
            "risk_level": "medium",
            "data_classes": ["financial"],
            "destructive_actions": ["payments.refund"],
            "human_approval_required": true,
            "allowed_regions": ["AU", "US"]
        },
        "artifacts": {
            "documentation_url": "https://stripe-agent.example.com/docs",
            "security_url": "https://stripe-agent.example.com/security"
        },
        "attestations": {
            "provider_signature": "signed-by-provider",
            "source_commit": "abc123",
            "build_digest": "sha256:def456"
        }
    })
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should read");
    serde_json::from_slice(&body).expect("json should parse")
}

async fn start_mock_a2a_server() -> String {
    async fn handle(Json(request): Json<serde_json::Value>) -> Json<serde_json::Value> {
        let method = request["method"].as_str().unwrap_or_default();
        let response = match method {
            "SendMessage" => serde_json::json!({
                "jsonrpc": "2.0",
                "id": request["id"].clone(),
                "result": {
                    "task": {
                        "id": "task-1",
                        "contextId": "ctx-1",
                        "status": {
                            "state": "TASK_STATE_WORKING"
                        }
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
                        "status": {
                            "state": "TASK_STATE_COMPLETED"
                        },
                        "artifacts": [
                            {
                                "artifactId": "artifact-1",
                                "parts": [
                                    {
                                        "data": {
                                            "ok": true,
                                            "provider": "mock-a2a"
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                }
            }),
            _ => serde_json::json!({
                "jsonrpc": "2.0",
                "id": request["id"].clone(),
                "error": {
                    "code": -32601,
                    "message": "Method not found"
                }
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
            .expect("mock a2a server should run");
    });
    format!("http://{addr}/a2a")
}

async fn register_provider_and_approve_agent(
    app: &axum::Router,
    endpoint_url: &str,
    card_url: &str,
) -> String {
    let register_provider = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/providers/register")
                .header("content-type", "application/json")
                .body(Body::from(provider_payload().to_string()))
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
                    valid_agent_submission_payload(card_url, endpoint_url).to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("submission should succeed");
    assert_eq!(submit.status(), StatusCode::CREATED);
    let submit_json = response_json(submit).await;
    let submission_id = submit_json["submission_id"]
        .as_str()
        .expect("submission id should exist")
        .to_owned();

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
                        "reviewed_by": "moderator-a",
                        "review_notes": "approved"
                    })
                    .to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("approval should succeed");
    assert_eq!(approve.status(), StatusCode::OK);

    submission_id
}

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let app = build_local_app(Arc::new(ServiceRegistry::in_memory()));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("response should succeed");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn provider_endpoints_register_list_and_revoke() {
    let app = build_local_app(Arc::new(ServiceRegistry::in_memory()));

    let register = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/providers/register")
                .header("content-type", "application/json")
                .body(Body::from(provider_payload().to_string()))
                .expect("request should build"),
        )
        .await
        .expect("provider register should succeed");
    assert_eq!(register.status(), StatusCode::CREATED);

    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/providers")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("provider list should succeed");
    assert_eq!(list.status(), StatusCode::OK);

    let revoke = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/providers/provider-local/revoke")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "reason": "compromised" }).to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("provider revoke should succeed");
    assert_eq!(revoke.status(), StatusCode::OK);
}

#[tokio::test]
async fn agent_submission_can_be_approved_and_published() {
    let app = build_local_app(Arc::new(ServiceRegistry::in_memory()));

    let register_provider = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/providers/register")
                .header("content-type", "application/json")
                .body(Body::from(provider_payload().to_string()))
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
                    valid_agent_submission_payload(
                        "https://stripe-agent.example.com",
                        "https://stripe-agent.example.com/a2a",
                    )
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
    assert_eq!(submit_json["status"], "submitted");

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
                        "reviewed_by": "moderator-a",
                        "review_notes": "approved"
                    })
                    .to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("approval should succeed");
    assert_eq!(approve.status(), StatusCode::OK);
    let approve_json = response_json(approve).await;
    assert_eq!(approve_json["agent_id"], "stripe-agent");
    assert_eq!(approve_json["status"], "approved");

    let agents = app
        .clone()
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
    assert_eq!(agents_json["items"][0]["agent_id"], "stripe-agent");

    let submission = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/agent-submissions/{submission_id}"))
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("submission get should succeed");
    assert_eq!(submission.status(), StatusCode::OK);
    let submission_json = response_json(submission).await;
    assert_eq!(submission_json["status"], "approved");
}

#[tokio::test]
async fn invalid_agent_submission_is_rejected() {
    let app = build_local_app(Arc::new(ServiceRegistry::in_memory()));
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/providers/register")
                .header("content-type", "application/json")
                .body(Body::from(provider_payload().to_string()))
                .expect("request should build"),
        )
        .await
        .expect("provider register should succeed");

    let mut payload = valid_agent_submission_payload(
        "https://stripe-agent.example.com",
        "https://stripe-agent.example.com/a2a",
    );
    payload["agent_card"]["preferredTransport"] = serde_json::json!("HTTP+JSON");

    let submit = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/agent-submissions")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("submission response should succeed");
    assert_eq!(submit.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn approved_agent_can_be_invoked_over_a2a_and_polled() {
    let app = build_local_app(Arc::new(ServiceRegistry::in_memory()));
    let a2a_url = start_mock_a2a_server().await;
    let card_url = a2a_url.trim_end_matches("/a2a").to_owned();

    let _submission_id = register_provider_and_approve_agent(&app, &a2a_url, &card_url).await;

    let invoke = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/agents/stripe-agent/invoke")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "message": "Create a payment link",
                        "input": { "amount": 42, "currency": "AUD" },
                        "auth_token": "test-token",
                        "region": "AU"
                    })
                    .to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("invoke should succeed");
    assert_eq!(invoke.status(), StatusCode::OK);
    let invoke_json = response_json(invoke).await;
    assert_eq!(invoke_json["status"], "TASK_STATE_WORKING");
    assert_eq!(invoke_json["task_id"], "task-1");

    let poll = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/agents/stripe-agent/tasks/task-1/get")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "history_length": 10,
                        "auth_token": "test-token"
                    })
                    .to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("task get should succeed");
    assert_eq!(poll.status(), StatusCode::OK);
    let poll_json = response_json(poll).await;
    assert_eq!(poll_json["status"], "TASK_STATE_COMPLETED");
    assert_eq!(poll_json["output"]["ok"], true);
    assert_eq!(poll_json["output"]["provider"], "mock-a2a");
}

#[tokio::test]
async fn agent_governance_routes_block_and_resolve_moderation() {
    let app = build_local_app(Arc::new(ServiceRegistry::in_memory()));
    let _submission_id = register_provider_and_approve_agent(
        &app,
        "https://stripe-agent.example.com/a2a",
        "https://stripe-agent.example.com",
    )
    .await;

    let create_case = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/moderation/cases")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "target_kind": "agent",
                        "target_id": "stripe-agent",
                        "created_by": "moderator-a",
                        "reason": "manual review",
                        "auto_block": true,
                        "auto_revoke_provider": false
                    })
                    .to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("moderation case should succeed");
    assert_eq!(create_case.status(), StatusCode::CREATED);
    let case_json = response_json(create_case).await;
    let case_id = case_json["case_id"].as_str().expect("case id should exist");
    assert_eq!(case_json["action_taken"], "agent_blocked");

    let trust = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/trust/agents")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("agent trust list should succeed");
    assert_eq!(trust.status(), StatusCode::OK);
    let trust_json = response_json(trust).await;
    assert_eq!(trust_json["items"][0]["agent_id"], "stripe-agent");
    assert_eq!(trust_json["items"][0]["blocked"], true);

    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/health/agents")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("agent health list should succeed");
    assert_eq!(health.status(), StatusCode::OK);
    let health_json = response_json(health).await;
    assert_eq!(health_json["items"][0]["agent_id"], "stripe-agent");
    assert_eq!(health_json["items"][0]["status"], "offline");

    let resolve = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/admin/moderation/cases/{case_id}/resolve"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "resolved_by": "moderator-b",
                        "resolution_notes": "cleared",
                        "clear_block": true,
                        "reject_case": false
                    })
                    .to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("moderation resolve should succeed");
    assert_eq!(resolve.status(), StatusCode::OK);

    let trust = app
        .oneshot(
            Request::builder()
                .uri("/v1/trust/agents")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("agent trust list should succeed");
    let trust_json = response_json(trust).await;
    assert_eq!(trust_json["items"][0]["blocked"], false);
}

#[tokio::test]
async fn blocked_agent_is_rejected_until_unblocked() {
    let app = build_local_app(Arc::new(ServiceRegistry::in_memory()));
    let a2a_url = start_mock_a2a_server().await;
    let card_url = a2a_url.trim_end_matches("/a2a").to_owned();
    let _submission_id = register_provider_and_approve_agent(&app, &a2a_url, &card_url).await;

    let block = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/agents/stripe-agent/block")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "reason": "manual block" }).to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("block should succeed");
    assert_eq!(block.status(), StatusCode::OK);

    let blocked_invoke = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/agents/stripe-agent/invoke")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "message": "Create a payment link"
                    })
                    .to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("invoke should return response");
    assert_eq!(blocked_invoke.status(), StatusCode::FORBIDDEN);
    let blocked_json = response_json(blocked_invoke).await;
    assert_eq!(blocked_json["error"], "agent is blocked");

    let unblock = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/agents/stripe-agent/unblock")
                .header("content-type", "application/json")
                .body(Body::from("{}".to_owned()))
                .expect("request should build"),
        )
        .await
        .expect("unblock should succeed");
    assert_eq!(unblock.status(), StatusCode::OK);

    let invoke = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/agents/stripe-agent/invoke")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "message": "Create a payment link",
                        "auth_token": "test-token",
                        "region": "AU"
                    })
                    .to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("invoke should succeed");
    assert_eq!(invoke.status(), StatusCode::OK);
}

#[tokio::test]
async fn invalid_moderation_target_kind_is_rejected() {
    let app = build_local_app(Arc::new(ServiceRegistry::in_memory()));

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/moderation/cases")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "target_kind": "service",
                        "target_id": "legacy-target",
                        "created_by": "moderator-a",
                        "reason": "invalid target kind",
                        "auto_block": true,
                        "auto_revoke_provider": false
                    })
                    .to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("response should succeed");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should read");
    let body = String::from_utf8(body.to_vec()).expect("body should be utf8");
    assert!(body.contains("unknown variant `service`"));
}
