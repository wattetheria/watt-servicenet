use axum::body::{self, Body};
use axum::http::{Request, StatusCode};
use axum::{Json, Router, extract::State, routing::post};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;
use watt_servicenet_node::build_local_app;
use watt_servicenet_protocol::{
    InvokeAgentRequest, ServiceAgentSignature, build_agent_attestation_payload,
    build_agent_unpublish_payload, build_service_agent_signature_payload,
};
use watt_servicenet_registry::ServiceRegistry;

fn provider_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[21u8; 32])
}

fn caller_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn service_signing_key(agent_id: &str) -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(agent_id.as_bytes()).into();
    SigningKey::from_bytes(&seed)
}

fn service_did(agent_id: &str) -> String {
    did_from_signing_key(&service_signing_key(agent_id))
}

fn service_verification_method(agent_id: &str) -> String {
    let service_did = service_did(agent_id);
    let fingerprint = service_did
        .strip_prefix("did:key:")
        .expect("service identity should use did:key");
    format!("{service_did}#{fingerprint}")
}

#[derive(Debug, Serialize)]
struct SignedAgentEnvelopePayload<'a> {
    protocol: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport_profile: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_agent_id: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_agent_id: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_node_id: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_node_id: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capability: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_agent_card_hash: Option<&'a String>,
    message_json: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    extensions_json: Option<&'a String>,
}

#[derive(Debug, Serialize)]
struct SignedSourceAgentCardPayload<'a> {
    agent_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_id: Option<&'a String>,
    card_hash: &'a str,
    issued_at: u64,
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

fn sign_payload(payload: &impl Serialize, signing_key: &SigningKey) -> String {
    STANDARD.encode(
        signing_key
            .sign(&serde_jcs::to_vec(payload).expect("payload should canonicalize"))
            .to_bytes(),
    )
}

fn canonical_value_hash(value: &serde_json::Value) -> String {
    let bytes = serde_jcs::to_vec(value).expect("value should canonicalize");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn signed_source_agent_card(signing_key: &SigningKey) -> serde_json::Value {
    let agent_id = did_from_signing_key(signing_key);
    let node_id = Some("node-caller".to_owned());
    let card = serde_json::json!({
        "name": "Caller Agent"
    });
    let card_hash = canonical_value_hash(&card);
    let issued_at = 1_776_000_000;
    let payload = SignedSourceAgentCardPayload {
        agent_id: &agent_id,
        node_id: node_id.as_ref(),
        card_hash: &card_hash,
        issued_at,
    };
    serde_json::json!({
        "agent_id": agent_id,
        "node_id": node_id,
        "card_hash": card_hash,
        "issued_at": issued_at,
        "card": card,
        "signature": sign_payload(&payload, signing_key)
    })
}

fn signed_agent_envelope(request: &serde_json::Value) -> serde_json::Value {
    let signing_key = caller_signing_key();
    let source_agent_id = did_from_signing_key(&signing_key);
    let transport_profile = Some("wattswarm_mesh".to_owned());
    let target_agent_id = Some("stripe-agent".to_owned());
    let source_node_id = Some("node-caller".to_owned());
    let capability = Some("servicenet.agents.invoke".to_owned());
    let source_agent_card = signed_source_agent_card(&signing_key);
    let source_agent_card_hash = source_agent_card
        .get("card_hash")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    let mut message = serde_json::to_value(
        serde_json::from_value::<InvokeAgentRequest>(request.clone())
            .expect("invocation request should parse"),
    )
    .expect("invocation request should serialize");
    let message_object = message
        .as_object_mut()
        .expect("invocation request should be an object");
    message_object.remove("auth_token");
    message_object.remove("auth_context_id");
    message_object.remove("agent_envelope");
    let issued_at_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_millis()
        .try_into()
        .expect("timestamp should fit u64");
    let extensions = serde_json::json!({
        "caller_public_id": "pub_caller",
        "nonce": format!("http-test-{}", uuid::Uuid::new_v4()),
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": issued_at_ms.saturating_add(60_000),
        "request_digest": canonical_value_hash(&message),
    });
    let message_json = serde_json::to_string(&message).expect("message should serialize");
    let extensions_json =
        Some(serde_json::to_string(&extensions).expect("extensions should serialize"));
    let payload = SignedAgentEnvelopePayload {
        protocol: "a2a_v1",
        transport_profile: transport_profile.as_ref(),
        source_agent_id: Some(&source_agent_id),
        target_agent_id: target_agent_id.as_ref(),
        source_node_id: source_node_id.as_ref(),
        target_node_id: None,
        capability: capability.as_ref(),
        source_agent_card_hash: source_agent_card_hash.as_ref(),
        message_json: &message_json,
        extensions_json: extensions_json.as_ref(),
    };
    serde_json::json!({
        "protocol": "a2a_v1",
        "transport_profile": transport_profile,
        "source_agent_id": source_agent_id,
        "target_agent_id": target_agent_id,
        "source_node_id": source_node_id,
        "capability": capability,
        "source_agent_card": source_agent_card,
        "message": message,
        "extensions": extensions,
        "signature": sign_payload(&payload, &signing_key)
    })
}

fn with_signed_agent_envelope(mut request: serde_json::Value) -> serde_json::Value {
    request["agent_envelope"] = signed_agent_envelope(&request);
    request
}

fn provider_payload() -> serde_json::Value {
    serde_json::json!({
        "provider_id": "provider-local",
        "provider_did": did_from_signing_key(&provider_signing_key()),
        "display_name": "Provider Local"
    })
}

fn valid_agent_submission_payload_for_agent(
    agent_id: &str,
    url_base: &str,
    endpoint_url: &str,
) -> serde_json::Value {
    let service_address = format!("{agent_id}@wattetheria");
    let service_did = service_did(agent_id);
    let mut payload = serde_json::json!({
        "provider_id": "provider-local",
        "agent_id": agent_id,
        "service_did": service_did,
        "service_address": service_address,
        "version": "0.1.0",
        "agent_card": {
            "name": "Stripe Agent",
            "description": "Handles Stripe payment flows",
            "url": url_base,
            "preferredTransport": "JSONRPC",
            "protocolVersion": "1.0",
            "supportsTask": false,
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
            "runtime": "wattetheria_adapter",
            "endpoint": {
                "url": endpoint_url,
                "protocol_binding": "JSONRPC",
                "protocol_version": "1.0",
                "interaction_protocol": "a2a_v1"
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
            "attestation_signature": "",
            "source_commit": "abc123",
            "build_digest": "sha256:def456"
        }
    });
    let signing_key = provider_signing_key();
    let signature = STANDARD.encode(
        signing_key
            .sign(
                &serde_jcs::to_vec(&build_agent_attestation_payload(
                    &serde_json::from_value(payload.clone()).expect("submission should parse"),
                ))
                .expect("attestation payload should canonicalize"),
            )
            .to_bytes(),
    );
    payload["attestations"]["attestation_signature"] = serde_json::Value::String(signature);
    payload
}

fn valid_agent_submission_payload(url_base: &str, endpoint_url: &str) -> serde_json::Value {
    valid_agent_submission_payload_for_agent("stripe-agent", url_base, endpoint_url)
}

fn valid_agent_unpublish_payload(agent_id: &str) -> serde_json::Value {
    let signing_key = provider_signing_key();
    let issued_at_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_millis()
        .try_into()
        .expect("current millis should fit u64");
    let mut payload = serde_json::json!({
        "provider_id": "provider-local",
        "provider_did": did_from_signing_key(&signing_key),
        "signature": "",
        "nonce": format!("unpublish-{agent_id}"),
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": issued_at_ms.saturating_add(30 * 60 * 1000),
        "reason": "operator requested unpublish"
    });
    let signature = STANDARD.encode(
        signing_key
            .sign(
                &serde_jcs::to_vec(&build_agent_unpublish_payload(
                    agent_id,
                    &serde_json::from_value(payload.clone()).expect("unpublish should parse"),
                ))
                .expect("unpublish payload should canonicalize"),
            )
            .to_bytes(),
    );
    payload["signature"] = serde_json::Value::String(signature);
    payload
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should read");
    serde_json::from_slice(&body).expect("json should parse")
}

fn forwarded_agent_envelope(request: &serde_json::Value) -> Option<serde_json::Value> {
    let envelope = request.pointer("/params/metadata/agent_envelope")?;
    match envelope {
        serde_json::Value::String(encoded) => serde_json::from_str(encoded).ok(),
        value => Some(value.clone()),
    }
}

fn signed_a2a_response(
    request: &serde_json::Value,
    mut result: serde_json::Value,
) -> serde_json::Value {
    let service_did = service_did("stripe-agent");
    let agent_envelope = forwarded_agent_envelope(request);
    let request_digest = agent_envelope
        .as_ref()
        .and_then(|value| value.pointer("/extensions/request_digest"))
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| canonical_value_hash(&request["params"]));
    let request_nonce = agent_envelope
        .as_ref()
        .and_then(|value| value.pointer("/extensions/nonce"))
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    let issued_at_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_millis()
        .try_into()
        .expect("timestamp should fit u64");
    let unsigned_wire_result = if request["method"] == "GetTask" {
        result["task"].clone()
    } else {
        result.clone()
    };
    let mut service_signature = ServiceAgentSignature {
        protocol: "wattetheria.servicenet.response.v1".to_owned(),
        service_did: service_did.clone(),
        agent_id: "stripe-agent".to_owned(),
        verification_method: service_verification_method("stripe-agent"),
        request_digest,
        request_nonce,
        result_digest: canonical_value_hash(&unsigned_wire_result),
        nonce: format!("test-response-{issued_at_ms}"),
        issued_at_ms,
        signature: String::new(),
    };
    service_signature.signature = sign_payload(
        &build_service_agent_signature_payload(&service_signature),
        &service_signing_key("stripe-agent"),
    );
    let signature = serde_json::Value::String(
        serde_json::to_string(&service_signature).expect("signature should serialize"),
    );
    let wire_result = if request["method"] == "GetTask" {
        let mut task = result["task"].take();
        task["metadata"]["wattetheriaServiceAgentSignature"] = signature;
        task
    } else {
        let payload_name = if result.get("task").is_some() {
            "task"
        } else {
            "message"
        };
        result[payload_name]["metadata"]["wattetheriaServiceAgentSignature"] = signature;
        result
    };
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": request["id"].clone(),
        "result": wire_result,
    })
}

async fn start_mock_a2a_server() -> String {
    async fn handle(Json(request): Json<serde_json::Value>) -> Json<serde_json::Value> {
        let method = request["method"].as_str().unwrap_or_default();
        let response = match method {
            "SendMessage" => signed_a2a_response(
                &request,
                serde_json::json!({
                    "task": {
                        "id": "task-1",
                        "contextId": "ctx-1",
                        "status": {
                            "state": "TASK_STATE_WORKING"
                        }
                    }
                }),
            ),
            "GetTask" => signed_a2a_response(
                &request,
                serde_json::json!({
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
                }),
            ),
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

async fn start_mock_a2a_server_with_capture() -> (String, Arc<Mutex<Vec<serde_json::Value>>>) {
    let captured = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));

    async fn handle(
        State(captured): State<Arc<Mutex<Vec<serde_json::Value>>>>,
        Json(request): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        captured.lock().expect("capture lock").push(request.clone());
        let response = signed_a2a_response(
            &request,
            serde_json::json!({
                "task": {
                    "id": "task-ap2-1",
                    "contextId": "ctx-ap2-1",
                    "status": {
                        "state": "TASK_STATE_COMPLETED"
                    },
                    "artifacts": [
                        {
                            "artifactId": "artifact-1",
                            "parts": [
                                {
                                    "data": {
                                        "payment_receipt": {
                                            "status": "authorized"
                                        },
                                        "provider": "mock-a2a"
                                    }
                                }
                            ]
                        }
                    ]
                }
            }),
        );
        Json(response)
    }

    let app = Router::new()
        .route("/a2a", post(handle))
        .with_state(Arc::clone(&captured));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("local addr should exist");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("mock a2a server should run");
    });
    (format!("http://{addr}/a2a"), captured)
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
    // Submissions are auto-approved by default; the admin approve POST below
    // is now idempotent but kept here to exercise the legacy flow.
    assert_eq!(submit_json["status"], "approved");

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
    assert_eq!(
        agents_json["items"][0]["deployment"]["runtime"].as_str(),
        Some("wattetheria_adapter")
    );
    assert!(
        agents_json["items"][0]["deployment"]["endpoint"]
            .get("url")
            .is_none()
    );
    assert!(agents_json["items"][0]["agent_card"].get("url").is_none());
    assert_eq!(
        agents_json["items"][0]["invoke"]["sync_url"].as_str(),
        Some("/v1/agents/stripe-agent/invoke")
    );
    let public_list_body = serde_json::to_string(&agents_json).expect("list body should serialize");
    assert!(!public_list_body.contains("https://stripe-agent.example.com"));

    let agent = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/agents/stripe-agent")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("agent get should succeed");
    assert_eq!(agent.status(), StatusCode::OK);
    let agent_json = response_json(agent).await;
    assert_eq!(agent_json["agent_id"], "stripe-agent");
    assert_eq!(
        agent_json["deployment"]["endpoint"]["protocol_binding"].as_str(),
        Some("JSONRPC")
    );
    assert!(agent_json["deployment"]["endpoint"].get("url").is_none());
    assert!(agent_json["agent_card"].get("url").is_none());
    assert_eq!(
        agent_json["invoke"]["async_url"].as_str(),
        Some("/v1/agents/stripe-agent/invoke-async")
    );
    let public_detail_body =
        serde_json::to_string(&agent_json).expect("detail body should serialize");
    assert!(!public_detail_body.contains("https://stripe-agent.example.com"));

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
async fn published_agent_can_be_unpublished_by_provider_signature() {
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

    let unpublish = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/agents/stripe-agent/unpublish")
                .header("content-type", "application/json")
                .body(Body::from(
                    valid_agent_unpublish_payload("stripe-agent").to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("unpublish should succeed");
    assert_eq!(unpublish.status(), StatusCode::OK);
    let unpublish_json = response_json(unpublish).await;
    assert_eq!(unpublish_json["agent_id"], "stripe-agent");
    assert_eq!(unpublish_json["status"], "revoked");

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
    assert_eq!(agents_json["count"], 0);
    assert_eq!(agents_json["known_count"], 0);

    let get_agent = app
        .oneshot(
            Request::builder()
                .uri("/v1/agents/stripe-agent")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("agent get should respond");
    assert_eq!(get_agent.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn agents_list_supports_limit_offset_pagination() {
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

    for agent_id in ["agent-a", "agent-b", "agent-c"] {
        let submit = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/agent-submissions")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        valid_agent_submission_payload_for_agent(
                            agent_id,
                            &format!("https://{agent_id}.example.com"),
                            &format!("https://{agent_id}.example.com/a2a"),
                        )
                        .to_string(),
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("submission should succeed");
        assert_eq!(submit.status(), StatusCode::CREATED);
    }

    let agents = app
        .oneshot(
            Request::builder()
                .uri("/v1/agents?limit=2&offset=1")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("agent list should succeed");
    assert_eq!(agents.status(), StatusCode::OK);
    let agents_json = response_json(agents).await;
    assert_eq!(agents_json["count"], 2);
    assert_eq!(agents_json["limit"], 2);
    assert_eq!(agents_json["offset"], 1);
    assert_eq!(agents_json["next_offset"], serde_json::Value::Null);
    assert_eq!(agents_json["has_more"], false);
    assert_eq!(agents_json["known_count"], 3);
    assert_eq!(agents_json["items"][0]["agent_id"], "agent-b");
    assert_eq!(agents_json["items"][1]["agent_id"], "agent-c");
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
                    with_signed_agent_envelope(serde_json::json!({
                        "message": "Create a payment link",
                        "input": { "amount": 42, "currency": "AUD" },
                        "auth_token": "test-token",
                        "region": "AU"
                    }))
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
    let poll_status = poll.status();
    let poll_json = response_json(poll).await;
    assert_eq!(poll_status, StatusCode::OK, "task poll failed: {poll_json}");
    assert_eq!(poll_json["status"], "TASK_STATE_COMPLETED");
    assert_eq!(poll_json["output"]["ok"], true);
    assert_eq!(poll_json["output"]["provider"], "mock-a2a");
}

#[tokio::test]
async fn approved_agent_can_be_invoked_async_and_polled_by_receipt() {
    let app = build_local_app(Arc::new(ServiceRegistry::in_memory()));
    let a2a_url = start_mock_a2a_server().await;
    let card_url = a2a_url.trim_end_matches("/a2a").to_owned();

    let _submission_id = register_provider_and_approve_agent(&app, &a2a_url, &card_url).await;

    let invoke = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/agents/stripe-agent/invoke-async")
                .header("content-type", "application/json")
                .body(Body::from(
                    with_signed_agent_envelope(serde_json::json!({
                        "message": "Create a payment link",
                        "input": { "amount": 42, "currency": "AUD" },
                        "auth_token": "test-token",
                        "region": "AU"
                    }))
                    .to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("async invoke should succeed");
    assert_eq!(invoke.status(), StatusCode::OK);
    let invoke_json = response_json(invoke).await;
    assert_eq!(invoke_json["status"], "running");
    let receipt_id = invoke_json["receipt_id"]
        .as_str()
        .expect("receipt id should be returned")
        .to_owned();

    let mut receipt_json = serde_json::Value::Null;
    for _ in 0..20 {
        let receipt = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/receipts/{receipt_id}"))
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("receipt poll should succeed");
        assert_eq!(receipt.status(), StatusCode::OK);
        receipt_json = response_json(receipt).await;
        if receipt_json["receipt"]["status"] == "succeeded" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    assert_eq!(receipt_json["receipt"]["status"], "succeeded");
    assert!(receipt_json["receipt"]["completed_at"].is_string());
    assert_eq!(receipt_json["output"]["result"]["task"]["id"], "task-1");
    assert_eq!(
        receipt_json["output"]["result"]["task"]["status"]["state"],
        "TASK_STATE_WORKING"
    );
}

#[tokio::test]
async fn approved_agent_can_be_invoked_over_a2a_with_x402_settlement() {
    let app = build_local_app(Arc::new(ServiceRegistry::in_memory()));
    let (a2a_url, captured) = start_mock_a2a_server_with_capture().await;
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
                    with_signed_agent_envelope(serde_json::json!({
                        "task_id": "task-ap2-1",
                        "context_id": "ctx-ap2-1",
                        "message": "Book a flight",
                        "input": {
                            "quote_id": "quote-1"
                        },
                        "settlement": {
                            "layer": "web3",
                            "rail": "x402",
                            "request": {
                                "pay_to": "0xabc123"
                            }
                        },
                        "auth_token": "test-token",
                        "region": "AU",
                        "confirm_risky": true
                    }))
                    .to_string(),
                ))
                .expect("request should build"),
        )
        .await
        .expect("invoke should succeed");
    assert_eq!(invoke.status(), StatusCode::OK);
    let invoke_json = response_json(invoke).await;
    assert_eq!(invoke_json["status"], "TASK_STATE_COMPLETED");
    assert_eq!(invoke_json["settlement"]["rail"], "x402");
    assert_eq!(
        invoke_json["payment_receipt"]["status"],
        serde_json::json!("authorized")
    );
    let receipt_id = invoke_json["receipt_id"]
        .as_str()
        .expect("receipt id should exist");
    let receipt = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/receipts/{receipt_id}"))
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("receipt should load");
    assert_eq!(receipt.status(), StatusCode::OK);
    let receipt_json = response_json(receipt).await;
    assert_eq!(
        receipt_json["receipt"]["caller_agent_id"],
        serde_json::json!(did_from_signing_key(&caller_signing_key()))
    );
    assert_eq!(
        receipt_json["receipt"]["caller_public_id"],
        serde_json::json!("pub_caller")
    );
    assert_eq!(
        receipt_json["receipt"]["caller_display_name"],
        serde_json::json!("Caller Agent")
    );
    assert_eq!(
        receipt_json["receipt"]["caller_node_id"],
        serde_json::json!("node-caller")
    );

    let captured = captured.lock().expect("capture lock");
    let request = captured.last().expect("captured request");
    assert_eq!(request["method"], "SendMessage");
    assert_eq!(request["params"]["metadata"]["settlement"]["rail"], "x402");
    assert_eq!(
        request["params"]["metadata"]["settlement"]["request"]["protocol"],
        "x402"
    );
    let forwarded_envelope =
        forwarded_agent_envelope(request).expect("signed envelope should remain valid JSON");
    assert_eq!(
        forwarded_envelope["extensions"]["caller_public_id"],
        serde_json::json!("pub_caller")
    );
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
                    with_signed_agent_envelope(serde_json::json!({
                        "message": "Create a payment link"
                    }))
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
                    with_signed_agent_envelope(serde_json::json!({
                        "message": "Create a payment link",
                        "auth_token": "test-token",
                        "region": "AU"
                    }))
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
