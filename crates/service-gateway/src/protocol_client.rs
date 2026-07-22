use a2a::{
    CancelTaskRequest as A2aCancelTaskRequest, GetTaskRequest as A2aGetTaskRequest, JsonRpcId,
    JsonRpcRequest, ListTasksRequest as A2aListTasksRequest, Message, Part, Role,
    SendMessageConfiguration, SendMessageRequest,
    SubscribeToTaskRequest as A2aSubscribeToTaskRequest, jsonrpc::methods,
};
use a2a_client::{
    A2AClient, auth::AuthInterceptor, jsonrpc::JsonRpcTransport, middleware::CallInterceptor,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};
use watt_servicenet_protocol::{
    AgentDeploymentEndpoint, AgentInteractionProtocol, CancelAgentTaskRequest, GetAgentTaskRequest,
    InvokeAgentRequest, ListAgentTasksRequest, NormalizedSettlementRequest,
    SubscribeAgentTaskRequest,
};

use crate::GatewayError;

const AGENT_ENVELOPE_METADATA_KEY: &str = "agent_envelope";
const SETTLEMENT_METADATA_KEY: &str = "settlement";
const SKILL_ID_METADATA_KEY: &str = "skillId";
const AGENT_ENVELOPE_HEADER: &str = "x-wattetheria-agent-envelope";

static A2A_HTTP_CLIENT: OnceLock<reqwest_a2a::Client> = OnceLock::new();

#[async_trait]
pub(crate) trait AgentProtocolClient: Send + Sync {
    async fn send_message(
        &self,
        endpoint: &str,
        request: &InvokeAgentRequest,
        settlement: Option<&NormalizedSettlementRequest>,
        auth_token: Option<&str>,
    ) -> Result<Value, GatewayError>;

    async fn get_task(
        &self,
        endpoint: &str,
        task_id: &str,
        request: &GetAgentTaskRequest,
        auth_token: Option<&str>,
    ) -> Result<Value, GatewayError>;

    async fn list_tasks(
        &self,
        endpoint: &str,
        request: &ListAgentTasksRequest,
        auth_token: Option<&str>,
    ) -> Result<Value, GatewayError>;

    async fn cancel_task(
        &self,
        endpoint: &str,
        task_id: &str,
        request: &CancelAgentTaskRequest,
        auth_token: Option<&str>,
    ) -> Result<Value, GatewayError>;

    async fn subscribe_to_task(
        &self,
        endpoint: &str,
        task_id: &str,
        request: &SubscribeAgentTaskRequest,
        auth_token: Option<&str>,
    ) -> Result<Vec<Value>, GatewayError>;
}

#[derive(Debug, Default)]
struct A2aV1Client;

#[async_trait]
impl AgentProtocolClient for A2aV1Client {
    async fn send_message(
        &self,
        endpoint: &str,
        request: &InvokeAgentRequest,
        settlement: Option<&NormalizedSettlementRequest>,
        auth_token: Option<&str>,
    ) -> Result<Value, GatewayError> {
        let client = client(endpoint, auth_token)?;
        let request = build_send_message_request(request, settlement)?;
        let response = client.send_message(&request).await.map_err(|error| {
            GatewayError::Execution(format!("A2A SendMessage to `{endpoint}` failed: {error}"))
        })?;
        let result = serde_json::to_value(response).map_err(|error| {
            GatewayError::Execution(format!(
                "serialize A2A SendMessage response failed: {error}"
            ))
        })?;
        Ok(json!({"result": result}))
    }

    async fn get_task(
        &self,
        endpoint: &str,
        task_id: &str,
        request: &GetAgentTaskRequest,
        auth_token: Option<&str>,
    ) -> Result<Value, GatewayError> {
        let history_length = request
            .history_length
            .map(i32::try_from)
            .transpose()
            .map_err(|_| GatewayError::Rejected("history_length exceeds A2A limits".to_owned()))?;
        raw_jsonrpc_call(
            endpoint,
            methods::GET_TASK,
            &A2aGetTaskRequest {
                id: task_id.to_owned(),
                history_length,
                tenant: None,
            },
            auth_token,
            request.agent_envelope.as_ref(),
        )
        .await
    }

    async fn list_tasks(
        &self,
        endpoint: &str,
        request: &ListAgentTasksRequest,
        auth_token: Option<&str>,
    ) -> Result<Value, GatewayError> {
        let status = request
            .status
            .as_ref()
            .map(|status| serde_json::from_value(Value::String(status.clone())))
            .transpose()
            .map_err(|error| GatewayError::Rejected(format!("invalid A2A task status: {error}")))?;
        raw_jsonrpc_call(
            endpoint,
            methods::LIST_TASKS,
            &A2aListTasksRequest {
                context_id: request.context_id.clone(),
                status,
                page_size: request
                    .page_size
                    .map(i32::try_from)
                    .transpose()
                    .map_err(|_| {
                        GatewayError::Rejected("page_size exceeds A2A limits".to_owned())
                    })?,
                page_token: request.page_token.clone(),
                history_length: request
                    .history_length
                    .map(i32::try_from)
                    .transpose()
                    .map_err(|_| {
                        GatewayError::Rejected("history_length exceeds A2A limits".to_owned())
                    })?,
                status_timestamp_after: request.status_timestamp_after,
                include_artifacts: request.include_artifacts,
                tenant: None,
            },
            auth_token,
            request.agent_envelope.as_ref(),
        )
        .await
    }

    async fn cancel_task(
        &self,
        endpoint: &str,
        task_id: &str,
        request: &CancelAgentTaskRequest,
        auth_token: Option<&str>,
    ) -> Result<Value, GatewayError> {
        raw_jsonrpc_call(
            endpoint,
            methods::CANCEL_TASK,
            &A2aCancelTaskRequest {
                id: task_id.to_owned(),
                metadata: None,
                tenant: None,
            },
            auth_token,
            request.agent_envelope.as_ref(),
        )
        .await
    }

    async fn subscribe_to_task(
        &self,
        endpoint: &str,
        task_id: &str,
        request: &SubscribeAgentTaskRequest,
        auth_token: Option<&str>,
    ) -> Result<Vec<Value>, GatewayError> {
        let client = client_with_envelope(endpoint, auth_token, request.agent_envelope.as_ref())?;
        let mut stream = client
            .subscribe_to_task(&A2aSubscribeToTaskRequest {
                id: task_id.to_owned(),
                tenant: None,
            })
            .await
            .map_err(|error| {
                GatewayError::Execution(format!(
                    "A2A SubscribeToTask from `{endpoint}` failed: {error}"
                ))
            })?;
        let max_events = request.max_events.unwrap_or(20).clamp(1, 100) as usize;
        let wait_ms = request.wait_timeout_ms.unwrap_or(30_000).clamp(1, 120_000);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(wait_ms);
        let mut events = Vec::new();
        while events.len() < max_events {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let event = match tokio::time::timeout(remaining, stream.next()).await {
                Ok(Some(event)) => event,
                Ok(None) | Err(_) => break,
            };
            let event = event.map_err(|error| {
                GatewayError::Execution(format!(
                    "A2A SubscribeToTask event from `{endpoint}` failed: {error}"
                ))
            })?;
            events.push(
                json!({"result": serde_json::to_value(event).map_err(|error| {
                GatewayError::Execution(format!("serialize A2A task event failed: {error}"))
            })?}),
            );
        }
        Ok(events)
    }
}

async fn raw_jsonrpc_call(
    endpoint: &str,
    method: &str,
    request: &impl serde::Serialize,
    auth_token: Option<&str>,
    agent_envelope: Option<&Value>,
) -> Result<Value, GatewayError> {
    let payload = serde_json::to_value(request).map_err(|error| {
        GatewayError::Execution(format!("serialize A2A {method} request failed: {error}"))
    })?;
    let rpc = JsonRpcRequest::new(
        JsonRpcId::String(uuid::Uuid::new_v4().to_string()),
        method,
        Some(payload),
    );
    let mut builder = shared_http_client()?.post(endpoint).json(&rpc);
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    if let Some(envelope) = agent_envelope {
        let encoded = STANDARD.encode(serde_json::to_vec(envelope).map_err(|error| {
            GatewayError::Execution(format!("serialize A2A agent envelope failed: {error}"))
        })?);
        builder = builder.header(AGENT_ENVELOPE_HEADER, encoded);
    }
    let response = builder.send().await.map_err(|error| {
        GatewayError::Execution(format!("A2A {method} to `{endpoint}` failed: {error}"))
    })?;
    let status = response.status();
    let body = response.text().await.map_err(|error| {
        GatewayError::Execution(format!("read A2A {method} response failed: {error}"))
    })?;
    if !status.is_success() {
        return Err(GatewayError::Execution(format!(
            "A2A {method} to `{endpoint}` returned {status}: {body}"
        )));
    }
    let response: Value = serde_json::from_str(&body).map_err(|error| {
        GatewayError::Execution(format!("parse A2A {method} response failed: {error}"))
    })?;
    if let Some(error) = response.get("error") {
        return Err(GatewayError::Execution(format!(
            "A2A {method} to `{endpoint}` failed: {error}"
        )));
    }
    Ok(response)
}

pub(crate) fn protocol_client(
    endpoint: &AgentDeploymentEndpoint,
) -> Result<Box<dyn AgentProtocolClient + Send + Sync>, GatewayError> {
    if !endpoint
        .interaction_protocol
        .supports_binding(&endpoint.protocol_binding)
    {
        return Err(GatewayError::Rejected(format!(
            "unsupported ServiceNet interaction protocol and binding: {} / {}",
            endpoint.interaction_protocol.as_str(),
            endpoint.protocol_binding
        )));
    }
    Ok(match endpoint.interaction_protocol {
        AgentInteractionProtocol::A2aV1 => Box::<A2aV1Client>::default(),
    })
}

fn client(
    endpoint: &str,
    auth_token: Option<&str>,
) -> Result<A2AClient<JsonRpcTransport>, GatewayError> {
    let transport = JsonRpcTransport::new(shared_http_client()?, endpoint.to_owned());
    let mut client = A2AClient::new(transport);
    if let Some(token) = auth_token {
        let interceptor: Arc<dyn CallInterceptor> =
            Arc::new(AuthInterceptor::bearer(token.to_owned()));
        client = client.with_interceptors(vec![interceptor]);
    }
    Ok(client)
}

fn client_with_envelope(
    endpoint: &str,
    auth_token: Option<&str>,
    agent_envelope: Option<&Value>,
) -> Result<A2AClient<JsonRpcTransport>, GatewayError> {
    let transport = JsonRpcTransport::new(shared_http_client()?, endpoint.to_owned());
    let mut interceptors: Vec<Arc<dyn CallInterceptor>> = Vec::new();
    if let Some(token) = auth_token {
        interceptors.push(Arc::new(AuthInterceptor::bearer(token.to_owned())));
    }
    if let Some(envelope) = agent_envelope {
        let encoded = STANDARD.encode(serde_json::to_vec(envelope).map_err(|error| {
            GatewayError::Execution(format!("serialize A2A agent envelope failed: {error}"))
        })?);
        interceptors.push(Arc::new(AuthInterceptor::custom(
            AGENT_ENVELOPE_HEADER,
            encoded,
        )));
    }
    Ok(A2AClient::new(transport).with_interceptors(interceptors))
}

fn shared_http_client() -> Result<reqwest_a2a::Client, GatewayError> {
    if let Some(client) = A2A_HTTP_CLIENT.get() {
        return Ok(client.clone());
    }
    let client = a2a_client::default_reqwest_client(None).map_err(|error| {
        GatewayError::Execution(format!("build ServiceNet A2A client failed: {error}"))
    })?;
    let _ = A2A_HTTP_CLIENT.set(client);
    Ok(A2A_HTTP_CLIENT
        .get()
        .expect("A2A HTTP client must be initialized")
        .clone())
}

fn build_send_message_request(
    request: &InvokeAgentRequest,
    settlement: Option<&NormalizedSettlementRequest>,
) -> Result<SendMessageRequest, GatewayError> {
    let mut parts = Vec::new();
    if let Some(text) = super::invoke_request_message_text(request) {
        parts.push(Part::text(text));
    }
    if !request.input.is_null() {
        parts.push(Part::data(request.input.clone()));
    }
    if parts.is_empty() {
        parts.push(Part::data(Value::Null));
    }

    let mut message = Message::new(Role::User, parts);
    message.task_id.clone_from(&request.task_id);
    message.context_id.clone_from(&request.context_id);

    let mut metadata = HashMap::new();
    if let Some(skill_id) = &request.skill_id {
        metadata.insert(
            SKILL_ID_METADATA_KEY.to_owned(),
            Value::String(skill_id.clone()),
        );
    }
    if let Some(settlement) = settlement {
        metadata.insert(SETTLEMENT_METADATA_KEY.to_owned(), json!(settlement));
    }
    if let Some(agent_envelope) = &request.agent_envelope {
        // A2A metadata is transported through protobuf Struct. Keep the signed
        // envelope opaque so numeric JSON values cannot be normalized to floats.
        metadata.insert(
            AGENT_ENVELOPE_METADATA_KEY.to_owned(),
            Value::String(serde_json::to_string(agent_envelope).map_err(|error| {
                GatewayError::Execution(format!(
                    "serialize signed agent_envelope metadata failed: {error}"
                ))
            })?),
        );
    }

    Ok(SendMessageRequest {
        message,
        configuration: request.return_immediately.map(|return_immediately| {
            SendMessageConfiguration {
                accepted_output_modes: None,
                task_push_notification_config: None,
                history_length: None,
                return_immediately: Some(return_immediately),
            }
        }),
        metadata: (!metadata.is_empty()).then_some(metadata),
        tenant: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::State,
        http::HeaderMap,
        response::sse::{Event, Sse},
        routing::post,
    };
    use futures_util::stream;
    use std::{convert::Infallible, sync::Mutex};

    fn endpoint(protocol_binding: &str) -> AgentDeploymentEndpoint {
        AgentDeploymentEndpoint {
            url: "https://agent.example.com".to_owned(),
            protocol_binding: protocol_binding.to_owned(),
            protocol_version: "1.0".to_owned(),
            interaction_protocol: AgentInteractionProtocol::A2aV1,
        }
    }

    #[test]
    fn protocol_client_is_selected_from_protocol_and_binding() {
        assert!(protocol_client(&endpoint("JSONRPC")).is_ok());
        let error = protocol_client(&endpoint("HTTP+JSON"))
            .err()
            .expect("unsupported binding should be rejected");
        assert!(error.to_string().contains("a2a_v1 / HTTP+JSON"));
    }

    #[test]
    fn send_message_request_uses_standard_a2a_metadata_for_servicenet_extensions() {
        let request = build_send_message_request(
            &InvokeAgentRequest {
                task_id: Some("task-1".to_owned()),
                context_id: Some("ctx-1".to_owned()),
                message: Some("Create payment link".to_owned()),
                input: json!({"amount": 42}),
                skill_id: Some("payments.create_link".to_owned()),
                return_immediately: Some(true),
                settlement: None,
                auth_token: None,
                auth_context_id: None,
                region: None,
                confirm_risky: false,
                max_cost_units: None,
                agent_envelope: Some(json!({"source_agent_id": "did:key:zCaller"})),
            },
            None,
        )
        .expect("request should build");
        let value = serde_json::to_value(request).expect("request should serialize");

        assert_eq!(value["message"]["taskId"], "task-1");
        assert_eq!(value["message"]["contextId"], "ctx-1");
        assert_eq!(value["message"]["parts"][0]["text"], "Create payment link");
        assert_eq!(value["message"]["parts"][1]["data"]["amount"], 42);
        assert_eq!(value["metadata"]["skillId"], "payments.create_link");
        assert_eq!(value["configuration"]["returnImmediately"], true);
        let envelope: Value = serde_json::from_str(
            value["metadata"]["agent_envelope"]
                .as_str()
                .expect("signed envelope should be opaque JSON metadata"),
        )
        .expect("signed envelope metadata should remain valid JSON");
        assert_eq!(envelope["source_agent_id"], "did:key:zCaller");
    }

    async fn subscription_handler(
        State(captured_header): State<Arc<Mutex<Option<String>>>>,
        headers: HeaderMap,
        Json(request): Json<Value>,
    ) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
        *captured_header.lock().expect("capture lock") = headers
            .get(AGENT_ENVELOPE_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let event = json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "message": {
                    "messageId": "event-1",
                    "role": "ROLE_AGENT",
                    "parts": [{"text": "done"}]
                }
            }
        });
        Sse::new(stream::iter([Ok(Event::default()
            .json_data(event)
            .expect("subscription event should serialize"))]))
    }

    #[tokio::test]
    async fn subscribe_to_task_forwards_signed_envelope_and_collects_events() {
        let captured_header = Arc::new(Mutex::new(None));
        let app = Router::new()
            .route("/adapter", post(subscription_handler))
            .with_state(Arc::clone(&captured_header));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let endpoint = format!("http://{}/adapter", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("mock Adapter should run");
        });
        let envelope = json!({"source_agent_id": "did:key:zCaller", "signature": "signed"});

        let events = A2aV1Client
            .subscribe_to_task(
                &endpoint,
                "task-1",
                &SubscribeAgentTaskRequest {
                    agent_envelope: Some(envelope.clone()),
                    max_events: Some(1),
                    wait_timeout_ms: Some(1_000),
                    ..SubscribeAgentTaskRequest::default()
                },
                None,
            )
            .await
            .expect("subscription should succeed");

        assert_eq!(events[0]["result"]["message"]["messageId"], "event-1");
        let encoded = captured_header
            .lock()
            .expect("capture lock")
            .clone()
            .expect("signed envelope header should be present");
        assert_eq!(
            STANDARD.decode(encoded).expect("header should decode"),
            serde_json::to_vec(&envelope).expect("envelope should serialize")
        );
    }
}
