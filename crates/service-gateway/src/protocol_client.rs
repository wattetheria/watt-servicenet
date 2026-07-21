use a2a::{GetTaskRequest as A2aGetTaskRequest, Message, Part, Role, SendMessageRequest};
use a2a_client::{
    A2AClient, auth::AuthInterceptor, jsonrpc::JsonRpcTransport, middleware::CallInterceptor,
};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};
use watt_servicenet_protocol::{
    AgentDeploymentEndpoint, AgentInteractionProtocol, GetAgentTaskRequest, InvokeAgentRequest,
    NormalizedSettlementRequest,
};

use crate::GatewayError;

const AGENT_ENVELOPE_METADATA_KEY: &str = "agent_envelope";
const SETTLEMENT_METADATA_KEY: &str = "settlement";
const SKILL_ID_METADATA_KEY: &str = "skillId";

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
        let request = build_send_message_request(request, settlement);
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
        let client = client(endpoint, auth_token)?;
        let task = client
            .get_task(&A2aGetTaskRequest {
                id: task_id.to_owned(),
                history_length,
                tenant: None,
            })
            .await
            .map_err(|error| {
                GatewayError::Execution(format!("A2A GetTask from `{endpoint}` failed: {error}"))
            })?;
        Ok(json!({"result": {"task": task}}))
    }
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
) -> SendMessageRequest {
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
        metadata.insert(
            AGENT_ENVELOPE_METADATA_KEY.to_owned(),
            agent_envelope.clone(),
        );
    }

    SendMessageRequest {
        message,
        configuration: None,
        metadata: (!metadata.is_empty()).then_some(metadata),
        tenant: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                settlement: None,
                auth_token: None,
                auth_context_id: None,
                region: None,
                confirm_risky: false,
                max_cost_units: None,
                agent_envelope: Some(json!({"source_agent_id": "did:key:zCaller"})),
            },
            None,
        );
        let value = serde_json::to_value(request).expect("request should serialize");

        assert_eq!(value["message"]["taskId"], "task-1");
        assert_eq!(value["message"]["contextId"], "ctx-1");
        assert_eq!(value["message"]["parts"][0]["text"], "Create payment link");
        assert_eq!(value["message"]["parts"][1]["data"]["amount"], 42);
        assert_eq!(value["metadata"]["skillId"], "payments.create_link");
        assert_eq!(
            value["metadata"]["agent_envelope"]["source_agent_id"],
            "did:key:zCaller"
        );
    }
}
