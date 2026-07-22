use serde_json::{Value, json};
use watt_servicenet_protocol::{
    AgentConnectionMode, AgentExecutionMode, CancelAgentTaskRequest, GetAgentTaskRequest,
    InvokeAgentResponse, ListAgentTasksRequest, PublishedAgentRecord, SubscribeAgentTaskRequest,
    cancel_agent_task_envelope_message, get_agent_task_envelope_message,
    list_agent_tasks_envelope_message, subscribe_agent_task_envelope_message,
};

use super::{
    AgentProtocolClient, GatewayError, GatewayService, VerifiedAgentEnvelopeSecurity,
    build_invoke_agent_response, build_service_agent_get_task_signature_params, map_registry_error,
    protocol_client, verify_agent_envelope_value,
};

struct PreparedTaskOperation {
    record: PublishedAgentRecord,
    auth_token: Option<String>,
    protocol_client: Box<dyn AgentProtocolClient + Send + Sync>,
    security: VerifiedAgentEnvelopeSecurity,
}

impl GatewayService {
    pub async fn get_agent_task(
        &self,
        agent_id: &str,
        task_id: &str,
        request: GetAgentTaskRequest,
    ) -> Result<InvokeAgentResponse, GatewayError> {
        let record = self
            .registry
            .get_published_agent(agent_id)
            .await
            .map_err(map_registry_error)?;
        if record.deployment.execution_mode == AgentExecutionMode::WattetheriaRuntime {
            return self.get_legacy_runtime_task(record, task_id, request).await;
        }
        let expected = get_agent_task_envelope_message(task_id, &request);
        let prepared = self
            .prepare_task_operation(
                record,
                request.agent_envelope.as_ref(),
                request.auth_context_id,
                request.auth_token.as_deref(),
                &expected,
            )
            .await?;
        let response = prepared
            .protocol_client
            .get_task(
                &prepared.record.deployment.endpoint.url,
                task_id,
                &request,
                prepared.auth_token.as_deref(),
            )
            .await?;
        self.verified_task_response(agent_id, prepared, response)
    }

    async fn get_legacy_runtime_task(
        &self,
        record: PublishedAgentRecord,
        task_id: &str,
        request: GetAgentTaskRequest,
    ) -> Result<InvokeAgentResponse, GatewayError> {
        if record.deployment.connection_mode != AgentConnectionMode::ServicenetRelay {
            return Err(GatewayError::Rejected(
                "wattetheria_direct agents do not support legacy ServiceNet task polling"
                    .to_owned(),
            ));
        }
        let auth_token = self
            .resolve_agent_auth_context(&record, request.auth_context_id)
            .await?
            .or_else(|| request.auth_token.clone());
        self.enforce_agent_task_access(&record, auth_token.as_deref())
            .await?;
        let protocol_client = protocol_client(&record.deployment.endpoint)?;
        let params = build_service_agent_get_task_signature_params(task_id, request.history_length);
        let expected_request_digest = super::jcs_sha256_digest_value(&params)
            .map_err(|error| GatewayError::Execution(error.to_string()))?;
        let response = protocol_client
            .get_task(
                &record.deployment.endpoint.url,
                task_id,
                &request,
                auth_token.as_deref(),
            )
            .await?;
        let service_signature = self.service_agent_verifier.verify_response(
            &record,
            Some(&expected_request_digest),
            None,
            &response,
        )?;
        Ok(build_invoke_agent_response(
            &record.agent_id,
            None,
            None,
            response,
            Some(service_signature),
        ))
    }

    pub async fn list_agent_tasks(
        &self,
        agent_id: &str,
        request: ListAgentTasksRequest,
    ) -> Result<InvokeAgentResponse, GatewayError> {
        let record = self
            .registry
            .get_published_agent(agent_id)
            .await
            .map_err(map_registry_error)?;
        let expected = list_agent_tasks_envelope_message(&request);
        let prepared = self
            .prepare_task_operation(
                record,
                request.agent_envelope.as_ref(),
                request.auth_context_id,
                request.auth_token.as_deref(),
                &expected,
            )
            .await?;
        let response = prepared
            .protocol_client
            .list_tasks(
                &prepared.record.deployment.endpoint.url,
                &request,
                prepared.auth_token.as_deref(),
            )
            .await?;
        self.verified_task_response(agent_id, prepared, response)
    }

    pub async fn cancel_agent_task(
        &self,
        agent_id: &str,
        task_id: &str,
        request: CancelAgentTaskRequest,
    ) -> Result<InvokeAgentResponse, GatewayError> {
        let record = self
            .registry
            .get_published_agent(agent_id)
            .await
            .map_err(map_registry_error)?;
        let expected = cancel_agent_task_envelope_message(task_id);
        let prepared = self
            .prepare_task_operation(
                record,
                request.agent_envelope.as_ref(),
                request.auth_context_id,
                request.auth_token.as_deref(),
                &expected,
            )
            .await?;
        let response = prepared
            .protocol_client
            .cancel_task(
                &prepared.record.deployment.endpoint.url,
                task_id,
                &request,
                prepared.auth_token.as_deref(),
            )
            .await?;
        self.verified_task_response(agent_id, prepared, response)
    }

    pub async fn subscribe_agent_task(
        &self,
        agent_id: &str,
        task_id: &str,
        request: SubscribeAgentTaskRequest,
    ) -> Result<InvokeAgentResponse, GatewayError> {
        let record = self
            .registry
            .get_published_agent(agent_id)
            .await
            .map_err(map_registry_error)?;
        let expected = subscribe_agent_task_envelope_message(task_id);
        let prepared = self
            .prepare_task_operation(
                record,
                request.agent_envelope.as_ref(),
                request.auth_context_id,
                request.auth_token.as_deref(),
                &expected,
            )
            .await?;
        let events = prepared
            .protocol_client
            .subscribe_to_task(
                &prepared.record.deployment.endpoint.url,
                task_id,
                &request,
                prepared.auth_token.as_deref(),
            )
            .await?;
        for event in &events {
            self.service_agent_verifier.verify_response(
                &prepared.record,
                prepared.security.request_digest.as_deref(),
                prepared.security.nonce.as_deref(),
                event,
            )?;
        }
        Ok(InvokeAgentResponse {
            agent_id: agent_id.to_owned(),
            status: "subscribed".to_owned(),
            receipt_id: None,
            task_id: Some(task_id.to_owned()),
            context_id: None,
            message: None,
            settlement: None,
            payment_receipt: None,
            output: Some(json!({"events": events})),
            service_signature: None,
            raw: json!({"result": {"events": events}}),
        })
    }

    async fn prepare_task_operation(
        &self,
        record: PublishedAgentRecord,
        envelope: Option<&Value>,
        auth_context_id: Option<uuid::Uuid>,
        auth_token: Option<&str>,
        expected_message: &Value,
    ) -> Result<PreparedTaskOperation, GatewayError> {
        let agent_id = record.agent_id.as_str();
        if record.deployment.connection_mode != AgentConnectionMode::ServicenetRelay {
            return Err(GatewayError::Rejected(
                "agent uses wattetheria_direct connection mode; call its published Adapter URL"
                    .to_owned(),
            ));
        }
        if record.deployment.execution_mode != AgentExecutionMode::CustomizedAgent {
            return Err(GatewayError::Rejected(
                "A2A Task operations require a Customized Agent; Wattetheria Runtime uses the internal invocation flow"
                    .to_owned(),
            ));
        }
        let envelope = envelope
            .ok_or_else(|| GatewayError::Rejected("agent_envelope is required".to_owned()))?;
        if envelope.get("target_agent_id").and_then(Value::as_str) != Some(agent_id) {
            return Err(GatewayError::Rejected(
                "agent_envelope.target_agent_id does not match the requested Service Agent"
                    .to_owned(),
            ));
        }
        let security = verify_agent_envelope_value(envelope)?;
        if &security.signed_message != expected_message {
            return Err(GatewayError::Rejected(
                "agent_envelope.message does not match the A2A Task operation".to_owned(),
            ));
        }
        self.enforce_signed_envelope_replay(&security)?;
        let auth_token = self
            .resolve_agent_auth_context(&record, auth_context_id)
            .await?
            .or_else(|| auth_token.map(ToOwned::to_owned));
        self.enforce_agent_task_access(&record, auth_token.as_deref())
            .await?;
        let protocol_client = protocol_client(&record.deployment.endpoint)?;
        Ok(PreparedTaskOperation {
            record,
            auth_token,
            protocol_client,
            security,
        })
    }

    fn verified_task_response(
        &self,
        agent_id: &str,
        prepared: PreparedTaskOperation,
        response: Value,
    ) -> Result<InvokeAgentResponse, GatewayError> {
        let service_signature = self.service_agent_verifier.verify_response(
            &prepared.record,
            prepared.security.request_digest.as_deref(),
            prepared.security.nonce.as_deref(),
            &response,
        )?;
        Ok(build_invoke_agent_response(
            agent_id,
            None,
            None,
            response,
            Some(service_signature),
        ))
    }
}
