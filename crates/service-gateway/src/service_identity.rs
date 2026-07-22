use crate::GatewayError;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use watt_did::{Did, DidKey, DidKeyPublicKey};
use watt_servicenet_protocol::{
    PublishedAgentRecord, SERVICE_AGENT_SIGNATURE_PROTOCOL, ServiceAgentSignature,
    build_service_agent_signature_payload,
};

const MAX_CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;
const PUBLIC_KEY_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const PUBLIC_KEY_CACHE_MAX_ENTRIES: usize = 4_096;
const RESPONSE_NONCE_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const RESPONSE_NONCE_CACHE_MAX_ENTRIES: usize = 262_144;

#[derive(Debug, Clone)]
struct CachedPublicKey {
    public_key: [u8; 32],
    expires_at: Instant,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ServiceAgentVerifier {
    public_key_cache: Arc<Mutex<HashMap<String, CachedPublicKey>>>,
    response_nonce_cache: Arc<Mutex<HashMap<String, Instant>>>,
}

impl ServiceAgentVerifier {
    pub(crate) fn verify_response(
        &self,
        record: &PublishedAgentRecord,
        expected_request_digest: Option<&str>,
        expected_request_nonce: Option<&str>,
        response: &Value,
    ) -> Result<ServiceAgentSignature, GatewayError> {
        let signature_value = service_agent_signature_value(response).ok_or_else(|| {
            GatewayError::Rejected(
                "callee response is missing Wattetheria Service Agent signature metadata"
                    .to_owned(),
            )
        })?;
        let signature: ServiceAgentSignature = match signature_value {
            Value::String(signature) => serde_json::from_str(signature),
            value => serde_json::from_value(value.clone()),
        }
        .map_err(|error| {
            GatewayError::Rejected(format!("callee service signature is invalid: {error}"))
        })?;
        if signature.protocol != SERVICE_AGENT_SIGNATURE_PROTOCOL {
            return Err(GatewayError::Rejected(
                "callee service signature protocol is unsupported".to_owned(),
            ));
        }
        if signature.service_did != record.service_did {
            return Err(GatewayError::Rejected(
                "callee service signature DID does not match the published Service Agent"
                    .to_owned(),
            ));
        }
        if signature.agent_id != record.agent_id {
            return Err(GatewayError::Rejected(
                "callee service signature agent_id does not match the published Service Agent"
                    .to_owned(),
            ));
        }
        if let Some(expected) = expected_request_digest
            && signature.request_digest != expected
        {
            return Err(GatewayError::Rejected(
                "callee service signature request digest does not match the invocation".to_owned(),
            ));
        }
        if signature.request_nonce.as_deref() != expected_request_nonce {
            return Err(GatewayError::Rejected(
                "callee service signature request nonce does not match the invocation".to_owned(),
            ));
        }
        if signature.nonce.trim().is_empty() {
            return Err(GatewayError::Rejected(
                "callee service signature nonce is required".to_owned(),
            ));
        }
        let issued_at_ms = i64::try_from(signature.issued_at_ms).map_err(|_| {
            GatewayError::Rejected("callee service signature timestamp is invalid".to_owned())
        })?;
        if (Utc::now().timestamp_millis() - issued_at_ms).abs() > MAX_CLOCK_SKEW_MS {
            return Err(GatewayError::Rejected(
                "callee service signature timestamp is outside the accepted window".to_owned(),
            ));
        }
        let result = unsigned_a2a_result(response);
        if signature.result_digest != jcs_sha256_digest(&result)? {
            return Err(GatewayError::Rejected(
                "callee service signature result digest does not match the response".to_owned(),
            ));
        }
        let public_key = self.cached_public_key(record, &signature.verification_method)?;
        let signature_bytes = STANDARD.decode(&signature.signature).map_err(|_| {
            GatewayError::Rejected("invalid Service Agent signature encoding".to_owned())
        })?;
        let signature_bytes: [u8; 64] = signature_bytes.try_into().map_err(|_| {
            GatewayError::Rejected("invalid Service Agent signature length".to_owned())
        })?;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| GatewayError::Rejected("invalid Service Agent public key".to_owned()))?;
        let payload = serde_jcs::to_vec(&build_service_agent_signature_payload(&signature))
            .map_err(|error| {
                GatewayError::Execution(format!(
                    "canonicalize Service Agent signature payload failed: {error}"
                ))
            })?;
        verifying_key
            .verify(&payload, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| {
                GatewayError::Rejected(
                    "Service Agent response signature does not verify".to_owned(),
                )
            })?;
        self.record_response_nonce(&signature)?;
        Ok(signature)
    }

    fn record_response_nonce(&self, signature: &ServiceAgentSignature) -> Result<(), GatewayError> {
        let now = Instant::now();
        let cache_key = format!("{}:{}", signature.service_did, signature.nonce);
        let mut cache = self.response_nonce_cache.lock().map_err(|_| {
            GatewayError::Execution("Service Agent response nonce cache lock poisoned".to_owned())
        })?;
        cache.retain(|_, expires_at| *expires_at > now);
        if cache.contains_key(&cache_key) {
            return Err(GatewayError::Rejected(
                "Service Agent response nonce has already been used; refusing replay".to_owned(),
            ));
        }
        if cache.len() >= RESPONSE_NONCE_CACHE_MAX_ENTRIES {
            return Err(GatewayError::Execution(
                "Service Agent response nonce cache is at capacity; retry through another Gateway instance"
                    .to_owned(),
            ));
        }
        cache.insert(cache_key, now + RESPONSE_NONCE_CACHE_TTL);
        Ok(())
    }

    fn cached_public_key(
        &self,
        record: &PublishedAgentRecord,
        verification_method: &str,
    ) -> Result<[u8; 32], GatewayError> {
        let cache_key = format!("{}:{verification_method}", record.service_did);
        let now = Instant::now();
        if let Some(public_key) = self
            .public_key_cache
            .lock()
            .map_err(|_| {
                GatewayError::Execution("Service Agent key cache lock poisoned".to_owned())
            })?
            .get(&cache_key)
            .filter(|cached| cached.expires_at > now)
            .map(|cached| cached.public_key)
        {
            return Ok(public_key);
        }

        let public_key = parse_public_key(record, verification_method)?;
        let mut cache = self.public_key_cache.lock().map_err(|_| {
            GatewayError::Execution("Service Agent key cache lock poisoned".to_owned())
        })?;
        cache.retain(|_, cached| cached.expires_at > now);
        if cache.len() >= PUBLIC_KEY_CACHE_MAX_ENTRIES && !cache.contains_key(&cache_key) {
            let oldest = cache
                .iter()
                .min_by_key(|(_, cached)| cached.expires_at)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                cache.remove(&oldest);
            }
        }
        cache.insert(
            cache_key,
            CachedPublicKey {
                public_key,
                expires_at: now + PUBLIC_KEY_CACHE_TTL,
            },
        );
        Ok(public_key)
    }
}

fn service_agent_signature_value(response: &Value) -> Option<&Value> {
    response
        .pointer("/result/task/metadata/wattetheriaServiceAgentSignature")
        .or_else(|| response.pointer("/result/message/metadata/wattetheriaServiceAgentSignature"))
        .or_else(|| {
            response.pointer("/result/statusUpdate/metadata/wattetheriaServiceAgentSignature")
        })
        .or_else(|| {
            response.pointer("/result/artifactUpdate/metadata/wattetheriaServiceAgentSignature")
        })
        .or_else(|| response.pointer("/result/metadata/wattetheriaServiceAgentSignature"))
        .or_else(|| response.pointer("/extensions/service_agent_signature"))
}

fn unsigned_a2a_result(response: &Value) -> Value {
    let mut result = response.get("result").cloned().unwrap_or(Value::Null);
    for payload_name in ["task", "message", "statusUpdate", "artifactUpdate"] {
        let Some(payload) = result.get_mut(payload_name).and_then(Value::as_object_mut) else {
            continue;
        };
        let Some(metadata) = payload.get_mut("metadata").and_then(Value::as_object_mut) else {
            continue;
        };
        metadata.remove("wattetheriaServiceAgentSignature");
        if metadata.is_empty() {
            payload.remove("metadata");
        }
    }
    let remove_root_metadata = result
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
        .is_some_and(|metadata| {
            metadata.remove("wattetheriaServiceAgentSignature");
            metadata.is_empty()
        });
    if remove_root_metadata && let Some(object) = result.as_object_mut() {
        object.remove("metadata");
    }
    result
}

fn parse_public_key(
    record: &PublishedAgentRecord,
    verification_method: &str,
) -> Result<[u8; 32], GatewayError> {
    let did = Did::parse(&record.service_did).map_err(|error| {
        GatewayError::Rejected(format!(
            "published Service Agent did:key is invalid: {error}"
        ))
    })?;
    let did_key = DidKey::from_did(did).map_err(|error| {
        GatewayError::Rejected(format!(
            "published Service Agent identity must use did:key: {error}"
        ))
    })?;
    let expected_verification_method = format!("{}#{}", did_key.did, did_key.public_key_multibase);
    if verification_method != expected_verification_method {
        return Err(GatewayError::Rejected(
            "Service Agent response references the wrong did:key verification method".to_owned(),
        ));
    }
    match did_key.decode_public_key().map_err(|error| {
        GatewayError::Rejected(format!(
            "Service Agent did:key public key is invalid: {error}"
        ))
    })? {
        DidKeyPublicKey::Ed25519(bytes) => Ok(bytes),
        _ => Err(GatewayError::Rejected(
            "Service Agent did:key must use Ed25519".to_owned(),
        )),
    }
}

fn jcs_sha256_digest(value: &Value) -> Result<String, GatewayError> {
    let bytes = serde_jcs::to_vec(value).map_err(|error| {
        GatewayError::Execution(format!("canonicalize Service Agent value failed: {error}"))
    })?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service_did() -> String {
        format!(
            "did:key:z{}",
            bs58::encode([[0xed, 0x01].as_slice(), &[24u8; 32]].concat()).into_string()
        )
    }

    fn published_agent(service_did: &str) -> PublishedAgentRecord {
        serde_json::from_value(serde_json::json!({
            "agent_id": "ride",
            "provider_id": "provider",
            "service_did": service_did,
            "version": "1.0.0",
            "status": "approved",
            "agent_card": {
                "name": "Ride",
                "description": "Ride agent",
                "url": "https://agent.example.com/a2a",
                "preferredTransport": "JSONRPC",
                "protocolVersion": "1.0",
                "supportsTask": false,
                "skills": []
            },
            "deployment": {
                "runtime": "wattetheria_adapter",
                "endpoint": {
                    "url": "https://agent.example.com/a2a",
                    "protocol_binding": "JSONRPC",
                    "protocol_version": "1.0",
                    "interaction_protocol": "a2a_v1"
                }
            },
            "review": {"risk_level": "low"},
            "approved_at": "2026-07-20T00:00:00Z",
            "updated_at": "2026-07-20T00:00:00Z",
            "reviewed_by": "test"
        }))
        .unwrap()
    }

    #[test]
    fn did_key_verification_method_must_use_standard_fingerprint() {
        let service_did = service_did();
        let fingerprint = service_did.strip_prefix("did:key:").unwrap();
        let record = published_agent(&service_did);

        assert!(parse_public_key(&record, &format!("{service_did}#{fingerprint}")).is_ok());
        assert!(parse_public_key(&record, &format!("{service_did}#signing-key")).is_err());
    }

    #[test]
    fn response_nonce_cache_rejects_replay() {
        let verifier = ServiceAgentVerifier::default();
        let service_did = service_did();
        let fingerprint = service_did
            .strip_prefix("did:key:")
            .expect("test service DID should use did:key");
        let signature = ServiceAgentSignature {
            protocol: SERVICE_AGENT_SIGNATURE_PROTOCOL.to_owned(),
            service_did: service_did.clone(),
            agent_id: "ride".to_owned(),
            verification_method: format!("{service_did}#{fingerprint}"),
            request_digest: "sha256:request".to_owned(),
            request_nonce: Some("request-nonce".to_owned()),
            result_digest: "sha256:result".to_owned(),
            nonce: "response-nonce".to_owned(),
            issued_at_ms: 1,
            signature: "unused".to_owned(),
        };

        verifier.record_response_nonce(&signature).unwrap();
        let error = verifier.record_response_nonce(&signature).unwrap_err();
        assert!(error.to_string().contains("refusing replay"));
    }
}
