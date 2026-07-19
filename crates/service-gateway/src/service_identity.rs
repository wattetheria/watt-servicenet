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
use watt_did::{DidDocument, JwkPublicKey};
use watt_servicenet_protocol::{
    PublishedAgentRecord, SERVICE_AGENT_SIGNATURE_PROTOCOL, ServiceAgentSignature,
    build_service_agent_signature_payload,
};

const MAX_CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;
const PUBLIC_KEY_CACHE_TTL: Duration = Duration::from_mins(5);
const PUBLIC_KEY_CACHE_MAX_ENTRIES: usize = 4_096;
const RESPONSE_NONCE_CACHE_TTL: Duration = Duration::from_mins(5);
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
        let signature_value = response
            .pointer("/extensions/service_agent_signature")
            .ok_or_else(|| {
                GatewayError::Rejected(
                    "callee response is missing extensions.service_agent_signature".to_owned(),
                )
            })?;
        let signature: ServiceAgentSignature = serde_json::from_value(signature_value.clone())
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
        let result = response.get("result").cloned().unwrap_or(Value::Null);
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
        let document = did_document_value(record)?;
        let cache_key = format!(
            "{}:{verification_method}:{}",
            record.service_did,
            jcs_sha256_digest(document)?
        );
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

fn parse_public_key(
    record: &PublishedAgentRecord,
    verification_method: &str,
) -> Result<[u8; 32], GatewayError> {
    let document: DidDocument = serde_json::from_value(did_document_value(record)?.clone())
        .map_err(|error| {
            GatewayError::Rejected(format!(
                "published Service Agent DID document is invalid: {error}"
            ))
        })?;
    if document.id.to_string() != record.service_did {
        return Err(GatewayError::Rejected(
            "published Service Agent DID document id does not match service_did".to_owned(),
        ));
    }
    let method = document
        .verification_method_by_reference(verification_method)
        .ok_or_else(|| {
            GatewayError::Rejected(
                "Service Agent response references an unknown verification method".to_owned(),
            )
        })?;
    if !document.has_relationship(
        watt_did::VerificationRelationship::AssertionMethod,
        verification_method,
    ) {
        return Err(GatewayError::Rejected(
            "Service Agent response key is not authorized for assertionMethod".to_owned(),
        ));
    }
    let jwk = method
        .public_key_jwk_model()
        .map_err(|error| {
            GatewayError::Rejected(format!("Service Agent public JWK is invalid: {error}"))
        })?
        .ok_or_else(|| {
            GatewayError::Rejected("Service Agent response key must use publicKeyJwk".to_owned())
        })?;
    match jwk.to_public_key().map_err(|error| {
        GatewayError::Rejected(format!("Service Agent public JWK is invalid: {error}"))
    })? {
        JwkPublicKey::Ed25519(bytes) => Ok(bytes),
        _ => Err(GatewayError::Rejected(
            "Service Agent response key must use Ed25519".to_owned(),
        )),
    }
}

fn did_document_value(record: &PublishedAgentRecord) -> Result<&Value, GatewayError> {
    record
        .agent_card
        .get("didDocument")
        .or_else(|| record.agent_card.get("did_document"))
        .ok_or_else(|| {
            GatewayError::Rejected("published Service Agent has no DID document".to_owned())
        })
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

    #[test]
    fn response_nonce_cache_rejects_replay() {
        let verifier = ServiceAgentVerifier::default();
        let signature = ServiceAgentSignature {
            protocol: SERVICE_AGENT_SIGNATURE_PROTOCOL.to_owned(),
            service_did: "did:web:agent.example.com:agents:ride".to_owned(),
            agent_id: "ride".to_owned(),
            verification_method: "did:web:agent.example.com:agents:ride#signing-key".to_owned(),
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
