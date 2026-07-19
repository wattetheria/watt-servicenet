use crate::RegistryError;
use reqwest::{Url, redirect::Policy};
use serde_json::Value;
use watt_did::{Did, DidDocument, DidWeb, JwkPublicKey};

const MAX_DID_DOCUMENT_BYTES: usize = 512 * 1024;

pub(crate) fn validate_service_did_document(
    service_did: &str,
    agent_id: &str,
    document: &Value,
) -> Result<(), RegistryError> {
    let did = Did::parse(service_did).map_err(|error| {
        RegistryError::InvalidAgent(format!("service_did must be a valid DID: {error}"))
    })?;
    if did.method() != "web" {
        return Err(RegistryError::InvalidAgent(
            "service_did must use did:web".to_owned(),
        ));
    }
    let did_web = DidWeb::from_did(did.clone()).map_err(|error| {
        RegistryError::InvalidAgent(format!("service_did must be a valid did:web: {error}"))
    })?;
    if did_web.path_segments != ["agents", agent_id] {
        return Err(RegistryError::InvalidAgent(
            "service_did path must use /agents/{agent_id}".to_owned(),
        ));
    }
    let document: DidDocument = serde_json::from_value(document.clone()).map_err(|error| {
        RegistryError::InvalidAgent(format!("agent_card.didDocument is invalid: {error}"))
    })?;
    document.validate().map_err(|error| {
        RegistryError::InvalidAgent(format!("agent_card.didDocument is invalid: {error}"))
    })?;
    if document.id != did {
        return Err(RegistryError::InvalidAgent(
            "agent_card.didDocument.id must match service_did".to_owned(),
        ));
    }
    let reference = document.assertion_method.first().ok_or_else(|| {
        RegistryError::InvalidAgent(
            "agent_card.didDocument.assertionMethod must include a signing key".to_owned(),
        )
    })?;
    let method = document
        .verification_method_by_reference(reference)
        .ok_or_else(|| {
            RegistryError::InvalidAgent(
                "agent_card.didDocument assertionMethod key was not found".to_owned(),
            )
        })?;
    let Some(jwk) = method.public_key_jwk_model().map_err(|error| {
        RegistryError::InvalidAgent(format!("Service Agent signing JWK is invalid: {error}"))
    })?
    else {
        return Err(RegistryError::InvalidAgent(
            "Service Agent signing key must use publicKeyJwk".to_owned(),
        ));
    };
    if !matches!(
        jwk.to_public_key().map_err(|error| {
            RegistryError::InvalidAgent(format!("Service Agent signing JWK is invalid: {error}"))
        })?,
        JwkPublicKey::Ed25519(_)
    ) {
        return Err(RegistryError::InvalidAgent(
            "Service Agent signing key must use Ed25519".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) async fn verify_service_did_domain_control(
    service_did: &str,
    agent_id: &str,
    deployment_url: &str,
    submitted_document: &Value,
) -> Result<(), RegistryError> {
    let did = Did::parse(service_did).map_err(|error| {
        RegistryError::InvalidAgent(format!("service_did must be a valid DID: {error}"))
    })?;
    let did_web = DidWeb::from_did(did).map_err(|error| {
        RegistryError::InvalidAgent(format!("service_did must be a valid did:web: {error}"))
    })?;

    // RFC 2606 example domains are unclaimable and are used by deterministic fixtures.
    if is_reserved_example_host(&did_web.host) {
        return Ok(());
    }

    let endpoint = Url::parse(deployment_url).map_err(|error| {
        RegistryError::InvalidAgent(format!("deployment endpoint URL is invalid: {error}"))
    })?;
    let endpoint_authority = endpoint_authority(&endpoint)?;
    if !did_web.host.eq_ignore_ascii_case(&endpoint_authority) {
        return Err(RegistryError::InvalidAgent(format!(
            "service_did authority `{}` must match deployment endpoint authority `{endpoint_authority}`",
            did_web.host
        )));
    }
    let resolution_url = did_web.to_url();
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(Policy::none())
        .build()
        .map_err(|error| {
            RegistryError::InvalidAgent(format!("build did:web resolver failed: {error}"))
        })?
        .get(&resolution_url)
        .header(
            reqwest::header::ACCEPT,
            "application/did+json, application/json",
        )
        .send()
        .await
        .map_err(|error| {
            RegistryError::InvalidAgent(format!(
                "resolve Service Agent did:web document from {resolution_url} failed: {error}"
            ))
        })?;
    if !response.status().is_success() {
        return Err(RegistryError::InvalidAgent(format!(
            "resolve Service Agent did:web document from {resolution_url} returned {}",
            response.status()
        )));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_DID_DOCUMENT_BYTES as u64)
    {
        return Err(RegistryError::InvalidAgent(
            "resolved Service Agent DID document is too large".to_owned(),
        ));
    }
    let bytes = response.bytes().await.map_err(|error| {
        RegistryError::InvalidAgent(format!(
            "read Service Agent did:web document from {resolution_url} failed: {error}"
        ))
    })?;
    if bytes.len() > MAX_DID_DOCUMENT_BYTES {
        return Err(RegistryError::InvalidAgent(
            "resolved Service Agent DID document is too large".to_owned(),
        ));
    }
    let resolved_value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        RegistryError::InvalidAgent(format!(
            "resolved Service Agent DID document is invalid JSON: {error}"
        ))
    })?;
    validate_service_did_document(service_did, agent_id, &resolved_value)?;

    let submitted = serde_jcs::to_vec(submitted_document).map_err(|error| {
        RegistryError::InvalidAgent(format!(
            "canonicalize submitted Service Agent DID document failed: {error}"
        ))
    })?;
    let resolved = serde_jcs::to_vec(&resolved_value).map_err(|error| {
        RegistryError::InvalidAgent(format!(
            "canonicalize resolved Service Agent DID document failed: {error}"
        ))
    })?;
    if resolved != submitted {
        return Err(RegistryError::InvalidAgent(
            "resolved Service Agent DID document does not match the submitted document".to_owned(),
        ));
    }
    Ok(())
}

fn endpoint_authority(endpoint: &Url) -> Result<String, RegistryError> {
    let host = endpoint.host_str().ok_or_else(|| {
        RegistryError::InvalidAgent("deployment endpoint URL has no host".to_owned())
    })?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_ascii_lowercase()
    };
    Ok(endpoint
        .port()
        .map_or(host.clone(), |port| format!("{host}:{port}")))
}

fn is_reserved_example_host(authority: &str) -> bool {
    let host = authority
        .split_once(':')
        .map_or(authority, |(host, _)| host)
        .trim_end_matches('.');
    host.eq_ignore_ascii_case("example.com") || host.to_ascii_lowercase().ends_with(".example.com")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[tokio::test]
    async fn domain_control_resolves_the_public_did_document() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let did_web = DidWeb::from_parts(authority.clone(), &["agents", "ride-agent"]).unwrap();
        let service_did = did_web.did.to_string();
        let verification_method = format!("{service_did}#signing-key");
        let signing_key = SigningKey::from_bytes(&[42; 32]);
        let document = json!({
            "id": service_did,
            "verificationMethod": [{
                "id": verification_method,
                "type": "JsonWebKey2020",
                "controller": service_did,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes()),
                    "alg": "EdDSA",
                }
            }],
            "authentication": [verification_method],
            "assertionMethod": [verification_method],
        });
        let body = serde_json::to_vec(&document).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/did+json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(&body).await.unwrap();
        });

        verify_service_did_domain_control(
            &service_did,
            "ride-agent",
            &format!("http://{authority}/a2a/ride-agent"),
            &document,
        )
        .await
        .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn domain_control_rejects_endpoint_authority_mismatch_before_resolution() {
        let did_web = DidWeb::from_parts("agent.example.net", &["agents", "ride-agent"]).unwrap();
        let error = verify_service_did_domain_control(
            &did_web.did.to_string(),
            "ride-agent",
            "https://other.example.net/a2a",
            &json!({}),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("must match deployment endpoint"));
    }
}
