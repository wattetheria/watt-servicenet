use crate::RegistryError;
use watt_did::{Did, DidKey, DidKeyPublicKey};

pub(crate) fn validate_service_did(
    service_did: &str,
    provider_did: &str,
) -> Result<(), RegistryError> {
    let did = Did::parse(service_did).map_err(|error| {
        RegistryError::InvalidAgent(format!("service_did must be a valid DID: {error}"))
    })?;
    let did_key = DidKey::from_did(did).map_err(|error| {
        RegistryError::InvalidAgent(format!("service_did must use a valid did:key: {error}"))
    })?;
    if service_did == provider_did {
        return Err(RegistryError::InvalidAgent(
            "Service Agent service_did must be independent from provider_did".to_owned(),
        ));
    }
    match did_key.decode_public_key().map_err(|error| {
        RegistryError::InvalidAgent(format!("service_did public key is invalid: {error}"))
    })? {
        DidKeyPublicKey::Ed25519(_) => Ok(()),
        _ => Err(RegistryError::InvalidAgent(
            "Service Agent service_did must resolve to an Ed25519 verification key".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ed25519_did_key(byte: u8) -> String {
        format!(
            "did:key:z{}",
            bs58::encode([[0xed, 0x01].as_slice(), &[byte; 32]].concat()).into_string()
        )
    }

    #[test]
    fn accepts_independent_ed25519_did_key() {
        validate_service_did(&ed25519_did_key(2), &ed25519_did_key(1)).unwrap();
    }

    #[test]
    fn rejects_provider_did_reuse() {
        let provider_did = ed25519_did_key(1);
        let error = validate_service_did(&provider_did, &provider_did).unwrap_err();
        assert!(error.to_string().contains("independent"));
    }

    #[test]
    fn rejects_did_web() {
        let error = validate_service_did("did:web:example.com:agents:ride", &ed25519_did_key(1))
            .unwrap_err();
        assert!(error.to_string().contains("did:key"));
    }
}
