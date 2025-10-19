use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use serde_json::json;
use thiserror::Error;

use crate::domain::models::vault_item::VaultItemPayload;
use crate::infrastructure::security::crypto::{self, VaultItemCiphertext};

#[derive(Debug, Error)]
pub enum VaultDataError {
    #[error("vault key header is required")]
    MissingKey,
    #[error("vault key must be provided as base64-encoded 256-bit key")]
    InvalidKey,
    #[error("unable to serialize vault item payload")]
    Serialize(#[source] serde_json::Error),
    #[error("unable to deserialize vault item payload")]
    Deserialize(#[source] serde_json::Error),
    #[error("encryption error: {0}")]
    Crypto(#[from] crypto::CryptoError),
}

impl VaultDataError {
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "status": "fail",
            "message": self.to_string(),
        })
    }
}

fn decode_vault_key(key_b64: &str) -> Result<Vec<u8>, VaultDataError> {
    let decoded = STANDARD_NO_PAD
        .decode(key_b64.trim().as_bytes())
        .map_err(|_| VaultDataError::InvalidKey)?;

    if decoded.len() != 32 {
        return Err(VaultDataError::InvalidKey);
    }

    Ok(decoded)
}

pub fn encrypt_payload(
    vault_key_b64: &str,
    payload: &VaultItemPayload,
) -> Result<VaultItemCiphertext, VaultDataError> {
    let vault_key = decode_vault_key(vault_key_b64)?;
    let serialized = serde_json::to_vec(payload).map_err(VaultDataError::Serialize)?;

    Ok(crypto::encrypt_vault_item_payload(&vault_key, &serialized)?)
}

pub fn decrypt_payload(
    vault_key_b64: &str,
    ciphertext: &VaultItemCiphertext,
) -> Result<VaultItemPayload, VaultDataError> {
    let vault_key = decode_vault_key(vault_key_b64)?;
    let decrypted = crypto::decrypt_vault_item_payload(&vault_key, ciphertext)?;
    let payload = serde_json::from_slice(&decrypted).map_err(VaultDataError::Deserialize)?;

    Ok(payload)
}
