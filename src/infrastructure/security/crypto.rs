use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("vault master key is not configured")]
    MissingMasterKey,
    #[error("vault master key must be provided as base64-encoded 256-bit key")]
    InvalidMasterKey,
    #[error("vault key must be 256 bits")]
    InvalidVaultKey,
    #[error("failed to generate secure random bytes")]
    Randomness,
    #[error("encryption operation failed")]
    Encrypt,
    #[error("decryption operation failed")]
    Decrypt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedVaultKey {
    pub ciphertext: String,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultItemCiphertext {
    pub ciphertext: String,
    pub nonce: String,
}

pub fn generate_vault_key() -> Result<Vec<u8>, CryptoError> {
    let mut key = vec![0u8; KEY_LEN];
    SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| CryptoError::Randomness)?;
    Ok(key)
}

pub fn wrap_vault_key(vault_key: &[u8]) -> Result<WrappedVaultKey, CryptoError> {
    if vault_key.len() != KEY_LEN {
        return Err(CryptoError::InvalidVaultKey);
    }

    let master_key = master_sealing_key()?;
    let nonce_bytes = generate_nonce()?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = vault_key.to_vec();
    in_out.reserve(aead::AES_256_GCM.tag_len());

    master_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::Encrypt)?;

    Ok(WrappedVaultKey {
        ciphertext: STANDARD_NO_PAD.encode(&in_out),
        nonce: STANDARD_NO_PAD.encode(nonce_bytes),
    })
}

pub fn unwrap_vault_key(wrapped: &WrappedVaultKey) -> Result<Vec<u8>, CryptoError> {
    let master_key = master_sealing_key()?;
    let mut ciphertext = STANDARD_NO_PAD
        .decode(wrapped.ciphertext.as_bytes())
        .map_err(|_| CryptoError::Decrypt)?;
    let nonce_bytes = STANDARD_NO_PAD
        .decode(wrapped.nonce.as_bytes())
        .map_err(|_| CryptoError::Decrypt)?;

    if nonce_bytes.len() != NONCE_LEN {
        return Err(CryptoError::Decrypt);
    }

    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| CryptoError::Decrypt)?;
    let plaintext = master_key
        .open_in_place(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|_| CryptoError::Decrypt)?;

    if plaintext.len() != KEY_LEN {
        return Err(CryptoError::InvalidVaultKey);
    }

    Ok(plaintext.to_vec())
}

pub fn encrypt_vault_item_payload(
    vault_key: &[u8],
    payload: &[u8],
) -> Result<VaultItemCiphertext, CryptoError> {
    if vault_key.len() != KEY_LEN {
        return Err(CryptoError::InvalidVaultKey);
    }

    let vault_key = vault_sealing_key(vault_key)?;
    let nonce_bytes = generate_nonce()?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = payload.to_vec();
    in_out.reserve(aead::AES_256_GCM.tag_len());

    vault_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::Encrypt)?;

    Ok(VaultItemCiphertext {
        ciphertext: STANDARD_NO_PAD.encode(&in_out),
        nonce: STANDARD_NO_PAD.encode(nonce_bytes),
    })
}

pub fn decrypt_vault_item_payload(
    vault_key: &[u8],
    encrypted: &VaultItemCiphertext,
) -> Result<Vec<u8>, CryptoError> {
    if vault_key.len() != KEY_LEN {
        return Err(CryptoError::InvalidVaultKey);
    }

    let vault_key = vault_sealing_key(vault_key)?;
    let mut ciphertext = STANDARD_NO_PAD
        .decode(encrypted.ciphertext.as_bytes())
        .map_err(|_| CryptoError::Decrypt)?;
    let nonce_bytes = STANDARD_NO_PAD
        .decode(encrypted.nonce.as_bytes())
        .map_err(|_| CryptoError::Decrypt)?;

    if nonce_bytes.len() != NONCE_LEN {
        return Err(CryptoError::Decrypt);
    }

    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| CryptoError::Decrypt)?;
    let plaintext = vault_key
        .open_in_place(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|_| CryptoError::Decrypt)?;

    Ok(plaintext.to_vec())
}

fn master_sealing_key() -> Result<LessSafeKey, CryptoError> {
    let master_key = master_key_bytes()?;
    create_sealing_key(&master_key).map_err(|_| CryptoError::InvalidMasterKey)
}

fn master_key_bytes() -> Result<Vec<u8>, CryptoError> {
    let key_b64 = std::env::var("VAULT_MASTER_KEY").map_err(|_| CryptoError::MissingMasterKey)?;
    let key = STANDARD_NO_PAD
        .decode(key_b64.trim().as_bytes())
        .map_err(|_| CryptoError::InvalidMasterKey)?;

    if key.len() != KEY_LEN {
        return Err(CryptoError::InvalidMasterKey);
    }

    Ok(key)
}

fn vault_sealing_key(vault_key: &[u8]) -> Result<LessSafeKey, CryptoError> {
    create_sealing_key(vault_key).map_err(|_| CryptoError::InvalidVaultKey)
}

fn create_sealing_key(key: &[u8]) -> Result<LessSafeKey, ring::error::Unspecified> {
    let unbound = UnboundKey::new(&aead::AES_256_GCM, key)?;
    Ok(LessSafeKey::new(unbound))
}

fn generate_nonce() -> Result<[u8; NONCE_LEN], CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| CryptoError::Randomness)?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_master_key_for_tests() {
        let key = vec![42u8; KEY_LEN];
        let key_b64 = STANDARD_NO_PAD.encode(key);
        // `std::env::set_var` is currently an unsafe fn under the strict provenance
        // configuration used by the project. We scope the call to this helper to a
        // single unsafe block so that the rest of the test code can remain safe.
        unsafe {
            std::env::set_var("VAULT_MASTER_KEY", key_b64);
        }
    }

    #[test]
    fn wrap_and_unwrap_vault_key_round_trip() {
        set_master_key_for_tests();

        let vault_key = generate_vault_key().expect("vault key generation should succeed");
        let wrapped = wrap_vault_key(&vault_key).expect("wrapping should succeed");
        let unwrapped = unwrap_vault_key(&wrapped).expect("unwrapping should succeed");

        assert_eq!(vault_key, unwrapped);
    }

    #[test]
    fn encrypt_and_decrypt_payload_round_trip() {
        set_master_key_for_tests();

        let vault_key = generate_vault_key().expect("vault key generation should succeed");
        let payload = b"super secret payload";
        let encrypted = encrypt_vault_item_payload(&vault_key, payload)
            .expect("payload encryption should succeed");
        let decrypted = decrypt_vault_item_payload(&vault_key, &encrypted)
            .expect("payload decryption should succeed");

        assert_eq!(payload.to_vec(), decrypted);
    }
}
