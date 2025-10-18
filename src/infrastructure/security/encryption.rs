use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use rand::RngCore;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;

const NONCE_LEN: usize = 12;

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("MFA encryption key is not configured")]
    MissingKey,
    #[error("MFA encryption key must be provided as base64-encoded 256-bit key")]
    InvalidKey,
    #[error("encryption operation failed")]
    Encrypt,
    #[error("decryption operation failed")]
    Decrypt,
}

fn key_bytes() -> Result<Vec<u8>, EncryptionError> {
    let key_b64 = std::env::var("MFA_ENCRYPTION_KEY").map_err(|_| EncryptionError::MissingKey)?;
    let bytes = STANDARD_NO_PAD
        .decode(key_b64.trim().as_bytes())
        .map_err(|_| EncryptionError::InvalidKey)?;

    if bytes.len() != 32 {
        return Err(EncryptionError::InvalidKey);
    }

    Ok(bytes)
}

fn sealing_key() -> Result<LessSafeKey, EncryptionError> {
    let key = key_bytes()?;
    let unbound =
        UnboundKey::new(&aead::AES_256_GCM, &key).map_err(|_| EncryptionError::InvalidKey)?;
    Ok(LessSafeKey::new(unbound))
}

pub fn encrypt_secret(plaintext: &[u8]) -> Result<(String, String), EncryptionError> {
    let sealing_key = sealing_key()?;
    let mut in_out = plaintext.to_vec();
    let tag_len = aead::AES_256_GCM.tag_len();
    in_out.resize(in_out.len() + tag_len, 0);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| EncryptionError::Encrypt)?;

    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    sealing_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| EncryptionError::Encrypt)?;

    Ok((
        STANDARD_NO_PAD.encode(in_out),
        STANDARD_NO_PAD.encode(nonce_bytes),
    ))
}

pub fn decrypt_secret(ciphertext_b64: &str, nonce_b64: &str) -> Result<Vec<u8>, EncryptionError> {
    let opening_key = sealing_key()?;
    let mut ciphertext = STANDARD_NO_PAD
        .decode(ciphertext_b64.as_bytes())
        .map_err(|_| EncryptionError::Decrypt)?;
    let nonce_bytes = STANDARD_NO_PAD
        .decode(nonce_b64.as_bytes())
        .map_err(|_| EncryptionError::Decrypt)?;

    if nonce_bytes.len() != NONCE_LEN {
        return Err(EncryptionError::Decrypt);
    }

    let nonce =
        Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| EncryptionError::Decrypt)?;
    let plaintext = opening_key
        .open_in_place(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|_| EncryptionError::Decrypt)?;

    Ok(plaintext.to_vec())
}

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("system RNG should be available");
    bytes
}

pub fn generate_secure_string(len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = (rng.next_u32() as usize) % ALPHABET.len();
            ALPHABET[idx] as char
        })
        .collect()
}
