use std::collections::HashMap;

use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use data_encoding::BASE32_NOPAD;
use once_cell::sync::Lazy;
use qrcode::{QrCode, render::svg};
use ring::hmac;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    application::services::auth::{hash_password, verify_password},
    domain::models::mfa::{MfaDevice, MfaRecoveryCode},
    infrastructure::security::encryption::{
        EncryptionError, decrypt_secret, encrypt_secret, generate_random_bytes,
        generate_secure_string,
    },
};

static CHALLENGES: Lazy<RwLock<HashMap<String, MfaChallenge>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

const DEFAULT_ISSUER: &str = "LockMate";
const ENROLLMENT_DURATION_MINUTES: i64 = 15;
const CHALLENGE_DURATION_MINUTES: i64 = 5;
const DEFAULT_RECOVERY_CODES: usize = 10;
const RECOVERY_CODE_LENGTH: usize = 12;
const MAX_FAILED_ATTEMPTS: i32 = 5;
const LOCKOUT_MINUTES: i64 = 5;
const SECRET_MIN_BYTES: usize = 20; // 160 bits

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    pub fn from_env() -> Self {
        match std::env::var("MFA_TOTP_ALGORITHM")
            .unwrap_or_else(|_| "SHA1".to_string())
            .to_uppercase()
            .as_str()
        {
            "SHA256" => TotpAlgorithm::Sha256,
            "SHA512" => TotpAlgorithm::Sha512,
            _ => TotpAlgorithm::Sha1,
        }
    }

    fn algorithm(&self) -> &'static hmac::Algorithm {
        match self {
            TotpAlgorithm::Sha1 => &hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            TotpAlgorithm::Sha256 => &hmac::HMAC_SHA256,
            TotpAlgorithm::Sha512 => &hmac::HMAC_SHA512,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
            TotpAlgorithm::Sha512 => "SHA512",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TotpConfig {
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub step: u64,
    pub window: i32,
    pub issuer: String,
}

impl TotpConfig {
    pub fn load() -> Self {
        let digits = std::env::var("MFA_TOTP_DIGITS")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(6);

        let step = std::env::var("MFA_TOTP_STEP")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(30);

        let window = std::env::var("MFA_TOTP_WINDOW")
            .ok()
            .and_then(|value| value.parse::<i32>().ok())
            .unwrap_or(1);

        let issuer =
            std::env::var("MFA_TOTP_ISSUER").unwrap_or_else(|_| DEFAULT_ISSUER.to_string());

        Self {
            algorithm: TotpAlgorithm::from_env(),
            digits,
            step,
            window,
            issuer,
        }
    }
}

#[derive(Debug, Error)]
pub enum MfaError {
    #[error("{0}")]
    Validation(String),
    #[error("MFA device is locked until {0}")]
    LockedOut(DateTime<Utc>),
    #[error("replay detected for current time window")]
    Replay,
    #[error("an internal error occurred")]
    Internal,
    #[error("enrollment session has expired")]
    EnrollmentExpired,
    #[error("enrollment is not pending")]
    EnrollmentNotPending,
    #[error("no active MFA challenge")]
    ChallengeNotFound,
    #[error("MFA challenge has expired")]
    ChallengeExpired,
    #[error("encryption error: {0}")]
    Encryption(#[from] EncryptionError),
}

#[derive(Debug, Clone, Serialize)]
pub struct TotpProvisioning {
    pub uri: String,
    pub qr_code: String,
    pub secret: String,
}

#[derive(Debug, Clone)]
pub struct TotpVerification {
    pub matched_step: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MfaChallenge {
    pub id: String,
    pub user_id: i32,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl MfaChallenge {
    pub fn new(user_id: i32) -> Self {
        let created_at = Utc::now();
        let expires_at = created_at + Duration::minutes(CHALLENGE_DURATION_MINUTES);

        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            created_at,
            expires_at,
        }
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now > self.expires_at
    }
}

pub async fn create_challenge(user_id: i32) -> MfaChallenge {
    let challenge = MfaChallenge::new(user_id);
    let mut guard = CHALLENGES.write().await;
    guard.insert(challenge.id.clone(), challenge.clone());
    challenge
}

pub async fn consume_challenge(id: &str) -> Option<MfaChallenge> {
    let mut guard = CHALLENGES.write().await;
    guard.remove(id)
}

pub async fn get_challenge(id: &str) -> Option<MfaChallenge> {
    let guard = CHALLENGES.read().await;
    guard.get(id).cloned()
}

pub fn generate_totp_secret() -> Vec<u8> {
    generate_random_bytes(SECRET_MIN_BYTES)
}

pub fn encode_secret_base32(secret: &[u8]) -> String {
    BASE32_NOPAD.encode(secret)
}

pub fn build_otpauth_uri(label: &str, secret: &str, config: &TotpConfig) -> String {
    let encoded_label = urlencoding::encode(label);
    let issuer = urlencoding::encode(&config.issuer);
    format!(
        "otpauth://totp/{issuer}:{label}?secret={secret}&issuer={issuer}&algorithm={algorithm}&digits={digits}&period={period}",
        label = encoded_label,
        issuer = issuer,
        algorithm = config.algorithm.as_str(),
        digits = config.digits,
        period = config.step,
    )
}

pub fn generate_qr_code_png(data: &str) -> Result<String, MfaError> {
    let code = QrCode::new(data.as_bytes()).map_err(|_| MfaError::Internal)?;
    let svg = code.render::<svg::Color>().min_dimensions(256, 256).build();

    Ok(format!(
        "data:image/svg+xml;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(svg.as_bytes())
    ))
}

fn truncate(mut value: u32, digits: u32) -> u32 {
    let modulo = 10u32.pow(digits);
    value %= modulo;
    value
}

fn compute_totp(secret: &[u8], counter: u64, config: &TotpConfig) -> u32 {
    let key = hmac::Key::new(*config.algorithm.algorithm(), secret);
    let counter_bytes = counter.to_be_bytes();
    let signature = hmac::sign(&key, &counter_bytes);
    let bytes = signature.as_ref();
    let offset = (bytes[bytes.len() - 1] & 0xf) as usize;

    let slice = &bytes[offset..offset + 4];
    let mut binary = u32::from_be_bytes(slice.try_into().unwrap());
    binary &= 0x7FFF_FFFF;

    truncate(binary, config.digits)
}

pub fn expected_step(now: DateTime<Utc>, config: &TotpConfig) -> i64 {
    (now.timestamp() / config.step as i64) as i64
}

fn parse_code(code: &str, digits: u32) -> Result<u32, MfaError> {
    let trimmed = code.trim();
    if trimmed.len() != digits as usize {
        return Err(MfaError::Validation(format!(
            "Code must be {digits} digits long"
        )));
    }

    if !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Err(MfaError::Validation("Code must only contain digits".into()));
    }

    trimmed
        .parse::<u32>()
        .map_err(|_| MfaError::Validation("Invalid code".into()))
}

pub fn verify_totp_code(
    device: &mut MfaDevice,
    secret: &[u8],
    code: &str,
    now: DateTime<Utc>,
    config: &TotpConfig,
) -> Result<TotpVerification, MfaError> {
    if let Some(lockout_until) = device.lockout_until {
        if now < lockout_until {
            return Err(MfaError::LockedOut(lockout_until));
        }
    }

    let parsed_code = parse_code(code, config.digits)?;
    let base_step = expected_step(now, config);

    let mut matched: Option<i64> = None;
    for offset in -config.window..=config.window {
        let step = base_step + offset as i64;
        if step < 0 {
            continue;
        }
        let totp = compute_totp(secret, step as u64, config);
        if totp == parsed_code {
            matched = Some(step);
            break;
        }
    }

    match matched {
        Some(step) => {
            if device.last_used_step == Some(step) {
                return Err(MfaError::Replay);
            }

            device.last_used_step = Some(step);
            device.failed_attempts = 0;
            device.lockout_until = None;
            device.mark_updated();

            Ok(TotpVerification { matched_step: step })
        }
        None => {
            let mut attempts = device.failed_attempts + 1;
            let mut lockout_until = device.lockout_until;

            if attempts >= MAX_FAILED_ATTEMPTS {
                attempts = 0;
                lockout_until = Some(now + Duration::minutes(LOCKOUT_MINUTES));
            }

            device.failed_attempts = attempts;
            device.lockout_until = lockout_until;
            device.mark_updated();

            Err(MfaError::Validation("Invalid authentication code".into()))
        }
    }
}

pub fn verify_recovery_code(
    device: &mut MfaDevice,
    code: &str,
    now: DateTime<Utc>,
) -> Result<(), MfaError> {
    let trimmed = code.trim();
    if trimmed.len() < RECOVERY_CODE_LENGTH {
        return Err(MfaError::Validation("Recovery code is not valid".into()));
    }

    let mut matched_index: Option<usize> = None;
    for (idx, entry) in device.backup_codes.iter().enumerate() {
        if entry.is_used() {
            continue;
        }

        if verify_password(trimmed, &entry.code_hash).map_err(|_| MfaError::Internal)? {
            matched_index = Some(idx);
            break;
        }
    }

    match matched_index {
        Some(idx) => {
            if let Some(entry) = device.backup_codes.get_mut(idx) {
                entry.used_at = Some(now);
            }
            device.failed_attempts = 0;
            device.lockout_until = None;
            device.mark_updated();
            Ok(())
        }
        None => {
            let mut attempts = device.failed_attempts + 1;
            let mut lockout_until = device.lockout_until;
            if attempts >= MAX_FAILED_ATTEMPTS {
                attempts = 0;
                lockout_until = Some(now + Duration::minutes(LOCKOUT_MINUTES));
            }
            device.failed_attempts = attempts;
            device.lockout_until = lockout_until;
            device.mark_updated();

            Err(MfaError::Validation(
                "Recovery code is invalid or already used".into(),
            ))
        }
    }
}

pub fn generate_provisioning(
    label: &str,
    secret: &[u8],
    config: &TotpConfig,
) -> Result<TotpProvisioning, MfaError> {
    let secret_b32 = encode_secret_base32(secret);
    let uri = build_otpauth_uri(label, &secret_b32, config);
    let qr_code = generate_qr_code_png(&uri)?;

    Ok(TotpProvisioning {
        uri,
        qr_code,
        secret: secret_b32,
    })
}

pub fn encrypt_secret_for_storage(secret: &[u8]) -> Result<(String, String), MfaError> {
    encrypt_secret(secret).map_err(MfaError::from)
}

pub fn decrypt_device_secret(device: &MfaDevice) -> Result<Vec<u8>, MfaError> {
    decrypt_secret(&device.secret_ciphertext, &device.secret_nonce).map_err(MfaError::from)
}

pub fn enrollment_expiration() -> DateTime<Utc> {
    Utc::now() + Duration::minutes(ENROLLMENT_DURATION_MINUTES)
}

pub fn generate_recovery_codes() -> Result<(Vec<String>, Vec<MfaRecoveryCode>), MfaError> {
    let mut raw_codes = Vec::with_capacity(DEFAULT_RECOVERY_CODES);
    let mut hashed_codes = Vec::with_capacity(DEFAULT_RECOVERY_CODES);

    for _ in 0..DEFAULT_RECOVERY_CODES {
        let code = generate_secure_string(RECOVERY_CODE_LENGTH);
        let hash = hash_password(&code).map_err(|_| MfaError::Internal)?;
        raw_codes.push(code);
        hashed_codes.push(MfaRecoveryCode {
            code_hash: hash,
            used_at: None,
        });
    }

    Ok((raw_codes, hashed_codes))
}

pub fn refresh_backup_codes(device: &mut MfaDevice) -> Result<Vec<String>, MfaError> {
    let (raw_codes, hashed_codes) = generate_recovery_codes()?;
    device.backup_codes = hashed_codes;
    device.mark_updated();
    Ok(raw_codes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> TotpConfig {
        TotpConfig {
            algorithm: TotpAlgorithm::Sha1,
            digits: 8,
            step: 30,
            window: 1,
            issuer: "Test".to_string(),
        }
    }

    #[test]
    fn rfc_6238_test_vectors_sha1() {
        let secret = b"12345678901234567890";
        let config = base_config();

        let cases = vec![
            (59, 94287082u32),
            (1111111109, 7081804u32),
            (1111111111, 14050471u32),
            (1234567890, 89005924u32),
            (2000000000, 69279037u32),
            (20000000000, 65353130u32),
        ];

        for (time, expected) in cases {
            let counter = (time / config.step as i64) as u64;
            assert_eq!(compute_totp(secret, counter, &config), expected);
        }
    }

    #[test]
    fn rejects_replay_within_same_window() {
        let mut device = MfaDevice {
            id: "test".to_string(),
            user_id: 1,
            secret_ciphertext: String::new(),
            secret_nonce: String::new(),
            algorithm: "SHA1".to_string(),
            digits: 6,
            step: 30,
            window: 1,
            enabled: true,
            enrollment_expires_at: None,
            verified_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_used_step: None,
            failed_attempts: 0,
            lockout_until: None,
            device_name: None,
            backup_codes: vec![],
        };
        let config = TotpConfig {
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            step: 30,
            window: 1,
            issuer: "Test".to_string(),
        };
        let secret = b"AAAAAAAAAAAAAAAA";
        let now = DateTime::from_timestamp(1_000_000, 0).unwrap();
        let step = expected_step(now, &config);
        let code = format!("{:06}", compute_totp(secret, step as u64, &config));

        let first = verify_totp_code(&mut device, secret, &code, now, &config)
            .expect("first verification should pass");
        assert_eq!(first.matched_step, step);

        let err = verify_totp_code(&mut device, secret, &code, now, &config)
            .expect_err("second verification must fail");
        assert!(matches!(err, MfaError::Replay));
    }

    #[test]
    fn rate_limiting_enforces_lockout() {
        let mut device = MfaDevice {
            id: "test".to_string(),
            user_id: 1,
            secret_ciphertext: String::new(),
            secret_nonce: String::new(),
            algorithm: "SHA1".to_string(),
            digits: 6,
            step: 30,
            window: 1,
            enabled: true,
            enrollment_expires_at: None,
            verified_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_used_step: None,
            failed_attempts: 0,
            lockout_until: None,
            device_name: None,
            backup_codes: vec![],
        };
        let config = TotpConfig::load();
        let secret = b"AAAAAAAAAAAAAAAA";
        let now = Utc::now();

        for _ in 0..MAX_FAILED_ATTEMPTS {
            let err = verify_totp_code(&mut device, secret, "000000", now, &config)
                .expect_err("verification should fail");
            assert!(matches!(err, MfaError::Validation(_)));
        }

        assert!(device.lockout_until.is_some(), "lockout should be set");
    }

    #[test]
    fn recovery_code_is_single_use() {
        let mut device = MfaDevice {
            id: "test".to_string(),
            user_id: 1,
            secret_ciphertext: String::new(),
            secret_nonce: String::new(),
            algorithm: "SHA1".to_string(),
            digits: 6,
            step: 30,
            window: 1,
            enabled: true,
            enrollment_expires_at: None,
            verified_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_used_step: None,
            failed_attempts: 0,
            lockout_until: None,
            device_name: None,
            backup_codes: vec![],
        };

        let (raw, hashed) = generate_recovery_codes().expect("codes to generate");
        let code = raw.first().cloned().expect("at least one code");
        device.backup_codes = hashed;

        verify_recovery_code(&mut device, &code, Utc::now()).expect("first use ok");
        assert!(device.backup_codes.first().unwrap().is_used());

        let err =
            verify_recovery_code(&mut device, &code, Utc::now()).expect_err("second use must fail");
        assert!(matches!(err, MfaError::Validation(_)));
    }
}
