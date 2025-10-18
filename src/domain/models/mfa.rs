use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MfaRecoveryCode {
    pub code_hash: String,
    pub used_at: Option<DateTime<Utc>>,
}

impl MfaRecoveryCode {
    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MfaDevice {
    pub id: String,
    pub user_id: i32,
    pub secret_ciphertext: String,
    pub secret_nonce: String,
    pub algorithm: String,
    pub digits: u32,
    pub step: u64,
    pub window: i32,
    pub enabled: bool,
    pub enrollment_expires_at: Option<DateTime<Utc>>,
    pub verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_step: Option<i64>,
    pub failed_attempts: i32,
    pub lockout_until: Option<DateTime<Utc>>,
    pub device_name: Option<String>,
    pub backup_codes: Vec<MfaRecoveryCode>,
}

impl MfaDevice {
    pub fn mark_updated(&mut self) {
        self.updated_at = Utc::now();
    }
}
