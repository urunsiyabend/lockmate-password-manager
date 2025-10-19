use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VaultItemRecord {
    pub id: String,
    pub user_id: String,
    pub folder_id: Option<String>,
    pub ciphertext: String,
    pub nonce: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NewVaultItemRecord {
    pub user_id: String,
    pub folder_id: Option<String>,
    pub ciphertext: String,
    pub nonce: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VaultItemPayload {
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct VaultItemView {
    pub id: String,
    pub user_id: String,
    pub folder_id: Option<String>,
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl VaultItemView {
    pub fn from_parts(record: &VaultItemRecord, payload: VaultItemPayload) -> Self {
        Self {
            id: record.id.clone(),
            user_id: record.user_id.clone(),
            folder_id: record.folder_id.clone(),
            created_at: record.created_at,
            updated_at: record.updated_at,
            title: payload.title,
            username: payload.username,
            password: payload.password,
            url: payload.url,
            notes: payload.notes,
        }
    }
}
