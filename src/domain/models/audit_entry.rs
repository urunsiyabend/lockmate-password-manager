use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuditEntry {
    pub id: String,
    pub user_id: String,
    pub vault_item_id: Option<String>,
    pub action: String,
    pub ip_address: Option<String>,
    pub metadata: Option<Value>,
    pub occurred_at: DateTime<Utc>,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NewAuditEntry {
    pub user_id: String,
    pub vault_item_id: Option<String>,
    pub action: String,
    pub ip_address: Option<String>,
    pub metadata: Option<Value>,
    pub occurred_at: DateTime<Utc>,
}
