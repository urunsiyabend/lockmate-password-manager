use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    pub user_id: i32,
    pub username: String,
    pub email: String,
    pub password: String,
    pub encryption_public_key: String,
    pub signature_public_key: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
