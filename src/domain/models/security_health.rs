use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityHealthFindingKind {
    BreachedCredential,
    ReusedCredential,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityHealthSeverity {
    Low,
    Medium,
    High,
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHealthFindingRecord {
    pub id: String,
    pub user_id: String,
    pub kind: SecurityHealthFindingKind,
    pub severity: SecurityHealthSeverity,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub vault_item_ids: Vec<String>,
    pub metadata: Option<Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewSecurityHealthFindingRecord {
    pub user_id: String,
    pub kind: SecurityHealthFindingKind,
    pub severity: SecurityHealthSeverity,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub vault_item_ids: Vec<String>,
    pub metadata: Option<Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHealthFinding {
    pub id: String,
    pub kind: SecurityHealthFindingKind,
    pub severity: SecurityHealthSeverity,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub vault_item_ids: Vec<String>,
    pub metadata: Option<Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHealthSummary {
    pub findings: Vec<SecurityHealthFinding>,
    pub generated_at: DateTime<Utc>,
}

impl From<&SecurityHealthFindingRecord> for SecurityHealthFinding {
    fn from(record: &SecurityHealthFindingRecord) -> Self {
        Self {
            id: record.id.clone(),
            kind: record.kind.clone(),
            severity: record.severity.clone(),
            title: record.title.clone(),
            description: record.description.clone(),
            remediation: record.remediation.clone(),
            vault_item_ids: record.vault_item_ids.clone(),
            metadata: record.metadata.clone(),
            created_at: record.created_at,
        }
    }
}

impl From<Vec<SecurityHealthFindingRecord>> for SecurityHealthSummary {
    fn from(records: Vec<SecurityHealthFindingRecord>) -> Self {
        let generated_at = records
            .iter()
            .map(|record| record.created_at)
            .max()
            .unwrap_or_else(Utc::now);

        let findings = records.iter().map(SecurityHealthFinding::from).collect();

        Self {
            findings,
            generated_at,
        }
    }
}
