use chrono::Utc;
use metrics::counter;
use serde_json::Value;
use tracing::{info, warn};

use crate::domain::models::audit_entry::NewAuditEntry;
use crate::infrastructure::data::repositories::audit_entry_repository::AuditEntryRepository;

fn sanitize_action(action: &str) -> String {
    action.trim().to_lowercase()
}

fn ip_string(ip: Option<String>) -> Option<String> {
    ip.map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub async fn log_audit_event(
    user_id: impl Into<String>,
    vault_item_id: Option<String>,
    action: &str,
    ip_address: Option<String>,
    metadata: Option<Value>,
) {
    let action = sanitize_action(action);
    counter!("audit_events_total", 1, "action" => action.clone());

    let user_id = user_id.into();
    let entry = NewAuditEntry {
        user_id: user_id.clone(),
        vault_item_id,
        action: action.clone(),
        ip_address: ip_string(ip_address),
        metadata,
        occurred_at: Utc::now(),
    };

    info!(target: "audit", action = %action, user_id = %user_id, "recording audit event");

    if let Err(err) = AuditEntryRepository::new().log(entry).await {
        counter!("audit_event_errors_total", 1, "action" => action.clone());
        warn!(target: "audit", error = %err, action = %action, user_id = %user_id, "failed to persist audit entry");
    }
}

pub async fn log_login_attempt(
    user_id: Option<i32>,
    outcome: &str,
    ip_address: Option<String>,
    metadata: Option<Value>,
) {
    let outcome = sanitize_action(outcome);
    counter!("login_attempts_total", 1, "outcome" => outcome.clone());

    let user_key = user_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "anonymous".to_string());
    let action = format!("login.{outcome}");

    log_audit_event(user_key, None, &action, ip_address, metadata).await;
}

pub fn record_audit_query(label: &str) {
    counter!("audit_query_total", 1, "scope" => label.to_string());
}
