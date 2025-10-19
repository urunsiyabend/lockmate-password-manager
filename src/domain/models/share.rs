use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShareInvitationStatus {
    Pending,
    Accepted,
    Declined,
    Revoked,
    Expired,
}

impl ShareInvitationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ShareInvitationStatus::Pending => "pending",
            ShareInvitationStatus::Accepted => "accepted",
            ShareInvitationStatus::Declined => "declined",
            ShareInvitationStatus::Revoked => "revoked",
            ShareInvitationStatus::Expired => "expired",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ShareInvitationStatus::Accepted
                | ShareInvitationStatus::Declined
                | ShareInvitationStatus::Revoked
                | ShareInvitationStatus::Expired
        )
    }
}

impl From<&ShareInvitationStatus> for String {
    fn from(value: &ShareInvitationStatus) -> Self {
        value.as_str().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::ShareInvitationStatus;

    #[test]
    fn as_str_maps_variants_to_expected_strings() {
        assert_eq!(ShareInvitationStatus::Pending.as_str(), "pending");
        assert_eq!(ShareInvitationStatus::Accepted.as_str(), "accepted");
        assert_eq!(ShareInvitationStatus::Declined.as_str(), "declined");
        assert_eq!(ShareInvitationStatus::Revoked.as_str(), "revoked");
        assert_eq!(ShareInvitationStatus::Expired.as_str(), "expired");
    }

    #[test]
    fn is_terminal_reflects_final_states() {
        assert!(!ShareInvitationStatus::Pending.is_terminal());
        assert!(ShareInvitationStatus::Accepted.is_terminal());
        assert!(ShareInvitationStatus::Declined.is_terminal());
        assert!(ShareInvitationStatus::Revoked.is_terminal());
        assert!(ShareInvitationStatus::Expired.is_terminal());
    }

    #[test]
    fn string_conversion_uses_as_str_representation() {
        let value: String = (&ShareInvitationStatus::Declined).into();
        assert_eq!(value, "declined");
    }
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareRecord {
    pub id: String,
    pub owner_id: String,
    pub item_id: String,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewShareRecord {
    pub owner_id: String,
    pub item_id: String,
    pub created_at: DateTime<Utc>,
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareInvitationRecord {
    pub id: String,
    pub share_id: String,
    pub recipient_id: String,
    pub status: ShareInvitationStatus,
    pub key_payload: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub responded_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewShareInvitationRecord {
    pub share_id: String,
    pub recipient_id: String,
    pub status: ShareInvitationStatus,
    pub key_payload: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
