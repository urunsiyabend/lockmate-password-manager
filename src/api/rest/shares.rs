use std::collections::HashMap;

use axum::{
    Json,
    extract::{Extension, Path},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use surrealdb::{Error, err::Error::Thrown};

use crate::api::rest::middleware::AuthContext;
use crate::domain::models::audit_entry::NewAuditEntry;
use crate::domain::models::share::{
    NewShareInvitationRecord, NewShareRecord, ShareInvitationRecord, ShareInvitationStatus,
};
use crate::infrastructure::data::repositories::audit_entry_repository::AuditEntryRepository;
use crate::infrastructure::data::repositories::share_repository::ShareRepository;
use crate::infrastructure::data::repositories::vault_item_repository::VaultItemRepository;

const DEFAULT_INVITATION_TTL_HOURS: i64 = 72;

#[derive(Deserialize)]
pub struct CreateShareInvitationsRequest {
    pub invitations: Vec<ShareInvitationRequest>,
}

#[derive(Deserialize, Clone)]
pub struct ShareInvitationRequest {
    pub recipient_id: i32,
    pub key_payload: Value,
}

#[derive(Serialize)]
pub struct ShareRecipientsResponse {
    pub share_id: Option<String>,
    pub recipients: Vec<ShareInvitationRecord>,
}

#[derive(Serialize)]
pub struct PendingInvitationView {
    pub id: String,
    pub share_id: String,
    pub owner_id: String,
    pub item_id: String,
    pub key_payload: Value,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct SharedItemView {
    pub invitation_id: String,
    pub share_id: String,
    pub owner_id: String,
    pub item_id: String,
    pub key_payload: Value,
    pub accepted_at: Option<DateTime<Utc>>,
}

type ApiError = (StatusCode, Json<Value>);

pub async fn create_share_invitations(
    Extension(ctx): Extension<AuthContext>,
    Path(item_id): Path<String>,
    Json(body): Json<CreateShareInvitationsRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if body.invitations.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "fail",
                "message": "At least one invitation must be provided.",
            })),
        ));
    }

    let owner_id = ctx.claims.sub.to_string();
    let vault_repo = VaultItemRepository::new();
    let share_repo = ShareRepository::new();

    let _item = vault_repo
        .get_by_id_for_user(&owner_id, &item_id)
        .await
        .map_err(map_db_error)?;

    let now = Utc::now();
    share_repo
        .expire_pending_invitations(now)
        .await
        .map_err(map_db_error)?;

    let share = match share_repo
        .find_active_share(&owner_id, &item_id)
        .await
        .map_err(map_db_error)?
    {
        Some(existing) => existing,
        None => share_repo
            .create_share(NewShareRecord {
                owner_id: owner_id.clone(),
                item_id: item_id.clone(),
                created_at: now,
            })
            .await
            .map_err(map_db_error)?,
    };

    let ttl = invitation_ttl_hours();
    let mut created = Vec::with_capacity(body.invitations.len());

    for invitation in body.invitations.iter() {
        if invitation.recipient_id == ctx.claims.sub {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "fail",
                    "message": "Cannot invite yourself to a share.",
                })),
            ));
        }

        if share_repo
            .find_existing_invitation(&share.id, &invitation.recipient_id.to_string())
            .await
            .map_err(map_db_error)?
            .is_some()
        {
            return Err((
                StatusCode::CONFLICT,
                Json(json!({
                    "status": "fail",
                    "message": "An active invitation already exists for one of the recipients.",
                })),
            ));
        }

        let new_invitation = NewShareInvitationRecord {
            share_id: share.id.clone(),
            recipient_id: invitation.recipient_id.to_string(),
            status: ShareInvitationStatus::Pending,
            key_payload: invitation.key_payload.clone(),
            created_at: now,
            updated_at: now,
            expires_at: now + Duration::hours(ttl),
        };

        let created_invitation = share_repo
            .create_invitation(new_invitation)
            .await
            .map_err(map_db_error)?;
        created.push(created_invitation);
    }

    log_audit(
        &owner_id,
        Some(item_id.clone()),
        "share.invite",
        json!({
            "share_id": share.id,
            "invitation_ids": created.iter().map(|inv| &inv.id).collect::<Vec<_>>(),
            "recipient_ids": created.iter().map(|inv| &inv.recipient_id).collect::<Vec<_>>(),
        }),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "status": "success",
            "data": {
                "share_id": share.id,
                "invitations": created,
            },
        })),
    ))
}

pub async fn list_pending_invitations(
    Extension(ctx): Extension<AuthContext>,
) -> Result<impl IntoResponse, ApiError> {
    let recipient_id = ctx.claims.sub.to_string();
    let share_repo = ShareRepository::new();
    let now = Utc::now();

    share_repo
        .expire_pending_invitations(now)
        .await
        .map_err(map_db_error)?;

    let invitations = share_repo
        .list_pending_for_recipient(&recipient_id, now)
        .await
        .map_err(map_db_error)?;

    let share_ids: Vec<String> = invitations.iter().map(|inv| inv.share_id.clone()).collect();
    let shares = share_repo
        .list_shares_for_ids(&share_ids)
        .await
        .map_err(map_db_error)?;

    let share_map: HashMap<_, _> = shares
        .into_iter()
        .map(|share| (share.id.clone(), share))
        .collect();

    let mut pending = Vec::new();
    for invitation in invitations {
        if let Some(share) = share_map.get(&invitation.share_id) {
            if share.revoked_at.is_some() {
                continue;
            }

            pending.push(PendingInvitationView {
                id: invitation.id.clone(),
                share_id: invitation.share_id.clone(),
                owner_id: share.owner_id.clone(),
                item_id: share.item_id.clone(),
                key_payload: invitation.key_payload.clone(),
                created_at: invitation.created_at,
                expires_at: invitation.expires_at,
            });
        }
    }

    Ok(Json(json!({
        "status": "success",
        "results": pending.len(),
        "data": pending,
    })))
}

pub async fn accept_invitation(
    Extension(ctx): Extension<AuthContext>,
    Path(invitation_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    respond_to_invitation(ctx, invitation_id, ShareInvitationStatus::Accepted).await
}

pub async fn decline_invitation(
    Extension(ctx): Extension<AuthContext>,
    Path(invitation_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    respond_to_invitation(ctx, invitation_id, ShareInvitationStatus::Declined).await
}

pub async fn list_share_recipients(
    Extension(ctx): Extension<AuthContext>,
    Path(item_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let owner_id = ctx.claims.sub.to_string();
    let vault_repo = VaultItemRepository::new();
    let share_repo = ShareRepository::new();

    let _item = vault_repo
        .get_by_id_for_user(&owner_id, &item_id)
        .await
        .map_err(map_db_error)?;

    if let Some(share) = share_repo
        .find_active_share(&owner_id, &item_id)
        .await
        .map_err(map_db_error)?
    {
        let invitations = share_repo
            .list_invitations_for_share(&share.id)
            .await
            .map_err(map_db_error)?;

        return Ok(Json(json!({
            "status": "success",
            "data": ShareRecipientsResponse {
                share_id: Some(share.id),
                recipients: invitations,
            },
        })));
    }

    Ok(Json(json!({
        "status": "success",
        "data": ShareRecipientsResponse {
            share_id: None,
            recipients: Vec::new(),
        },
    })))
}

pub async fn revoke_recipient(
    Extension(ctx): Extension<AuthContext>,
    Path((share_id, recipient_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let owner_id = ctx.claims.sub.to_string();
    let share_repo = ShareRepository::new();

    let share = share_repo
        .get_share_by_id(&share_id)
        .await
        .map_err(map_db_error)?;

    if share.owner_id != owner_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "fail",
                "message": "You do not have permission to modify this share.",
            })),
        ));
    }

    if share.revoked_at.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({
                "status": "fail",
                "message": "The share has already been revoked.",
            })),
        ));
    }

    let revoked = share_repo
        .revoke_recipient(&share_id, &recipient_id)
        .await
        .map_err(map_db_error)?;

    if revoked.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "status": "fail",
                "message": "No active invitation found for the specified recipient.",
            })),
        ));
    }

    log_audit(
        &owner_id,
        Some(share.item_id.clone()),
        "share.revoke_recipient",
        json!({
            "share_id": share_id,
            "recipient_id": recipient_id,
        }),
    )
    .await;

    Ok(Json(json!({
        "status": "success",
        "data": revoked,
    })))
}

pub async fn revoke_share(
    Extension(ctx): Extension<AuthContext>,
    Path(share_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let owner_id = ctx.claims.sub.to_string();
    let share_repo = ShareRepository::new();

    let share = share_repo
        .get_share_by_id(&share_id)
        .await
        .map_err(map_db_error)?;

    if share.owner_id != owner_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "fail",
                "message": "You do not have permission to modify this share.",
            })),
        ));
    }

    if share.revoked_at.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({
                "status": "fail",
                "message": "The share has already been revoked.",
            })),
        ));
    }

    let revoked_share = share_repo
        .mark_share_revoked(&share_id)
        .await
        .map_err(map_db_error)?;

    let revoked_recipients = share_repo
        .revoke_all_for_share(&share_id)
        .await
        .map_err(map_db_error)?;

    log_audit(
        &owner_id,
        Some(revoked_share.item_id.clone()),
        "share.revoke",
        json!({
            "share_id": share_id,
            "revoked_recipients": revoked_recipients
                .iter()
                .map(|inv| &inv.recipient_id)
                .collect::<Vec<_>>(),
        }),
    )
    .await;

    Ok(Json(json!({
        "status": "success",
        "data": revoked_share,
    })))
}

pub async fn list_shared_items(
    Extension(ctx): Extension<AuthContext>,
) -> Result<impl IntoResponse, ApiError> {
    let recipient_id = ctx.claims.sub.to_string();
    let share_repo = ShareRepository::new();

    let invitations = share_repo
        .list_active_for_recipient(&recipient_id)
        .await
        .map_err(map_db_error)?;

    let share_ids: Vec<String> = invitations.iter().map(|inv| inv.share_id.clone()).collect();
    let shares = share_repo
        .list_shares_for_ids(&share_ids)
        .await
        .map_err(map_db_error)?;

    let share_map: HashMap<_, _> = shares
        .into_iter()
        .map(|share| (share.id.clone(), share))
        .collect();
    let mut items = Vec::new();

    for invitation in invitations {
        if let Some(share) = share_map.get(&invitation.share_id) {
            if share.revoked_at.is_some() {
                continue;
            }

            items.push(SharedItemView {
                invitation_id: invitation.id.clone(),
                share_id: invitation.share_id.clone(),
                owner_id: share.owner_id.clone(),
                item_id: share.item_id.clone(),
                key_payload: invitation.key_payload.clone(),
                accepted_at: invitation.responded_at,
            });
        }
    }

    Ok(Json(json!({
        "status": "success",
        "results": items.len(),
        "data": items,
    })))
}

async fn respond_to_invitation(
    ctx: AuthContext,
    invitation_id: String,
    status: ShareInvitationStatus,
) -> Result<impl IntoResponse, ApiError> {
    let share_repo = ShareRepository::new();
    let now = Utc::now();

    share_repo
        .expire_pending_invitations(now)
        .await
        .map_err(map_db_error)?;

    let invitation = share_repo
        .get_invitation_by_id(&invitation_id)
        .await
        .map_err(map_db_error)?;

    if invitation.recipient_id != ctx.claims.sub.to_string() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "fail",
                "message": "You are not the recipient of this invitation.",
            })),
        ));
    }

    if invitation.status != ShareInvitationStatus::Pending {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({
                "status": "fail",
                "message": "This invitation has already been processed.",
            })),
        ));
    }

    if invitation.expires_at <= now {
        return Err((
            StatusCode::GONE,
            Json(json!({
                "status": "fail",
                "message": "This invitation has expired.",
            })),
        ));
    }

    let share = share_repo
        .get_share_by_id(&invitation.share_id)
        .await
        .map_err(map_db_error)?;

    if share.revoked_at.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({
                "status": "fail",
                "message": "The share has been revoked.",
            })),
        ));
    }

    let updated = share_repo
        .update_invitation_status(&invitation_id, status.clone(), Some(now), None)
        .await
        .map_err(map_db_error)?;

    let action = match status {
        ShareInvitationStatus::Accepted => "share.accept",
        ShareInvitationStatus::Declined => "share.decline",
        ShareInvitationStatus::Pending => "share.pending",
        ShareInvitationStatus::Revoked => "share.revoked",
        ShareInvitationStatus::Expired => "share.expired",
    };

    log_audit(
        &ctx.claims.sub.to_string(),
        Some(share.item_id.clone()),
        action,
        json!({
            "share_id": invitation.share_id,
            "invitation_id": invitation_id,
        }),
    )
    .await;

    Ok(Json(json!({
        "status": "success",
        "data": updated,
    })))
}

fn invitation_ttl_hours() -> i64 {
    std::env::var("SHARE_INVITATION_TTL_HOURS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_INVITATION_TTL_HOURS)
}

fn map_db_error(err: Error) -> ApiError {
    match err {
        Error::Db(Thrown(message)) => {
            let status = if message.to_lowercase().contains("not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };

            (
                status,
                Json(
                    json!({ "status": if status == StatusCode::NOT_FOUND { "fail" } else { "error" }, "message": message }),
                ),
            )
        }
        other => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "message": format!("database error: {other}"),
            })),
        ),
    }
}

async fn log_audit(user_id: &str, vault_item_id: Option<String>, action: &str, metadata: Value) {
    let repository = AuditEntryRepository::new();
    let entry = NewAuditEntry {
        user_id: user_id.to_string(),
        vault_item_id,
        action: action.to_string(),
        ip_address: None,
        metadata: Some(metadata),
        occurred_at: Utc::now(),
    };

    let _ = repository.log(entry).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use serde_json::json;
    use surrealdb::Error;

    fn clear_ttl_env() {
        unsafe { std::env::remove_var("SHARE_INVITATION_TTL_HOURS"); }
    }

    #[test]
    fn invitation_ttl_uses_default_when_env_missing_or_invalid() {
        clear_ttl_env();
        assert_eq!(invitation_ttl_hours(), DEFAULT_INVITATION_TTL_HOURS);

        unsafe { std::env::set_var("SHARE_INVITATION_TTL_HOURS", "invalid"); }
        assert_eq!(invitation_ttl_hours(), DEFAULT_INVITATION_TTL_HOURS);

        unsafe { std::env::set_var("SHARE_INVITATION_TTL_HOURS", "0"); }
        assert_eq!(invitation_ttl_hours(), DEFAULT_INVITATION_TTL_HOURS);

        clear_ttl_env();
        unsafe { std::env::set_var("SHARE_INVITATION_TTL_HOURS", "12"); }
        assert_eq!(invitation_ttl_hours(), 12);

        unsafe { std::env::set_var("SHARE_INVITATION_TTL_HOURS", "168"); }
        assert_eq!(invitation_ttl_hours(), 168);

        clear_ttl_env();
    }

    #[test]
    fn map_db_error_translates_not_found_messages() {
        let message = "Share not found".to_string();
        let (status, Json(body)) = map_db_error(Error::Db(Thrown(message.clone())));

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, json!({ "status": "fail", "message": message }));
    }

    #[test]
    fn map_db_error_defaults_to_bad_request_for_other_db_errors() {
        let message = "Failed to create share".to_string();
        let (status, Json(body)) = map_db_error(Error::Db(Thrown(message.clone())));

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({ "status": "error", "message": message }));
    }

    #[test]
    fn map_db_error_wraps_non_db_errors() {
        let (status, Json(body)) =
            map_db_error(Error::Api(surrealdb::error::Api::Http("boom".into())));

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["status"], "error");
        assert!(body["message"].as_str().unwrap().contains("boom"));
    }
}
