use axum::{Json, extract::Extension, http::StatusCode, response::IntoResponse};
use serde_json::json;

use crate::{
    api::rest::middleware::AuthContext,
    infrastructure::data::repositories::mfa_repository::MfaRepository,
};

use crate::application::commands::mfa::responses::{json_error, json_success};

pub async fn get_mfa_status(
    Extension(auth): Extension<AuthContext>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repository = MfaRepository::new();

    let active_device = repository
        .get_active_by_user(auth.claims.sub)
        .await
        .map_err(|err| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to load MFA status: {err}"),
            )
        })?;

    let pending_device = repository
        .get_pending_by_user(auth.claims.sub)
        .await
        .map_err(|err| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to load pending MFA status: {err}"),
            )
        })?;

    let enabled = active_device.is_some();
    let device_payload = active_device.as_ref().map(|device| {
        json!({
            "device_id": device.id,
            "device_name": device.device_name,
            "enabled": device.enabled,
            "verified_at": device.verified_at,
            "created_at": device.created_at,
            "updated_at": device.updated_at,
            "algorithm": device.algorithm,
            "digits": device.digits,
            "step": device.step,
            "window": device.window,
            "backup_codes_remaining": device.backup_codes.iter().filter(|code| !code.is_used()).count(),
        })
    });

    let pending_payload = pending_device.as_ref().map(|device| {
        json!({
            "device_id": device.id,
            "expires_at": device.enrollment_expires_at,
            "device_name": device.device_name,
        })
    });

    Ok(json_success(json!({
        "enabled": enabled,
        "device": device_payload,
        "pending": pending_payload,
    })))
}
