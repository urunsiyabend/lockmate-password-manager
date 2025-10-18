use axum::{Json, extract::Extension, http::StatusCode, response::IntoResponse};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use crate::{
    api::rest::middleware::AuthContext,
    application::services::mfa::{MfaError, TotpConfig, decrypt_device_secret, verify_totp_code},
    infrastructure::data::repositories::mfa_repository::MfaRepository,
};

use super::responses::{json_error, json_success, map_mfa_error};

#[derive(Debug, Deserialize)]
pub struct EnrollmentVerifyRequest {
    pub device_id: String,
    pub code: String,
}

pub async fn verify_mfa_enrollment(
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<EnrollmentVerifyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repository = MfaRepository::new();
    let mut device = repository.get_by_id(&body.device_id).await.map_err(|err| {
        json_error(
            StatusCode::NOT_FOUND,
            &format!("MFA enrollment not found: {err}"),
        )
    })?;

    if device.user_id != auth.claims.sub {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "You do not have permission to verify this device",
        ));
    }

    if device.enabled {
        return Err(json_error(
            StatusCode::CONFLICT,
            "This MFA device has already been activated",
        ));
    }

    let now = Utc::now();
    if let Some(expires_at) = device.enrollment_expires_at {
        if now > expires_at {
            return Err(map_mfa_error(MfaError::EnrollmentExpired));
        }
    } else {
        return Err(map_mfa_error(MfaError::EnrollmentNotPending));
    }

    let secret = decrypt_device_secret(&device).map_err(map_mfa_error)?;
    let config = TotpConfig::load();

    let verification =
        verify_totp_code(&mut device, &secret, &body.code, now, &config).map_err(map_mfa_error)?;

    device.enabled = true;
    device.verified_at = Some(now);
    device.enrollment_expires_at = None;
    device.last_used_step = Some(verification.matched_step);
    device.failed_attempts = 0;
    device.lockout_until = None;

    repository.upsert(&device).await.map_err(|err| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to activate MFA device: {err}"),
        )
    })?;

    Ok(json_success(json!({
        "device_id": device.id,
        "enabled": true,
        "verified_at": device.verified_at,
    })))
}
