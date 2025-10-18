use axum::{Json, extract::Extension, http::StatusCode, response::IntoResponse};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    api::rest::middleware::AuthContext,
    application::services::mfa::{
        TotpConfig, encrypt_secret_for_storage, enrollment_expiration, generate_provisioning,
        generate_recovery_codes, generate_totp_secret,
    },
    domain::models::mfa::MfaDevice,
    infrastructure::data::repositories::mfa_repository::MfaRepository,
};

use super::responses::{json_created, json_error, map_mfa_error};

#[derive(Debug, Deserialize)]
pub struct EnrollmentStartRequest {
    pub device_name: Option<String>,
}

pub async fn start_mfa_enrollment(
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<EnrollmentStartRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repository = MfaRepository::new();

    if let Ok(Some(_)) = repository.get_active_by_user(auth.claims.sub).await {
        return Err(json_error(
            StatusCode::CONFLICT,
            "An MFA device is already enabled for this account",
        ));
    }

    let config = TotpConfig::load();
    let secret = generate_totp_secret();
    let provisioning =
        generate_provisioning(&auth.claims.username, &secret, &config).map_err(map_mfa_error)?;
    let (ciphertext, nonce) = encrypt_secret_for_storage(&secret).map_err(map_mfa_error)?;
    let (raw_codes, hashed_codes) = generate_recovery_codes().map_err(map_mfa_error)?;

    let now = Utc::now();
    let expires_at = enrollment_expiration();

    let mut pending_device = match repository.get_pending_by_user(auth.claims.sub).await {
        Ok(Some(mut device)) => {
            device.secret_ciphertext = ciphertext.clone();
            device.secret_nonce = nonce.clone();
            device.algorithm = config.algorithm.as_str().to_string();
            device.digits = config.digits;
            device.step = config.step;
            device.window = config.window;
            device.enabled = false;
            device.enrollment_expires_at = Some(expires_at);
            device.verified_at = None;
            device.last_used_step = None;
            device.failed_attempts = 0;
            device.lockout_until = None;
            device.device_name = body.device_name.clone();
            device.backup_codes = hashed_codes;
            device.created_at = device.created_at.min(now);
            device.updated_at = now;
            repository.upsert(&device).await.map_err(|err| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to update MFA enrollment: {err}"),
                )
            })?
        }
        Ok(None) => {
            let device = MfaDevice {
                id: Uuid::new_v4().to_string(),
                user_id: auth.claims.sub,
                secret_ciphertext: ciphertext.clone(),
                secret_nonce: nonce.clone(),
                algorithm: config.algorithm.as_str().to_string(),
                digits: config.digits,
                step: config.step,
                window: config.window,
                enabled: false,
                enrollment_expires_at: Some(expires_at),
                verified_at: None,
                created_at: now,
                updated_at: now,
                last_used_step: None,
                failed_attempts: 0,
                lockout_until: None,
                device_name: body.device_name.clone(),
                backup_codes: hashed_codes,
            };
            repository.create(&device).await.map_err(|err| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to start MFA enrollment: {err}"),
                )
            })?
        }
        Err(err) => {
            return Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to load MFA enrollment: {err}"),
            ));
        }
    };

    pending_device.created_at = pending_device.created_at.min(now);

    let response = json!({
        "device_id": pending_device.id,
        "expires_at": expires_at,
        "totp": {
            "uri": provisioning.uri,
            "qr_code": provisioning.qr_code,
            "secret": provisioning.secret,
            "algorithm": config.algorithm.as_str(),
            "digits": config.digits,
            "step": config.step,
            "window": config.window,
        },
        "backup_codes": raw_codes,
    });

    Ok(json_created(response))
}
