use axum::{Json, http::StatusCode, response::IntoResponse};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use crate::{
    application::services::auth::{AuthServiceError, create_session_token},
    application::services::mfa::{
        MfaError, TotpConfig, consume_challenge, decrypt_device_secret, get_challenge,
        verify_recovery_code, verify_totp_code,
    },
    infrastructure::data::repositories::{
        mfa_repository::MfaRepository, user_repository::UserRepository,
    },
};

use super::responses::{json_error, json_success, map_mfa_error};

#[derive(Debug, Deserialize)]
pub struct LoginVerifyRequest {
    pub challenge_id: String,
    pub code: Option<String>,
    pub recovery_code: Option<String>,
}

pub async fn verify_mfa_login(
    Json(body): Json<LoginVerifyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    if body.code.is_some() == body.recovery_code.is_some() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "Provide either a TOTP code or a recovery code",
        ));
    }

    let challenge = match get_challenge(&body.challenge_id).await {
        Some(challenge) => challenge,
        None => return Err(map_mfa_error(MfaError::ChallengeNotFound)),
    };

    let now = Utc::now();
    if challenge.is_expired(now) {
        consume_challenge(&body.challenge_id).await;
        return Err(map_mfa_error(MfaError::ChallengeExpired));
    }

    let repository = MfaRepository::new();
    let mut device = match repository.get_active_by_user(challenge.user_id).await {
        Ok(Some(device)) => device,
        Ok(None) => {
            return Err(json_error(
                StatusCode::NOT_FOUND,
                "No MFA device registered",
            ));
        }
        Err(err) => {
            return Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to load MFA device: {err}"),
            ));
        }
    };

    if let Some(lockout_until) = device.lockout_until {
        if now < lockout_until {
            return Err(map_mfa_error(MfaError::LockedOut(lockout_until)));
        }
    }

    let mut verification_successful = false;

    if let Some(code) = body.code {
        let secret = decrypt_device_secret(&device).map_err(map_mfa_error)?;
        let config = TotpConfig::load();
        verify_totp_code(&mut device, &secret, &code, now, &config).map_err(map_mfa_error)?;
        verification_successful = true;
    }

    if let Some(recovery_code) = body.recovery_code {
        verify_recovery_code(&mut device, &recovery_code, now).map_err(map_mfa_error)?;
        verification_successful = true;
    }

    if !verification_successful {
        return Err(json_error(StatusCode::BAD_REQUEST, "Verification failed"));
    }

    repository.upsert(&device).await.map_err(|err| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to update MFA device: {err}"),
        )
    })?;

    consume_challenge(&body.challenge_id).await;

    let user_repository = UserRepository::new();
    let mut user = user_repository
        .get_by_id(challenge.user_id.to_string())
        .await
        .map_err(|_| json_error(StatusCode::NOT_FOUND, "User not found"))?;
    user.password.clear();

    let token = create_session_token(user.id, &user.username).map_err(|err| match err {
        AuthServiceError::MissingSecret => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "JWT secret is not configured",
        ),
        AuthServiceError::Jwt(_) | AuthServiceError::Revoked => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to issue session token",
        ),
    })?;

    Ok(json_success(json!({
        "token": token,
        "user": user,
        "mfa": {
            "verified": true,
        }
    })))
}
