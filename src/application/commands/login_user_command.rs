use axum::{Json, extract::ConnectInfo, http::StatusCode, response::IntoResponse};
use log::error;
use serde::Deserialize;
use std::net::SocketAddr;

use crate::{
    application::services::{
        audit::log_login_attempt,
        auth::{AuthServiceError, create_session_token, hash_password, verify_password},
        mfa::create_challenge,
    },
    domain::models::user::User,
    infrastructure::data::repositories::{
        mfa_repository::MfaRepository, user_repository::UserRepository,
    },
};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

pub async fn login_user_command(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repository = UserRepository::new();
    let ip_address = Some(addr.ip().to_string());

    let user = match repository.get_by_username(&body.username).await {
        Ok(user) => user,
        Err(_) => {
            log_login_attempt(
                None,
                "unknown_user",
                ip_address.clone(),
                Some(serde_json::json!({ "username": body.username })),
            )
            .await;

            let json_response = serde_json::json!({
                "status": "fail",
                "message": "Invalid username or password",
            });

            return Err((StatusCode::UNAUTHORIZED, Json(json_response)));
        }
    };

    let password_is_valid = match verify_password(&body.password, &user.password) {
        Ok(valid) => valid,
        Err(_) => {
            log_login_attempt(
                Some(user.user_id),
                "error",
                ip_address.clone(),
                Some(serde_json::json!({ "reason": "password_verification_failed" })),
            )
            .await;

            let json_response = serde_json::json!({
                "status": "error",
                "message": "Failed to verify password",
            });

            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json_response)));
        }
    };

    if !password_is_valid {
        log_login_attempt(
            Some(user.user_id),
            "failure",
            ip_address.clone(),
            Some(serde_json::json!({ "reason": "invalid_password" })),
        )
        .await;

        let json_response = serde_json::json!({
            "status": "fail",
            "message": "Invalid username or password",
        });
        return Err((StatusCode::UNAUTHORIZED, Json(json_response)));
    }

    let mut sanitized_user: User = user.clone();
    sanitized_user.password = String::new();

    let mfa_repository = MfaRepository::new();
    if let Some(device) = mfa_repository
        .get_active_by_user(user.user_id)
        .await
        .map_err(|err| {
            let json_response = serde_json::json!({
                "status": "error",
                "message": format!("Failed to load MFA status: {err}"),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json_response))
        })?
    {
        if device.enabled {
            let challenge = create_challenge(sanitized_user.user_id).await;
            log_login_attempt(
                Some(sanitized_user.user_id),
                "mfa_required",
                ip_address.clone(),
                Some(serde_json::json!({ "challenge_id": challenge.id })),
            )
            .await;
            let json_response = serde_json::json!({
                "status": "mfa_required",
                "data": {
                    "challenge_id": challenge.id,
                    "expires_at": challenge.expires_at,
                    "user": sanitized_user,
                },
            });

            return Ok((StatusCode::OK, Json(json_response)));
        }
    }

    let token = create_session_token(sanitized_user.user_id, &sanitized_user.username).map_err(
        |err: AuthServiceError| {
            error!("Failed to create session token: {err}");

            let status = err.status_code();
            let (status_str, message) = if status.is_server_error() {
                ("error", "Failed to create session token")
            } else {
                ("fail", err.message())
            };

            let json_response = serde_json::json!({
                "status": status_str,
                "message": message,
            });

            (status, Json(json_response))
        },
    )?;

    log_login_attempt(Some(sanitized_user.user_id), "success", ip_address, None).await;

    let json_response = serde_json::json!({
        "status": "success",
        "data": {
            "token": token,
            "user": sanitized_user,
        },
    });

    Ok((StatusCode::OK, Json(json_response)))
}

pub fn hash_user_password(user: &mut User) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let hashed_password = hash_password(&user.password).map_err(|_| {
        let json_response = serde_json::json!({
            "status": "error",
            "message": "Failed to hash password",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json_response))
    })?;

    user.password = hashed_password;
    Ok(())
}
