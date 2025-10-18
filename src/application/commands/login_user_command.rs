use axum::{Json, http::StatusCode, response::IntoResponse};
use log::error;
use serde::Deserialize;

use crate::{
    application::services::auth::{
        AuthServiceError, create_session_token, hash_password, verify_password,
    },
    domain::models::user::User,
    infrastructure::data::repositories::user_repository::UserRepository,
};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

pub async fn login_user_command(
    Json(body): Json<LoginRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repository = UserRepository::new();

    let user = repository
        .get_by_username(&body.username)
        .await
        .map_err(|_| {
            let json_response = serde_json::json!({
                "status": "fail",
                "message": "Invalid username or password",
            });
            (StatusCode::UNAUTHORIZED, Json(json_response))
        })?;

    let password_is_valid = verify_password(&body.password, &user.password).map_err(|_| {
        let json_response = serde_json::json!({
            "status": "error",
            "message": "Failed to verify password",
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json_response))
    })?;

    if !password_is_valid {
        let json_response = serde_json::json!({
            "status": "fail",
            "message": "Invalid username or password",
        });
        return Err((StatusCode::UNAUTHORIZED, Json(json_response)));
    }

    let mut sanitized_user: User = user;
    sanitized_user.password = String::new();

    let token = create_session_token(sanitized_user.id, &sanitized_user.username).map_err(
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
