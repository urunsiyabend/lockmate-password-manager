use axum::{Json, http::StatusCode, response::IntoResponse};
use chrono::Utc;
use serde::Deserialize;

use super::login_user_command::hash_user_password;
use crate::{
    domain::models::user::User, infrastructure::data::repositories::user_repository::UserRepository,
};

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub username: String,
    pub password: String,
    pub master_password_hint: Option<String>,
}

pub async fn register_user_command(
    Json(body): Json<RegisterRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repository = UserRepository::new();

    let RegisterRequest {
        email,
        username,
        password,
        master_password_hint: _,
    } = body;

    let username = username.trim();
    if username.is_empty() {
        let json_response = serde_json::json!({
            "status": "fail",
            "message": "Username is required",
        });
        return Err((StatusCode::BAD_REQUEST, Json(json_response)));
    }

    let email = email.trim();
    if email.is_empty() {
        let json_response = serde_json::json!({
            "status": "fail",
            "message": "Email is required",
        });
        return Err((StatusCode::BAD_REQUEST, Json(json_response)));
    }

    if password.len() < 8 {
        let json_response = serde_json::json!({
            "status": "fail",
            "message": "Password must be at least 8 characters long",
        });
        return Err((StatusCode::BAD_REQUEST, Json(json_response)));
    }

    if repository
        .username_exists(username)
        .await
        .map_err(internal_error)?
    {
        let json_response = serde_json::json!({
            "status": "fail",
            "message": "Username is already taken",
        });
        return Err((StatusCode::CONFLICT, Json(json_response)));
    }

    if repository
        .email_exists(email)
        .await
        .map_err(internal_error)?
    {
        let json_response = serde_json::json!({
            "status": "fail",
            "message": "Email is already registered",
        });
        return Err((StatusCode::CONFLICT, Json(json_response)));
    }

    let now = Utc::now();
    let mut user = User {
        user_id: repository.next_id().await.map_err(internal_error)?,
        username: username.to_owned(),
        email: email.to_owned(),
        password,
        encryption_public_key: String::new(),
        signature_public_key: String::new(),
        created_at: now,
        updated_at: now,
    };

    hash_user_password(&mut user)?;

    let mut created_user = repository
        .add_user(user)
        .await
        .map_err(internal_error)?;

    // sanitize
    created_user.password.clear();
    created_user.encryption_public_key.clear();
    created_user.signature_public_key.clear();

    let json_response = serde_json::json!({
    "id": created_user.user_id.to_string(),
    "email": created_user.email,
    "username": created_user.username,
    "created_at": created_user.created_at,
});

    Ok((StatusCode::CREATED, Json(json_response)))
}

fn internal_error<E: std::fmt::Display>(err: E) -> (StatusCode, Json<serde_json::Value>) {
    let json_response = serde_json::json!({
        "status": "error",
        "message": format!("{err}"),
    });
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json_response))
}

fn internal_error_message(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    let json_response = serde_json::json!({
        "status": "error",
        "message": message,
    });
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json_response))
}
