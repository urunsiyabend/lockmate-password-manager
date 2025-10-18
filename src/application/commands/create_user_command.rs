use axum::{Json, http::StatusCode, response::IntoResponse};

use super::login_user_command::hash_user_password;
use crate::{
    domain::models::user::User, infrastructure::data::repositories::user_repository::UserRepository,
};

pub async fn create_user_command(
    Json(body): Json<User>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repository = UserRepository::new();

    let mut user = body.to_owned();
    hash_user_password(&mut user)?;

    let mut user = repository.add_user(user.clone()).await.unwrap()[0].to_owned();
    user.password.clear();

    let json_response = serde_json::json!({
        "status": "success".to_string(),
        "data": user,
    });

    Ok((StatusCode::CREATED, Json(json_response)))
}
