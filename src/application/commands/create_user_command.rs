use axum::{http::StatusCode, response::IntoResponse, Json};

use crate::{domain::models::user::User, infrastructure::data::repositories::user_repository::UserRepository};

pub async fn create_user_command(
    Json(mut body): Json<User>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repository = UserRepository::new();

    let user = body.to_owned();

    let user = repository.add_user(user.clone()).await.unwrap()[0].to_owned();

    let json_response = serde_json::json!({
        "status": "success".to_string(),
        "data": user,
    });

    Ok((StatusCode::CREATED, Json(json_response)))
}