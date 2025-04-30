use axum::Json;
use axum::response::IntoResponse;
use crate::domain::models::user::User;
use crate::infrastructure::data::repositories::user_repository::UserRepository;

pub async fn get_all_users_query() -> impl IntoResponse {
    let repository = UserRepository::new();

    let mut todos: Vec<User> = Vec::new();
    if let Ok(result) = repository.get_all().await {
        todos = result;
    }

    let json_response = serde_json::json!({
        "status": "success",
        "results": todos.len(),
        "todos": todos,
    });

    Json(json_response)
}