use axum::{Json, extract::Extension, http::StatusCode, response::IntoResponse};

use crate::{api::rest::middleware::AuthContext, application::services::auth::revoke_token};

pub async fn logout_user_command(
    Extension(auth_ctx): Extension<AuthContext>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    revoke_token(&auth_ctx.token).await;

    let json_response = serde_json::json!({
        "status": "success",
        "message": "Logged out successfully",
    });

    Ok((StatusCode::OK, Json(json_response)))
}
