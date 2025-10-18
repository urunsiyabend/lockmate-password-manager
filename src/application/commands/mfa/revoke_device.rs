use axum::{
    Json,
    extract::{Extension, Path},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use crate::{
    api::rest::middleware::AuthContext,
    infrastructure::data::repositories::mfa_repository::MfaRepository,
};

use super::responses::{json_error, json_success};

pub async fn revoke_mfa_device(
    Extension(auth): Extension<AuthContext>,
    Path(device_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repository = MfaRepository::new();
    let device = repository
        .get_by_id(&device_id)
        .await
        .map_err(|_| json_error(StatusCode::NOT_FOUND, "MFA device not found"))?;

    if device.user_id != auth.claims.sub {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "You do not have permission to revoke this device",
        ));
    }

    repository.delete(&device_id).await.map_err(|err| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to revoke MFA device: {err}"),
        )
    })?;

    Ok(json_success(json!({
        "device_id": device_id,
        "revoked": true,
    })))
}
