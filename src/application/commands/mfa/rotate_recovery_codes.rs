use axum::{Json, extract::Extension, http::StatusCode, response::IntoResponse};
use serde::Deserialize;
use serde_json::json;

use crate::{
    api::rest::middleware::AuthContext, application::services::mfa::refresh_backup_codes,
    infrastructure::data::repositories::mfa_repository::MfaRepository,
};

use super::responses::{json_error, json_success, map_mfa_error};

#[derive(Debug, Deserialize)]
pub struct RotateRecoveryCodesRequest {
    pub device_id: Option<String>,
}

pub async fn rotate_recovery_codes(
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<RotateRecoveryCodesRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repository = MfaRepository::new();

    let mut device = if let Some(ref id) = body.device_id {
        let device = repository
            .get_by_id(id)
            .await
            .map_err(|_| json_error(StatusCode::NOT_FOUND, "MFA device not found"))?;
        if device.user_id != auth.claims.sub {
            return Err(json_error(
                StatusCode::FORBIDDEN,
                "You do not have access to this MFA device",
            ));
        }
        device
    } else {
        repository
            .get_active_by_user(auth.claims.sub)
            .await
            .map_err(|err| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Failed to load MFA device: {err}"),
                )
            })?
            .ok_or_else(|| json_error(StatusCode::NOT_FOUND, "No active MFA device"))?
    };

    if !device.enabled {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "MFA enrollment has not been completed",
        ));
    }

    let codes = refresh_backup_codes(&mut device).map_err(map_mfa_error)?;

    repository.upsert(&device).await.map_err(|err| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to persist recovery codes: {err}"),
        )
    })?;

    Ok(json_success(json!({
        "device_id": device.id,
        "backup_codes": codes,
    })))
}
