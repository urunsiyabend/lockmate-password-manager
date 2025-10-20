use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, Extension},
    http::{HeaderMap, HeaderName, StatusCode},
    response::IntoResponse,
};
use serde_json::{Value, json};

use crate::api::rest::middleware::AuthContext;
use crate::application::services::{
    audit::log_audit_event,
    security_health::{SecurityHealthError, get_security_health_summary, refresh_security_health},
    vault::VaultDataError,
};

const VAULT_KEY_HEADER: &str = "x-vault-key";

type ApiError = (StatusCode, Json<Value>);

pub async fn get_security_health(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<impl IntoResponse, ApiError> {
    let user_id = ctx.claims.sub.to_string();
    let summary = get_security_health_summary(&user_id)
        .await
        .map_err(map_service_error)?;

    log_audit_event(
        user_id,
        None,
        "security.health.view",
        Some(addr.ip().to_string()),
        Some(json!({ "findings": summary.findings.len() })),
    )
    .await;

    Ok(Json(json!({
        "status": "success",
        "results": summary.findings.len(),
        "data": summary,
    })))
}

pub async fn run_security_health_check(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let vault_key = extract_vault_key(&headers)?;
    let user_id = ctx.claims.sub.to_string();

    let summary = refresh_security_health(&user_id, &vault_key)
        .await
        .map_err(map_service_error)?;

    log_audit_event(
        user_id,
        None,
        "security.health.check",
        Some(addr.ip().to_string()),
        Some(json!({
            "findings": summary.findings.len(),
            "generated_at": summary.generated_at,
        })),
    )
    .await;

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "status": "success",
            "results": summary.findings.len(),
            "data": summary,
        })),
    ))
}

fn extract_vault_key(headers: &HeaderMap) -> Result<String, ApiError> {
    let header_name = HeaderName::from_static(VAULT_KEY_HEADER);
    let value = headers
        .get(&header_name)
        .ok_or_else(|| map_vault_error(VaultDataError::MissingKey))?;

    let key = value
        .to_str()
        .map_err(|_| map_vault_error(VaultDataError::InvalidKey))?
        .to_owned();

    if key.trim().is_empty() {
        return Err(map_vault_error(VaultDataError::InvalidKey));
    }

    Ok(key)
}

fn map_service_error(err: SecurityHealthError) -> ApiError {
    match err {
        SecurityHealthError::Database(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "message": format!("database error: {error}"),
            })),
        ),
        SecurityHealthError::Vault(error) => map_vault_error(error),
        SecurityHealthError::Breach(error) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "status": "error",
                "message": error.to_string(),
            })),
        ),
    }
}

fn map_vault_error(err: VaultDataError) -> ApiError {
    use crate::infrastructure::security::crypto::CryptoError;

    match err {
        VaultDataError::MissingKey | VaultDataError::InvalidKey => {
            (StatusCode::BAD_REQUEST, Json(err.to_json()))
        }
        VaultDataError::Serialize(_)
        | VaultDataError::Deserialize(_)
        | VaultDataError::Crypto(CryptoError::Encrypt)
        | VaultDataError::Crypto(CryptoError::Randomness)
        | VaultDataError::Crypto(CryptoError::InvalidMasterKey)
        | VaultDataError::Crypto(CryptoError::InvalidVaultKey)
        | VaultDataError::Crypto(CryptoError::MissingMasterKey) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "message": err.to_string(),
            })),
        ),
        VaultDataError::Crypto(CryptoError::Decrypt) => (
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "fail",
                "message": "Unable to decrypt with the provided vault key.",
            })),
        ),
    }
}
