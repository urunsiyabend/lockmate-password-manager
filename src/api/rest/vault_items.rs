use axum::{
    Json,
    extract::{Extension, Path},
    http::{HeaderMap, HeaderName, StatusCode, header::IF_MATCH},
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use surrealdb::{Error, err::Error::Thrown};

use crate::api::rest::middleware::AuthContext;
use crate::application::services::vault::{self, VaultDataError};
use crate::domain::models::vault_item::{
    NewVaultItemRecord, VaultItemPayload, VaultItemRecord, VaultItemView,
};
use crate::infrastructure::{
    data::repositories::vault_item_repository::VaultItemRepository,
    security::crypto::VaultItemCiphertext,
};

const VAULT_KEY_HEADER: &str = "x-vault-key";

type ApiError = (StatusCode, Json<Value>);

#[derive(Deserialize)]
pub struct VaultItemRequest {
    pub folder_id: Option<String>,
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
}

pub async fn create_vault_item(
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
    Json(body): Json<VaultItemRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let vault_key = extract_vault_key(&headers)?;
    let payload = payload_from_request(&body);

    let ciphertext = vault::encrypt_payload(&vault_key, &payload).map_err(map_vault_error)?;
    let now = Utc::now();
    let repository = VaultItemRepository::new();

    let record = NewVaultItemRecord {
        user_id: ctx.claims.sub.to_string(),
        folder_id: body.folder_id.clone(),
        ciphertext: ciphertext.ciphertext,
        nonce: ciphertext.nonce,
        created_at: now,
        updated_at: now,
    };

    let created = repository.create(record).await.map_err(map_db_error)?;
    let decrypted = decrypt_record(&created, &vault_key)?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "status": "success",
            "data": VaultItemView::from_parts(&created, decrypted),
        })),
    ))
}

pub async fn list_vault_items(
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let vault_key = extract_vault_key(&headers)?;
    let repository = VaultItemRepository::new();
    let user_id = ctx.claims.sub.to_string();

    let records = repository
        .list_by_user(&user_id)
        .await
        .map_err(map_db_error)?;

    let mut items = Vec::with_capacity(records.len());
    for record in records {
        let decrypted = decrypt_record(&record, &vault_key)?;
        items.push(VaultItemView::from_parts(&record, decrypted));
    }

    Ok(Json(json!({
        "status": "success",
        "results": items.len(),
        "data": items,
    })))
}

pub async fn get_vault_item(
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
    Path(item_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let vault_key = extract_vault_key(&headers)?;
    let repository = VaultItemRepository::new();
    let user_id = ctx.claims.sub.to_string();

    let record = repository
        .get_by_id_for_user(&user_id, &item_id)
        .await
        .map_err(map_db_error)?;

    let decrypted = decrypt_record(&record, &vault_key)?;
    Ok(Json(json!({
        "status": "success",
        "data": VaultItemView::from_parts(&record, decrypted),
    })))
}

pub async fn update_vault_item(
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
    Path(item_id): Path<String>,
    Json(body): Json<VaultItemRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let vault_key = extract_vault_key(&headers)?;
    let expected_updated_at = parse_if_match(&headers)?;
    let payload = payload_from_request(&body);

    let ciphertext = vault::encrypt_payload(&vault_key, &payload).map_err(map_vault_error)?;
    let repository = VaultItemRepository::new();
    let user_id = ctx.claims.sub.to_string();

    let current = repository
        .get_by_id_for_user(&user_id, &item_id)
        .await
        .map_err(map_db_error)?;

    if current.updated_at != expected_updated_at {
        return Err(conflict_error());
    }

    let updated = repository
        .update_for_user(
            &item_id,
            &user_id,
            body.folder_id.clone(),
            ciphertext.ciphertext,
            ciphertext.nonce,
            expected_updated_at,
        )
        .await
        .map_err(map_db_error)?;

    let Some(updated) = updated else {
        return Err(conflict_error());
    };

    let decrypted = decrypt_record(&updated, &vault_key)?;
    Ok(Json(json!({
        "status": "success",
        "data": VaultItemView::from_parts(&updated, decrypted),
    })))
}

pub async fn delete_vault_item(
    Extension(ctx): Extension<AuthContext>,
    headers: HeaderMap,
    Path(item_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let expected_updated_at = parse_if_match(&headers)?;
    let repository = VaultItemRepository::new();
    let user_id = ctx.claims.sub.to_string();

    let current = repository
        .get_by_id_for_user(&user_id, &item_id)
        .await
        .map_err(map_db_error)?;

    if current.updated_at != expected_updated_at {
        return Err(conflict_error());
    }

    let deleted = repository
        .delete_for_user(&item_id, &user_id, expected_updated_at)
        .await
        .map_err(map_db_error)?;

    if !deleted {
        return Err(conflict_error());
    }

    Ok(StatusCode::NO_CONTENT)
}

fn conflict_error() -> ApiError {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "status": "fail",
            "message": "The vault item has been modified by another request.",
        })),
    )
}

fn payload_from_request(body: &VaultItemRequest) -> VaultItemPayload {
    VaultItemPayload {
        title: body.title.clone(),
        username: body.username.clone(),
        password: body.password.clone(),
        url: body.url.clone(),
        notes: body.notes.clone(),
    }
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
    Ok(key)
}

fn parse_if_match(headers: &HeaderMap) -> Result<DateTime<Utc>, ApiError> {
    let value = headers.get(IF_MATCH).ok_or((
        StatusCode::PRECONDITION_REQUIRED,
        Json(json!({
            "status": "fail",
            "message": "The If-Match header is required for this operation.",
        })),
    ))?;

    let value = value.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "fail",
                "message": "The If-Match header must be a valid RFC3339 timestamp.",
            })),
        )
    })?;

    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "fail",
                    "message": "The If-Match header must be a valid RFC3339 timestamp.",
                })),
            )
        })
}

fn decrypt_record(record: &VaultItemRecord, vault_key: &str) -> Result<VaultItemPayload, ApiError> {
    let ciphertext =
        vault::decrypt_payload(vault_key, &crypto_record(record)).map_err(map_vault_error)?;
    Ok(ciphertext)
}

fn crypto_record(record: &VaultItemRecord) -> VaultItemCiphertext {
    VaultItemCiphertext {
        ciphertext: record.ciphertext.clone(),
        nonce: record.nonce.clone(),
    }
}

fn map_db_error(err: Error) -> ApiError {
    match err {
        Error::Db(Thrown(message)) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "status": "fail", "message": message })),
        ),
        other => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "message": format!("database error: {other}"),
            })),
        ),
    }
}

fn map_vault_error(err: VaultDataError) -> ApiError {
    use crate::infrastructure::security::crypto::CryptoError;

    match &err {
        VaultDataError::MissingKey | VaultDataError::InvalidKey => {
            (StatusCode::BAD_REQUEST, Json(err.to_json()))
        }
        VaultDataError::Serialize(_) | VaultDataError::Deserialize(_) => (
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
                "message": "Unable to decrypt the vault item with the provided key.",
            })),
        ),
        VaultDataError::Crypto(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "message": err.to_string(),
            })),
        ),
    }
}
