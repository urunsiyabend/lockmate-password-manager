use std::collections::HashSet;
use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, Extension, Query},
    http::StatusCode,
};
use once_cell::sync::OnceCell;
use serde::Deserialize;
use serde_json::{Value, json};
use surrealdb::{Error, err::Error::Thrown};

use crate::api::rest::middleware::AuthContext;
use crate::application::services::audit::record_audit_query;
use crate::infrastructure::data::repositories::audit_entry_repository::AuditEntryRepository;

const DEFAULT_QUERY_LIMIT: usize = 100;
const MAX_QUERY_LIMIT: usize = 500;

static ADMIN_USER_IDS: OnceCell<HashSet<i32>> = OnceCell::new();

type ApiError = (StatusCode, Json<Value>);

#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    pub user_id: Option<String>,
    pub action: Option<String>,
    pub limit: Option<usize>,
}

fn admin_user_ids() -> &'static HashSet<i32> {
    ADMIN_USER_IDS.get_or_init(|| {
        std::env::var("ADMIN_USER_IDS")
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .filter_map(|segment| segment.trim().parse::<i32>().ok())
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default()
    })
}

fn ensure_admin(ctx: &AuthContext) -> Result<(), ApiError> {
    if admin_user_ids().contains(&ctx.claims.sub) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "fail",
                "message": "Admin access required",
            })),
        ))
    }
}

fn map_db_error(err: Error) -> ApiError {
    match err {
        Error::Db(Thrown(message)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "error",
                "message": message,
            })),
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

fn extract_ip(connect_info: &SocketAddr) -> Option<String> {
    Some(connect_info.ip().to_string())
}

pub async fn list_audit_logs(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(ctx): Extension<AuthContext>,
    Query(params): Query<AuditLogQuery>,
) -> Result<Json<Value>, ApiError> {
    ensure_admin(&ctx)?;

    let limit = params
        .limit
        .unwrap_or(DEFAULT_QUERY_LIMIT)
        .min(MAX_QUERY_LIMIT)
        .max(1);

    record_audit_query("admin_list");

    let repository = AuditEntryRepository::new();
    let entries = repository
        .query_logs(params.user_id.as_deref(), params.action.as_deref(), limit)
        .await
        .map_err(map_db_error)?;

    Ok(Json(json!({
        "status": "success",
        "results": entries.len(),
        "source_ip": extract_ip(&addr),
        "data": entries,
    })))
}
