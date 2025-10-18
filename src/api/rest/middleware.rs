use std::convert::Infallible;

use axum::{
    Json,
    body::Body,
    http::{Request, StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::{IntoResponse, Response},
};
use log::{error, warn};
use serde_json::json;

use crate::application::services::auth::{Claims, verify_token};

#[derive(Clone, Debug)]
pub struct AuthContext {
    pub token: String,
    pub claims: Claims,
}

fn parse_bearer_token(header_value: &str) -> Option<&str> {
    let mut segments = header_value.split_whitespace();

    match (segments.next(), segments.next(), segments.next()) {
        (Some(scheme), Some(token), None) if scheme.eq_ignore_ascii_case("bearer") => {
            if token.is_empty() { None } else { Some(token) }
        }
        _ => None,
    }
}

fn json_response(status: StatusCode, level: &str, message: &str) -> Response {
    let payload = Json(json!({
        "status": level,
        "message": message,
    }));

    let mut response = payload.into_response();
    *response.status_mut() = status;
    response
}

pub async fn require_jwt(mut req: Request<Body>, next: Next) -> Result<Response, Infallible> {
    let raw_header = match req.headers().get(AUTHORIZATION) {
        Some(value) => value,
        None => {
            return Ok(json_response(
                StatusCode::UNAUTHORIZED,
                "fail",
                "Missing Authorization header",
            ));
        }
    };

    let header_value = match raw_header.to_str() {
        Ok(value) => value,
        Err(_) => {
            return Ok(json_response(
                StatusCode::UNAUTHORIZED,
                "fail",
                "Authorization header is not valid UTF-8",
            ));
        }
    };

    let token = match parse_bearer_token(header_value) {
        Some(token) => token.to_owned(),
        None => {
            return Ok(json_response(
                StatusCode::UNAUTHORIZED,
                "fail",
                "Authorization header must use the Bearer scheme",
            ));
        }
    };

    match verify_token(&token).await {
        Ok(claims) => {
            req.extensions_mut().insert(AuthContext {
                token: token.clone(),
                claims,
            });

            Ok(next.run(req).await)
        }
        Err(err) => {
            let status = err.status_code();
            if status.is_server_error() {
                error!("JWT validation failed: {err}");
            } else {
                warn!("JWT validation failed: {err}");
            }

            Ok(json_response(
                status,
                if status.is_server_error() {
                    "error"
                } else {
                    "fail"
                },
                err.message(),
            ))
        }
    }
}
