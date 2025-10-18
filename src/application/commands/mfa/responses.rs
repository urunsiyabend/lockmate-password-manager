use axum::{Json, http::StatusCode};
use serde_json::{Value, json};

use crate::application::services::mfa::MfaError;

pub fn json_success(data: Value) -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({ "status": "success", "data": data })),
    )
}

pub fn json_created(data: Value) -> (StatusCode, Json<Value>) {
    (
        StatusCode::CREATED,
        Json(json!({ "status": "success", "data": data })),
    )
}

pub fn json_error(status: StatusCode, message: &str) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(
            json!({ "status": if status.is_server_error() { "error" } else { "fail" }, "message": message }),
        ),
    )
}

pub fn map_mfa_error(err: MfaError) -> (StatusCode, Json<Value>) {
    match err {
        MfaError::Validation(message) => json_error(StatusCode::BAD_REQUEST, &message),
        MfaError::LockedOut(until) => json_error(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("Too many failed attempts. Try again after {until}"),
        ),
        MfaError::Replay => json_error(
            StatusCode::CONFLICT,
            "Code has already been used in this window",
        ),
        MfaError::Internal => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "An internal error occurred",
        ),
        MfaError::EnrollmentExpired => {
            json_error(StatusCode::GONE, "Enrollment session has expired")
        }
        MfaError::EnrollmentNotPending => {
            json_error(StatusCode::BAD_REQUEST, "No pending enrollment")
        }
        MfaError::ChallengeNotFound => {
            json_error(StatusCode::NOT_FOUND, "Login challenge was not found")
        }
        MfaError::ChallengeExpired => json_error(StatusCode::GONE, "Login challenge has expired"),
        MfaError::Encryption(inner) => match inner {
            crate::infrastructure::security::encryption::EncryptionError::MissingKey => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "MFA encryption key is not configured",
            ),
            crate::infrastructure::security::encryption::EncryptionError::InvalidKey => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "MFA encryption key is invalid",
            ),
            crate::infrastructure::security::encryption::EncryptionError::Encrypt
            | crate::infrastructure::security::encryption::EncryptionError::Decrypt => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to process MFA secret",
            ),
        },
    }
}
