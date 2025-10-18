use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use once_cell::sync::Lazy;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt};
use tokio::sync::RwLock;

/// Hashes the provided password using Argon2id with a randomly generated salt.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

/// Verifies that the plaintext password matches the previously hashed password.
pub fn verify_password(
    password: &str,
    password_hash: &str,
) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(password_hash)?;
    let argon2 = Argon2::default();
    Ok(argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

#[derive(Debug)]
pub enum AuthServiceError {
    MissingSecret,
    Jwt(jsonwebtoken::errors::Error),
    Revoked,
}

impl fmt::Display for AuthServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthServiceError::MissingSecret => {
                write!(f, "JWT_SECRET environment variable is not set")
            }
            AuthServiceError::Jwt(err) => write!(f, "{err}"),
            AuthServiceError::Revoked => write!(f, "Token has been revoked"),
        }
    }
}

impl std::error::Error for AuthServiceError {}

impl From<jsonwebtoken::errors::Error> for AuthServiceError {
    fn from(value: jsonwebtoken::errors::Error) -> Self {
        AuthServiceError::Jwt(value)
    }
}

impl AuthServiceError {
    pub fn message(&self) -> &str {
        match self {
            AuthServiceError::MissingSecret => "Authentication service is not configured correctly",
            AuthServiceError::Jwt(_) => "Token verification failed",
            AuthServiceError::Revoked => "Token has been revoked",
        }
    }

    pub fn status_code(&self) -> axum::http::StatusCode {
        match self {
            AuthServiceError::MissingSecret => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            AuthServiceError::Jwt(_) | AuthServiceError::Revoked => {
                axum::http::StatusCode::UNAUTHORIZED
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: i32,
    pub username: String,
    pub exp: usize,
    pub iat: usize,
}

static REVOKED_TOKENS: Lazy<RwLock<HashSet<String>>> = Lazy::new(|| RwLock::new(HashSet::new()));

fn jwt_secret() -> Result<String, AuthServiceError> {
    std::env::var("JWT_SECRET").map_err(|_| AuthServiceError::MissingSecret)
}

fn jwt_expiration_minutes() -> i64 {
    std::env::var("JWT_EXPIRATION_MINUTES")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(60)
}

pub fn create_session_token(user_id: i32, username: &str) -> Result<String, AuthServiceError> {
    let secret = jwt_secret()?;
    let issued_at = Utc::now();
    let expires_at = issued_at + Duration::minutes(jwt_expiration_minutes());

    let claims = Claims {
        sub: user_id,
        username: username.to_string(),
        iat: issued_at.timestamp() as usize,
        exp: expires_at.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(AuthServiceError::from)
}

pub fn decode_token(token: &str) -> Result<Claims, AuthServiceError> {
    let secret = jwt_secret()?;
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .map(|data| data.claims)
    .map_err(AuthServiceError::from)
}

pub async fn verify_token(token: &str) -> Result<Claims, AuthServiceError> {
    if is_token_revoked(token).await {
        return Err(AuthServiceError::Revoked);
    }

    decode_token(token)
}

pub async fn revoke_token(token: &str) {
    let mut revoked = REVOKED_TOKENS.write().await;
    revoked.insert(token.to_string());
}

pub async fn is_token_revoked(token: &str) -> bool {
    let revoked = REVOKED_TOKENS.read().await;
    revoked.contains(token)
}

pub async fn clear_revoked_tokens() {
    let mut revoked = REVOKED_TOKENS.write().await;
    revoked.clear();
}

#[cfg(test)]
mod tests {
    use super::{
        clear_revoked_tokens, create_session_token, hash_password, revoke_token, verify_password,
        verify_token,
    };

    fn configure_secret() {
        unsafe {
            std::env::set_var("JWT_SECRET", "test_secret");
        }
    }

    #[test]
    fn successful_login_with_valid_credentials() {
        let password = "CorrectHorseBatteryStaple";
        let hash = hash_password(password).expect("hashing should succeed");

        let is_valid = verify_password(password, &hash).expect("verification should succeed");

        assert!(is_valid, "expected the password to verify successfully");
    }

    #[test]
    fn login_rejected_with_invalid_password() {
        let password = "CorrectHorseBatteryStaple";
        let hash = hash_password(password).expect("hashing should succeed");

        let is_valid = verify_password("Tr0ub4dor&3", &hash).expect("verification should succeed");

        assert!(
            !is_valid,
            "expected verification to fail for invalid password"
        );
    }

    #[tokio::test]
    async fn generates_and_validates_token() {
        configure_secret();
        clear_revoked_tokens().await;

        let token = create_session_token(1, "alice").expect("token creation should succeed");
        let claims = verify_token(&token).await.expect("token should verify");

        assert_eq!(claims.username, "alice");
        assert_eq!(claims.sub, 1);
    }

    #[tokio::test]
    async fn revoked_token_is_rejected() {
        configure_secret();
        clear_revoked_tokens().await;

        let token = create_session_token(1, "alice").expect("token creation should succeed");
        revoke_token(&token).await;

        let validation = verify_token(&token).await;
        assert!(
            validation.is_err(),
            "token should be rejected after revocation"
        );
    }
}
