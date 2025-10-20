use axum::{Json, response::IntoResponse};
use serde::Deserialize;
use serde_json::json;

use crate::application::services::password::{
    PassphraseOptions, evaluate_strength, generate_passphrase,
};

#[derive(Deserialize)]
pub struct PasswordGenerationRequest {
    #[serde(default = "default_word_count")]
    pub word_count: usize,
    #[serde(default = "default_separator")]
    pub separator: String,
    #[serde(default = "default_true")]
    pub capitalize: bool,
    #[serde(default = "default_true")]
    pub include_number: bool,
    #[serde(default = "default_number_digits")]
    pub number_digits: usize,
    #[serde(default)]
    pub include_symbol: bool,
    #[serde(default = "default_symbol_set")]
    pub symbol_set: String,
}

#[derive(Deserialize)]
pub struct PasswordStrengthRequest {
    pub password: String,
}

pub async fn generate_password(Json(body): Json<PasswordGenerationRequest>) -> impl IntoResponse {
    let separator_owned = normalize_separator(&body.separator);
    let symbol_set_owned = normalize_symbol_set(&body.symbol_set);

    let result = generate_passphrase(PassphraseOptions {
        word_count: body.word_count,
        separator: separator_owned.as_str(),
        capitalize: body.capitalize,
        include_number: body.include_number,
        number_digits: body.number_digits,
        include_symbol: body.include_symbol,
        symbol_set: symbol_set_owned.as_str(),
    });

    Json(json!({
        "password": result.password,
        "strength": result.strength,
    }))
}

pub async fn password_strength(Json(body): Json<PasswordStrengthRequest>) -> impl IntoResponse {
    let report = evaluate_strength(&body.password);
    Json(report)
}

fn default_word_count() -> usize {
    4
}

fn default_separator() -> String {
    "-".to_string()
}

fn default_true() -> bool {
    true
}

fn default_number_digits() -> usize {
    2
}

fn default_symbol_set() -> String {
    "!@#$%^&*".to_string()
}

fn normalize_separator(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "-".to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalize_symbol_set(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        default_symbol_set()
    } else {
        trimmed.to_string()
    }
}
