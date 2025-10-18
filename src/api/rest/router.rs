use crate::api::rest::middleware::require_jwt;
use crate::application::commands::{
    create_user_command::create_user_command,
    login_user_command::login_user_command,
    logout_user_command::logout_user_command,
    mfa::{
        enroll_start::start_mfa_enrollment, enroll_verify::verify_mfa_enrollment,
        login_verify::verify_mfa_login, revoke_device::revoke_mfa_device,
        rotate_recovery_codes::rotate_recovery_codes,
    },
};
use crate::application::queries::{
    get_all_users_query::get_all_users_query, mfa_status_query::get_mfa_status,
};
use axum::{
    Router, middleware,
    routing::{delete, get, post},
};

pub fn create_router() -> Router {
    let protected_users_router = Router::new()
        .route("/", get(get_all_users_query))
        .route("/logout/", post(logout_user_command))
        .layer(middleware::from_fn(require_jwt));

    let protected_mfa_router = Router::new()
        .route("/status/", get(get_mfa_status))
        .route("/enroll/start/", post(start_mfa_enrollment))
        .route("/enroll/verify/", post(verify_mfa_enrollment))
        .route("/recovery/rotate/", post(rotate_recovery_codes))
        .route("/device/:device_id/revoke/", delete(revoke_mfa_device))
        .layer(middleware::from_fn(require_jwt));

    let mfa_router = Router::new()
        .route("/login/verify/", post(verify_mfa_login))
        .merge(protected_mfa_router);

    let users_router = Router::new()
        .route("/", post(create_user_command))
        .route("/login/", post(login_user_command))
        .merge(protected_users_router)
        .nest("/mfa", mfa_router);

    let api_router = Router::new()
        .route(
            "/healthcheck/",
            get(crate::api::rest::healthcheck::health_checker_handler),
        )
        .nest("/users", users_router);

    Router::new().nest("/api", api_router)
}
