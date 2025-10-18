use crate::api::rest::middleware::require_jwt;
use crate::application::commands::{
    create_user_command::create_user_command, login_user_command::login_user_command,
    logout_user_command::logout_user_command,
};
use crate::application::queries::get_all_users_query::get_all_users_query;
use axum::{
    Router, middleware,
    routing::{get, post},
};

pub fn create_router() -> Router {
    let protected_users_router = Router::new()
        .route("/", get(get_all_users_query))
        .route("/logout/", post(logout_user_command))
        .layer(middleware::from_fn(require_jwt));

    let users_router = Router::new()
        .route("/", post(create_user_command))
        .route("/login/", post(login_user_command))
        .merge(protected_users_router);

    let api_router = Router::new()
        .route(
            "/healthcheck/",
            get(crate::api::rest::healthcheck::health_checker_handler),
        )
        .nest("/users", users_router);

    Router::new().nest("/api", api_router)
}
