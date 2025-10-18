use crate::application::commands::{
    create_user_command::create_user_command, login_user_command::login_user_command,
};
use crate::application::queries::get_all_users_query::get_all_users_query;
use axum::{
    Router,
    routing::{get, post},
};

pub fn create_router() -> Router {
    let api_router = Router::new()
        .route(
            "/healthcheck/",
            get(crate::api::rest::healthcheck::health_checker_handler),
        )
        .route(
            "/users/",
            get(get_all_users_query).post(create_user_command),
        )
        .route("/users/login/", post(login_user_command));

    Router::new().nest("/api", api_router)
}
