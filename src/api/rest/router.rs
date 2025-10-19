use crate::api::rest::{
    middleware::require_jwt,
    shares::{
        accept_invitation, create_share_invitations, decline_invitation, list_pending_invitations,
        list_share_recipients, list_shared_items, revoke_recipient, revoke_share,
    },
    vault_items::{
        create_vault_item, delete_vault_item, get_vault_item, list_vault_items, update_vault_item,
    },
};
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

    let vault_items_router = Router::new()
        .route("/", get(list_vault_items).post(create_vault_item))
        .route(
            "/:item_id/",
            get(get_vault_item)
                .put(update_vault_item)
                .delete(delete_vault_item),
        )
        .layer(middleware::from_fn(require_jwt));

    let shares_router = Router::new()
        .route("/:item_id/invitations/", post(create_share_invitations))
        .route("/:item_id/recipients/", get(list_share_recipients))
        .route(
            "/:share_id/recipients/:recipient_id/revoke/",
            post(revoke_recipient),
        )
        .route("/:share_id/revoke/", post(revoke_share))
        .layer(middleware::from_fn(require_jwt));

    let invitations_router = Router::new()
        .route("/", get(list_pending_invitations))
        .route("/:invitation_id/accept/", post(accept_invitation))
        .route("/:invitation_id/decline/", post(decline_invitation))
        .layer(middleware::from_fn(require_jwt));

    let me_router = Router::new()
        .route("/shared-items/", get(list_shared_items))
        .layer(middleware::from_fn(require_jwt));

    let api_router = Router::new()
        .route(
            "/healthcheck/",
            get(crate::api::rest::healthcheck::health_checker_handler),
        )
        .nest("/users", users_router)
        .nest("/vault/items", vault_items_router)
        .nest("/shares", shares_router)
        .nest("/invitations", invitations_router)
        .nest("/me", me_router);

    Router::new().nest("/api", api_router)
}
