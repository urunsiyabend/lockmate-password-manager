pub mod api;
pub mod application;
pub mod domain;
pub mod infrastructure;
use api::rest::router::create_router;

use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, IF_MATCH};
use axum::http::{HeaderName, HeaderValue, Method};
use dotenvy::dotenv;
use infrastructure::{data::db_context::surrealdb_context::init_db, telemetry::init_telemetry};
use tower_http::cors::CorsLayer;

use tracing_subscriber::fmt;

use std::net::SocketAddr;

static X_VAULT_KEY: HeaderName = HeaderName::from_static("x-vault-key");

#[tokio::main]
async fn main() {
    let allowed_origins: [HeaderValue; 4] = [
        "http://localhost:5173".parse().unwrap(),   // Vite (dev)
        "http://127.0.0.1:5173".parse().unwrap(),
        "http://localhost:3000".parse().unwrap(),   // Next.js (dev)
        "http://127.0.0.1:3000".parse().unwrap(),
    ];

    dotenv().ok();
    let _ = fmt::try_init();
    init_telemetry();
    println!("▶ About to initialize DB…");

    match init_db().await {
        Ok(ctx) => println!("✔️ DB initialized: {:?}", ctx),
        Err(e) => {
            eprintln!("❌ init_db failed: {:?}", e);
            std::process::exit(1);
        }
    }

    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        // allow preflight + all verbs you actually use (PUT is used by update_vault_item)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_credentials(true)
        // include the custom and conditional headers your API requires
        .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE, IF_MATCH, X_VAULT_KEY.clone()])
        // optional: if you want clients to read these headers from responses
        .expose_headers([IF_MATCH]);

    let app = create_router().layer(cors);

    println!("Server running on http://127.0.0.1:10002");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:10002")
        .await
        .unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
