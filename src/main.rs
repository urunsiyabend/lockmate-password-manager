pub mod domain;
pub mod application;
pub mod infrastructure;
pub mod api;
use api::rest::router::create_router;

use axum::http::{HeaderValue, Method};
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use tower_http::cors::CorsLayer;
use infrastructure::data::db_context::surrealdb_context::init_db;

#[tokio::main]
async fn main() {
    println!("▶ About to initialize DB…");

    match init_db().await {
        Ok(ctx) => println!("✔️ DB initialized: {:?}", ctx),
        Err(e)  => {
            eprintln!("❌ init_db failed: {:?}", e);
            std::process::exit(1);
        }
    }

    let cors = CorsLayer::new()
        .allow_origin("http://localhost:10002".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
        .allow_credentials(true)
        .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE]);

    let app = create_router().layer(cors);

    println!("Server running on http://127.0.0.1:10002");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:10002").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}