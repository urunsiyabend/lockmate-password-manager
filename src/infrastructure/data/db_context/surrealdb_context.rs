use once_cell::sync::Lazy;
use surrealdb::{
    Surreal,
    engine::remote::ws::{Client, Ws},
    opt::auth::Root,
};

pub static DB: Lazy<Surreal<Client>> = Lazy::new(Surreal::init);

pub(crate) async fn init_db() -> Result<(), surrealdb::Error> {
    let db_url = "localhost:10001";

    println!("▶ Connecting to SurrealDB at {}", db_url);
    let _ = DB.connect::<Ws>(db_url).await?;
    println!("✔ Connected to SurrealDB");

    println!("▶ Signing in…");
    let _ = DB
        .signin(Root {
            username: "root",
            password: "root",
        })
        .await;
    println!("✔ Signed in");

    println!("▶ Selecting namespace+database…");
    let _ = DB.use_ns("users").use_db("users").await?;
    println!("✔ Namespace ‘users’ and database ‘users’ selected");

    Ok(())
}
