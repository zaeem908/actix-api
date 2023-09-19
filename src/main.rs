use actix_web::{App, HttpServer};
use dotenv::dotenv;
mod auth;
mod db;
mod error;
mod handlers;
mod models;
mod routes;
use db::{create_pool, AppState};
use routes::configure_routes;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = create_pool(&database_url).await;

    HttpServer::new(move || {
        App::new()
            .configure(|cfg| configure_routes(cfg))
            .data(AppState { db: pool.clone() })
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
