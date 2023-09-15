use actix_web::{ App, HttpServer};
use dotenv::dotenv;
mod routes;
mod db;
mod auth;
mod models;

use db::create_pool;
use routes::configure_routes;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = create_pool(&database_url).await;
    
    HttpServer::new(move || {
        App::new()
            .configure(configure_routes)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}



