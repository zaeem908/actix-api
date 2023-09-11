use actix_web::{web::Data, App, HttpResponse, HttpServer};
use dotenv::dotenv;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};


pub struct AppState {
    db: Pool<Postgres>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Error building a connection pool");

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(AppState { db: pool.clone() }))
            .route("/users", actix_web::web::get().to(fetch_users))
            .route("/", actix_web::web::get().to(hello))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

async fn fetch_users(data: Data<AppState>) -> HttpResponse {
    let query_result = sqlx::query_as::<_, (i32, String)>("SELECT id, name FROM mytable")
        .fetch_all(&data.db)
        .await;

    match query_result {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(err) => {
            eprintln!("Database error: {:?}", err);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }
}

async fn hello() -> HttpResponse {
    HttpResponse::Ok().body("Hello, World!")
}