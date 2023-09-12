use actix_web::{web::Data, App, HttpResponse, HttpServer};
use dotenv::dotenv;
use serde::Deserialize;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use regex::Regex;

pub struct AppState {
    db: Pool<Postgres>,
}

#[derive(Deserialize)]

pub struct UserDataStruct {
  username:String,
  email:String,
  password:String
}

impl UserDataStruct {
    // Custom validation function for email
    fn is_valid_email(&self) -> bool {
        // Regular expression pattern for a simple email validation
        let re = Regex::new(r"^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}$").unwrap();
        re.is_match(&self.email)
    }

    // Custom validation function for password
    fn is_valid_password(&self) -> bool {
        // Password validation criteria (e.g., minimum length)
        self.password.len() >= 8
    }
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
            .route("/create-user", actix_web::web::post().to(create_user))
            .route("/", actix_web::web::get().to(hello))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

async fn fetch_users(data: Data<AppState>) -> HttpResponse {
    let query_result = sqlx::query_as::<_, (i32, String, String, String)>("SELECT * FROM users")
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

async fn create_user(user_data: actix_web::web::Json<UserDataStruct>, data: Data<AppState>) -> HttpResponse {
    let username = &user_data.username;
    let email = &user_data.email;
    let password = &user_data.password;

    if !user_data.is_valid_email() {
        return HttpResponse::BadRequest().json("invalid email")
    }
    if !user_data.is_valid_password() {
        return HttpResponse::BadRequest().json("invalid password")
    }
    
    // Execute an SQL insert query to add the new user to the "users" table
    let query_result = sqlx::query(
        "INSERT INTO users (username, email, password) VALUES ($1, $2, $3)"
    )
    .bind(username)
    .bind(email)
    .bind(password)
    .execute(&data.db)
    .await;

    match query_result {
        Ok(_) => HttpResponse::Ok().body("User created successfully"),
        Err(err) => {
            eprintln!("Database error: {:?}", err);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }
}
 

async fn hello() -> HttpResponse {
    HttpResponse::Ok().body("Hello, World!")
}