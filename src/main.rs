use actix_web::{web::Data, App, HttpResponse, HttpServer};
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use regex::Regex;
use bcrypt::{hash, DEFAULT_COST};
extern crate jsonwebtoken as jwt;
use jwt::{Header,  Algorithm, Validation, encode, decode, EncodingKey};



pub struct AppState {
    db: Pool<Postgres>, 
}

#[derive(Deserialize)]

pub struct UserDataStruct {
  username:String,
  email:String,
  password:String
}

#[derive(Deserialize)]
pub struct LoginStruct {
    email:String,
    password:String
}
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub : String
}

pub fn hash_password(pwd:&str) -> Result<String, bcrypt::BcryptError> {
       hash(pwd, DEFAULT_COST)
}
impl UserDataStruct {
    fn is_valid_email(&self) -> bool {
        let re = Regex::new(r"^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}$").unwrap();
        re.is_match(&self.email)
    }

    fn is_valid_password(&self) -> bool {
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
            .route("/login", actix_web::web::post().to(login))
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

async fn login(user_data: actix_web::web::Json<LoginStruct>, data: Data<AppState>) -> HttpResponse {
    let email = &user_data.email;
    let password = &user_data.password;


    let query_result = sqlx::query_as::<_, (String, String, String)>("SELECT username, email, password FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(&data.db)
        .await;

    match query_result {
        Ok(Some((stored_username,stored_email, stored_password))) => {
            println!("Found user with email: {}, stored password: {}", stored_email, stored_password);

            if bcrypt::verify(password, &stored_password).unwrap_or(false) {
                let secret_key = std::env::var("SECRET_KEY").expect("SECTET_KEY must be set");

                let token = encode(
                    &Header::default(),
                    &Claims { sub: email.to_string() },
                    &EncodingKey::from_secret(secret_key.as_ref()),
                );
                println!("Generated token: {:?}", token);
                println!("user {} is logged in succesfully", stored_username);
                HttpResponse::Ok().json("succesfully logged in!")
            } else {
                HttpResponse::Unauthorized().json("Invalid credentials")
            }
        }
        Ok(None) => {
            HttpResponse::Unauthorized().json("No user found with that email!")
        }
        Err(err) => {
            eprintln!("Error: {:?}", err);
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

    let hashed_password = hash_password(password).unwrap();
    
    let query_result = sqlx::query(
        "INSERT INTO users (username, email, password) VALUES ($1, $2, $3)"
    )
    .bind(username)
    .bind(email)
    .bind(hashed_password)
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