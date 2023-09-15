use actix_web::{web::Data, HttpResponse};
use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Deserialize, Serialize};

use crate::db::AppState;
use crate::auth::{UserDataStruct, hash_password};
use crate::models::Users;

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginStruct {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
}


pub async fn fetch_users(data: Data<AppState>) -> HttpResponse {
    let query_result = sqlx::query_as!(Users, "SELECT * FROM users")
        .fetch_all(&data.db)
        .await;

    match query_result {
        Ok(Users) => HttpResponse::Ok().json(Users),
        Err(err) => {
            eprintln!("Database error: {:?}", err);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }
}


pub async fn login(user_data: actix_web::web::Json<LoginStruct>, data: Data<AppState>) -> HttpResponse {
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




 pub async fn create_user(user_data: actix_web::web::Json<UserDataStruct>, data: Data<AppState>) -> HttpResponse {
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
    
    let query_result = sqlx::query!(
        "INSERT INTO users (username, email, password) VALUES ($1, $2, $3)",
        username,
        email,
        hashed_password
    )
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


pub async fn hello() -> HttpResponse {
    HttpResponse::Ok().body("Hello, World!")
}