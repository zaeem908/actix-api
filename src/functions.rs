use crate::auth::{hash_password, UserDataStruct};
use crate::db::AppState;
use crate::error::AppError;
use crate::models::Users;
use actix_web::{web::Data, HttpResponse};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginStruct {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
}

pub struct UserController {
    pub username: String,
    pub email: String,
    pub password: String,
}

impl LoginStruct {
    pub async fn login(user_data: &LoginStruct, data: Data<AppState>) -> Result<String, AppError> {
        let query_result = sqlx::query!(
            "SELECT username, email, password FROM users WHERE email = $1",
            &user_data.email
        )
        .fetch_optional(&data.db)
        .await;

        match query_result {
            Ok(Some(row)) => {
                if bcrypt::verify(&user_data.password, &row.password).unwrap_or(false) {
                    let secret_key = std::env::var("SECRET_KEY").expect("SECRET_KEY must be set");

                    let token = encode(
                        &Header::default(),
                        &Claims {
                            sub: user_data.email.to_string(),
                        },
                        &EncodingKey::from_secret(secret_key.as_ref()),
                    );

                    if let Ok(token) = token {
                        println!("User {} is logged in successfully", row.username);
                        Ok(token)
                    } else {
                        Err(AppError::InternalServerError)
                    }
                } else {
                    Err(AppError::IncorrectPassword("invalid password".to_string()))
                }
            }
            Ok(None) => Err(AppError::InvalidEmail(
                "No user found with that email!".to_string(),
            )),
            Err(err) => {
                eprintln!("Error: {:?}", err);
                Err(AppError::InternalServerError)
            }
        }
    }
}

impl UserController {
    pub async fn fetch_users(data: Data<AppState>) -> Result<Vec<Users>, String> {
        let query_result = sqlx::query_as!(Users, "SELECT * FROM users")
            .fetch_all(&data.db)
            .await;

        match query_result {
            Ok(Users) => Ok(Users),
            Err(err) => {
                eprintln!("Database error: {:?}", err);
                Err("Internal Server Error".to_string())
            }
        }
    }

    pub async fn create_user(
        user_data: UserDataStruct,
        data: &Data<AppState>,
    ) -> Result<(), String> {
        if !user_data.is_valid_email() {
            return Err("invalid email".to_string());
        }
        if !user_data.is_valid_password() {
            return Err("invalid password".to_string());
        }

        let hashed_password = match hash_password(&user_data.password) {
            Ok(hashed) => hashed,
            Err(_) => {
                return Err("Internal Server Error".to_string());
            }
        };

        if let Err(_) = sqlx::query!(
            "INSERT INTO users (username, email, password) VALUES ($1, $2, $3)",
            &user_data.username,
            &user_data.email,
            &hashed_password
        )
        .execute(&data.db)
        .await
        {
            return Err("detected duplicate data! try again".to_string());
        }

        Ok(())
    }

    pub async fn hello() -> HttpResponse {
        HttpResponse::Ok().body("Hello, World!")
    }
}
