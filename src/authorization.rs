use crate::auth::{hash_password, UserDataStruct};
use crate::db::AppState;
use crate::error::AppError;
use crate::models::Users;
use actix_web::web::{self, Data};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginForm {
    pub email: String,
    pub password: String,
}

impl LoginForm {
    pub async fn login(&self, db: &Pool<Postgres>) -> Result<String, AppError> {
        let query_result = sqlx::query!(
            "SELECT username, email, password FROM users WHERE email = $1",
            &self.email
        )
        .fetch_optional(db)
        .await;

        match query_result {
            Ok(Some(row)) => {
                if bcrypt::verify(&self.password, &row.password).unwrap_or(false) {
                    let secret_key = std::env::var("SECRET_KEY").expect("SECRET_KEY must be set");

                    let token = encode(
                        &Header::default(),
                        &Claims {
                            sub: self.email.to_string(),
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

pub struct UserController {
    pub username: String,
    pub email: String,
    pub password: String,
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ForgotPassword {
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPayload {
    pub email: String,
    pub exp: i64,
}

impl ForgotPassword {
    pub async fn forgot_password(&self, db: &Pool<Postgres>) -> Result<(), AppError> {
        let query = sqlx::query!("SELECT * FROM users WHERE email = $1", &self.email)
            .fetch_all(db)
            .await;

        match query {
            Ok(rows) => {
                if rows.is_empty() {
                    Err(AppError::InvalidEmail(
                        "no user found with this email".to_string(),
                    ))
                } else {
                    let secret_key = std::env::var("SECRET_KEY").expect("SECRET_KEY must be set");

                    let token = encode(
                        &Header::default(),
                        &TokenPayload {
                            email: self.email.to_string(),
                            exp: (Utc::now() + Duration::minutes(10)).timestamp(),
                        },
                        &EncodingKey::from_secret(secret_key.as_ref()),
                    );
                    println!("Generated token: {:?}", token);
                    Ok(())
                }
            }
            Err(err) => {
                eprintln!("Database error: {:?}", err);
                Err(AppError::InternalServerError)
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResetTokenPayload {
    pub email: String,
    pub exp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResetPassword {
    pub token: String,
    pub new_password: String,
}

impl ResetPassword {
    pub async fn reset_password(&self, db: &Pool<Postgres>) -> Result<(), AppError> {
        let secret_key = std::env::var("SECRET_KEY").expect("SECRET_KEY must be set");
        let decoding_key = DecodingKey::from_secret(secret_key.as_ref());
        let validation = Validation::default();
        let token_data = decode::<ResetTokenPayload>(&self.token, &decoding_key, &validation);

        match token_data {
            Ok(decoded) => {
                if Utc::now().timestamp() > decoded.claims.exp {
                    return Err(AppError::ExpiredToken);
                }

                let email = &decoded.claims.email;
                let hashed_password_result = hash_password(&self.new_password);
                let hashed_password = match hashed_password_result {
                    Ok(hashed) => hashed,
                    Err(_) => {
                        eprintln!("Failed to hash password");
                        return Err(AppError::InternalServerError);
                    }
                };
                let result = sqlx::query!(
                    "UPDATE users SET password = $1 WHERE email = $2",
                    &hashed_password,
                    email
                )
                .execute(db)
                .await;

                match result {
                    Ok(_) => Ok(()),
                    Err(err) => {
                        eprintln!("Database error: {:?}", err);
                        Err(AppError::InternalServerError)
                    }
                }
            }
            Err(_) => Err(AppError::InvalidToken),
        }
    }
}

////////////////////////////////////////jdcjdj

#[derive(Debug, Serialize, Deserialize)]
pub struct NewUserProfile {
    pub age: i32,
    pub weight: f64,
    pub height: f64,
    pub goal_physique_id: i32,
}

impl NewUserProfile {
    pub async fn create_user_profile(
        &self,
        path: web::Path<(i32,)>,
        db: &Pool<Postgres>, // Database connection pool
    ) -> Result<(), AppError> {
        let user_id = path.0;

        // Check if the user already exists, if not, insert a new profile
        let user_exists = sqlx::query!("SELECT * FROM user_profiles WHERE user_id = $1", user_id)
            .fetch_optional(db)
            .await;

        let _ = match user_exists {
            Ok(_) => Ok(()),
            Err(err) => Err(AppError::InvalidEmail(err.to_string())),
        };

        // Insert the new user profile
        let result = sqlx::query!(
        "INSERT INTO user_profiles (user_id, age, weight, height, dream_physique_id) VALUES ($1, $2, $3, $4, $5)",
        user_id,
        self.age,
        self.weight,
        self.height,
        self.goal_physique_id,
    )
    .execute(db)
    .await;

        match result {
            Ok(_) => Ok(()),
            Err(err) => {
                eprintln!("Database error: {:?}", err);
                Err(AppError::InternalServerError)
            }
        }
    }
}
