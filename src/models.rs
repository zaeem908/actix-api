use serde::Serialize;
// models.rs
use sqlx::FromRow;

#[derive(Debug, FromRow, Serialize)]
pub struct Users {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub password: String,
}
