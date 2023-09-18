use thiserror::Error;


#[derive(Error, Debug)]
pub enum AppError {
    #[error("Invalid email: {0}")]
    InvalidEmail(String),

    #[error("invalid credentials: {0}")]
    InvalidCredentials(String),

    #[error("Internal server error")]
    InternalServerError,
}

