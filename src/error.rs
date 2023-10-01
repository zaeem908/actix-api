use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Invalid email: {0}")]
    InvalidEmail(String),

    #[error("incorrect password: {0}")]
    IncorrectPassword(String),

    #[error("Internal server error")]
    InternalServerError,

    #[error("Invalid Token")]
    InvalidToken,

    #[error("Apready Exists!: {0}")]
    AlreadyExists(String),

    #[error("Expired Token")]
    ExpiredToken,
}
