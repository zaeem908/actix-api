use bcrypt::{hash, DEFAULT_COST};
use regex::Regex;
use serde::Deserialize;

pub fn hash_password(pwd: &str) -> Result<String, bcrypt::BcryptError> {
    hash(pwd, DEFAULT_COST)
}
#[derive(Deserialize)]
pub struct UserDataStruct {
    pub username: String,
    pub email: String,
    pub password: String,
}


impl UserDataStruct {
    pub fn is_valid_email(&self) -> bool {
        let re = Regex::new(r"^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}$").unwrap();
        re.is_match(&self.email)
    }

    pub fn is_valid_password(&self) -> bool {
        self.password.len() >= 8
    }
}
