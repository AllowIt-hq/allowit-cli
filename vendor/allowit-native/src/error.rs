use std::fmt;
#[derive(Debug, Clone)]
pub struct Error {
    pub message: String,
    pub code: i32,
}
impl Error {
    pub fn config(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 3,
        }
    }
    pub fn denied(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 20,
        }
    }
    pub fn uncertain(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 5,
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
