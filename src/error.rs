use std::fmt;
#[derive(Debug, Clone)]
pub(crate) struct Error {
    pub code: i32,
    pub message: String,
    pub status: Option<u16>,
    pub config: bool,
}
impl Error {
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(2, message)
    }
    pub fn config(message: impl Into<String>) -> Self {
        let mut e = Self::new(3, message);
        e.config = true;
        e
    }
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(3, message)
    }
    pub fn uncertain(message: impl Into<String>) -> Self {
        Self::new(5, message)
    }
    pub fn api(status: u16, message: impl Into<String>) -> Self {
        let mut e = Self::new(
            if status == 401 || status == 403 { 3 } else { 4 },
            format!("AllowIt returned HTTP {status}: {}", message.into()),
        );
        e.status = Some(status);
        e
    }
    fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            status: None,
            config: false,
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
pub(crate) type Result<T> = std::result::Result<T, Error>;
pub(crate) fn quoted(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}
