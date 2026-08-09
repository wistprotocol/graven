use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] wist_core::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error("fetch: {0}")]
    Fetch(String),
    #[error("verify: {0}")]
    Verify(String),
}

pub type Result<T> = std::result::Result<T, Error>;
