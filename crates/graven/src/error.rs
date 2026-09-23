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
    #[error("no local index in {0}: run `graven sync` first")]
    NotSynced(std::path::PathBuf),
    #[error("mcp: {0}")]
    Mcp(String),
    #[error("publisher verify: {0}")]
    PublisherVerify(String),
}

impl Error {
    pub fn code(&self) -> Option<String> {
        let text = self.to_string();
        text.split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
            .find(|token| {
                let bytes = token.as_bytes();
                bytes.len() == 9
                    && token.starts_with("WIST")
                    && bytes[4].is_ascii_digit()
                    && bytes[5] == b'-'
                    && bytes[6] == b'E'
                    && bytes[7].is_ascii_digit()
                    && bytes[8].is_ascii_digit()
            })
            .map(str::to_owned)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
