use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Callers that show this to the user prefix it with the file name themselves.
    #[error("{source}")]
    File {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("missing key '{0}' in prod.keys")]
    MissingKey(String),

    #[error("invalid keys file: {0}")]
    InvalidKeys(String),

    #[error("unsupported or corrupt file: {0}")]
    Format(String),

    #[error("{0}")]
    Unsupported(String),

    #[error("{0}")]
    Network(String),

    #[error("cancelled")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn fmt_err<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Format(msg.into()))
}
