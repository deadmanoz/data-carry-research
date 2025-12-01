//! Decoder-specific error types

/// Result type for decoder operations
pub type DecoderResult<T> = Result<T, DecoderError>;

/// Decoder-specific error types
#[derive(Debug, thiserror::Error)]
pub enum DecoderError {
    #[error("RPC error: {0}")]
    Rpc(#[from] crate::errors::RpcError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid transaction format for {0}")]
    InvalidTransaction(String),

    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Invalid image format in transaction {0}")]
    InvalidImageFormat(String),

    #[error("Output error: {0}")]
    Output(#[from] crate::decoder::output::OutputError),
}
