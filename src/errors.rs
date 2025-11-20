#![allow(dead_code)]

use thiserror::Error;

/// Application-wide error type - single point of truth
#[derive(Error, Debug)]
pub enum AppError {
    /// Database operations
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// Bitcoin RPC operations
    #[error("RPC error: {0}")]
    Rpc(#[from] RpcError),

    /// File I/O operations
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// CSV processing
    #[error("CSV parsing error: {0}")]
    Csv(#[from] csv::Error),

    /// Configuration issues
    #[error("Configuration error: {0}")]
    Config(String),

    /// Data validation/parsing
    #[error("Invalid data: {0}")]
    InvalidData(String),

    /// Protocol-specific errors
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Image/decoder errors
    #[error("Decoder error: {0}")]
    Decoder(String),

    /// Base64 decoding
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Checkpoint errors
    #[error("Checkpoint error: {0}")]
    Checkpoint(String),

    /// Invalid UTXO record
    #[error("Invalid UTXO record at line {line}: {reason}")]
    InvalidRecord { line: usize, reason: String },

    /// Script parsing error
    #[error("Script parsing error: {0}")]
    ScriptParse(String),
}

/// RPC error types
#[derive(Error, Debug)]
pub enum RpcError {
    /// Failed to establish connection to Bitcoin Core RPC server
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// TXID string format is invalid (not valid hex or wrong length)
    #[error("Invalid txid: {txid}")]
    InvalidTxid { txid: String },

    /// RPC method call failed (covers network errors, authentication, etc.)
    #[error("RPC call failed: {method} - {message}")]
    CallFailed { method: String, message: String },

    /// Failed to deserialise RPC response data
    #[error("Deserialisation failed: {0}")]
    DeserialisationFailed(String),

    /// Retry limit exceeded for RPC operation
    #[error("Max retries exceeded: {operation}")]
    MaxRetriesExceeded { operation: String },

    /// RPC request timed out
    #[error("Request timeout: {timeout_seconds}s for {operation}")]
    Timeout {
        timeout_seconds: u64,
        operation: String,
    },

    /// RPC returned unexpected or malformed response data
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// Transaction exists in valid format but not found in blockchain/mempool
    #[error("Transaction not found: {txid}")]
    TransactionNotFound { txid: String },
}

/// Application-wide result type - single point of truth
pub type AppResult<T> = Result<T, AppError>;

/// Result type for RPC operations
pub type RpcResult<T> = Result<T, RpcError>;

// Additional From implementations for common error types
impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::InvalidData(format!("JSON error: {}", err))
    }
}

impl From<crate::decoder::DecoderError> for AppError {
    fn from(err: crate::decoder::DecoderError) -> Self {
        AppError::Decoder(err.to_string())
    }
}

impl From<glob::PatternError> for AppError {
    fn from(err: glob::PatternError) -> Self {
        AppError::Config(format!("Glob pattern error: {}", err))
    }
}

impl From<glob::GlobError> for AppError {
    fn from(err: glob::GlobError) -> Self {
        AppError::Config(format!("Glob error: {}", err))
    }
}
