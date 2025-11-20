//! Bitcoin Core RPC integration module
//!
//! This module provides all Bitcoin Core RPC-related functionality including:
//! - **Client** - Async Bitcoin Core RPC client with retry logic
//! - **Cache** - Transaction caching for RPC responses
//! - **Retry** - Exponential backoff retry utilities and timeout wrappers
//!
//! The RPC client uses the `corepc-client` crate and implements an async
//! worker pattern with channel-based request/response handling.

pub mod cache;
pub mod client;
pub mod retry;

// Re-export main types
pub use cache::{CacheStats, TransactionCache};
pub use client::{BitcoinRpcClient, RpcRequest};
pub use retry::{calculate_next_backoff, execute_with_timeout};
