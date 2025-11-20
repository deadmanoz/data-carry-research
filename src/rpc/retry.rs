//! Retry logic utilities for RPC operations
//!
//! This module provides helper functions for implementing exponential backoff
//! retry logic and timeout wrappers for RPC client operations.

use crate::errors::RpcResult;
use std::time::Duration;
use tokio::task::JoinError;
use tokio::time::error::Elapsed;
use tokio::time::timeout;

/// Calculate next backoff duration using exponential backoff with a maximum cap
///
/// This is a pure helper function that implements the exponential backoff formula:
/// `new_backoff = min(current_backoff * multiplier, max_backoff)`
///
/// # Arguments
/// * `current_backoff` - Current backoff duration
/// * `multiplier` - Multiplier for exponential increase (typically 1.5-2.0)
/// * `max_backoff_seconds` - Maximum backoff duration in seconds
///
/// # Returns
/// New backoff duration, capped at max_backoff_seconds
///
/// # Example
/// ```
/// use std::time::Duration;
/// use data_carry_research::rpc::calculate_next_backoff;
///
/// let backoff = Duration::from_millis(100);
/// let next = calculate_next_backoff(backoff, 2.0, 30);
/// assert_eq!(next, Duration::from_millis(200));
/// ```
pub fn calculate_next_backoff(
    current_backoff: Duration,
    multiplier: f64,
    max_backoff_seconds: u64,
) -> Duration {
    Duration::from_millis((current_backoff.as_millis() as f64 * multiplier) as u64)
        .min(Duration::from_secs(max_backoff_seconds))
}

/// Execute a blocking RPC operation with timeout wrapper
///
/// This helper wraps the common pattern of:
/// 1. Wrapping a blocking RPC call in `spawn_blocking`
/// 2. Wrapping that in a timeout
/// 3. Preserving the exact result type for caller handling
///
/// # Arguments
/// * `timeout_seconds` - Timeout duration in seconds
/// * `operation` - Closure containing the blocking RPC call
///
/// # Returns
/// `Result<Result<RpcResult<T>, JoinError>, Elapsed>`
/// - Outer Result: Timeout result (Err = timeout elapsed)
/// - Middle Result: spawn_blocking result (Err = task panic/failure)
/// - Inner RpcResult<T>: RPC operation result
///
/// # Example
/// ```no_run
/// use data_carry_research::rpc::execute_with_timeout;
/// use data_carry_research::errors::RpcResult;
///
/// async fn example() -> RpcResult<String> {
///     match execute_with_timeout(30, move || -> RpcResult<String> {
///         // Your blocking RPC call here
///         Ok("result".to_string())
///     }).await {
///         Ok(Ok(Ok(result))) => Ok(result),
///         Ok(Ok(Err(e))) => Err(e),
///         Ok(Err(_)) => panic!("Task panicked"),
///         Err(_) => panic!("Timeout"),
///     }
/// }
/// ```
pub async fn execute_with_timeout<T, F>(
    timeout_seconds: u64,
    operation: F,
) -> Result<Result<RpcResult<T>, JoinError>, Elapsed>
where
    T: Send + 'static,
    F: FnOnce() -> RpcResult<T> + Send + 'static,
{
    timeout(
        Duration::from_secs(timeout_seconds),
        tokio::task::spawn_blocking(operation),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exponential_backoff() {
        let backoff = Duration::from_millis(100);
        let next = calculate_next_backoff(backoff, 2.0, 30);
        assert_eq!(next, Duration::from_millis(200));

        let next2 = calculate_next_backoff(next, 2.0, 30);
        assert_eq!(next2, Duration::from_millis(400));
    }

    #[test]
    fn test_backoff_capped_at_max() {
        let backoff = Duration::from_secs(20);
        let next = calculate_next_backoff(backoff, 2.0, 30);
        assert_eq!(next, Duration::from_secs(30)); // Capped at max

        let large_backoff = Duration::from_secs(50);
        let next2 = calculate_next_backoff(large_backoff, 1.5, 30);
        assert_eq!(next2, Duration::from_secs(30)); // Capped at max
    }

    #[test]
    fn test_backoff_with_fractional_multiplier() {
        let backoff = Duration::from_millis(1000);
        let next = calculate_next_backoff(backoff, 1.5, 30);
        assert_eq!(next, Duration::from_millis(1500));
    }

    #[test]
    fn test_backoff_preserves_exact_calculation() {
        // This test verifies the exact calculation matches the original implementation
        let backoff = Duration::from_millis(10);
        let multiplier = 1.5;
        let max_seconds = 1;

        let result = calculate_next_backoff(backoff, multiplier, max_seconds);
        let expected = Duration::from_millis((backoff.as_millis() as f64 * multiplier) as u64)
            .min(Duration::from_secs(max_seconds));

        assert_eq!(result, expected);
    }
}
