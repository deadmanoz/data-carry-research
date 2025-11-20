//! Bitcoin RPC Test Utilities and Configuration
//!
//! Provides standardised RPC configuration and helper functions for integration tests
//! that require Bitcoin Core RPC access.

use data_carry_research::config::BitcoinRpcConfig;
use data_carry_research::rpc::BitcoinRpcClient;

/// Standard test RPC URL (localhost)
pub const TEST_RPC_URL: &str = "http://localhost:8332";

/// Standard test RPC username
pub const TEST_RPC_USERNAME: &str = "bitcoin";

/// Standard test RPC password
pub const TEST_RPC_PASSWORD: &str = "bitcoin";

/// Create standard Bitcoin RPC configuration for tests
///
/// This provides a consistent RPC configuration across all integration tests
/// that require Bitcoin Core RPC access.
///
/// # Configuration
/// - URL: `http://localhost:8332`
/// - Username: `bitcoin`
/// - Password: `bitcoin`
/// - Max retries: 3
/// - Timeout: 30 seconds
/// - Concurrent requests: 4
///
/// # Example
/// ```rust
/// use crate::common::rpc_helpers::create_test_rpc_config;
///
/// let rpc_config = create_test_rpc_config();
/// // Use rpc_config for testing...
/// ```
pub fn create_test_rpc_config() -> BitcoinRpcConfig {
    BitcoinRpcConfig {
        url: TEST_RPC_URL.to_string(),
        username: TEST_RPC_USERNAME.to_string(),
        password: TEST_RPC_PASSWORD.to_string(),
        max_retries: 3,
        initial_backoff_ms: 100,
        timeout_seconds: 30,
        backoff_multiplier: 1.5,
        max_backoff_seconds: 10,
        concurrent_requests: 4,
    }
}

/// Create a test Bitcoin RPC client
///
/// Returns an RPC client configured for testing, or an error if the client
/// cannot be created (e.g., RPC is not available).
///
/// # Example
/// ```rust
/// use crate::common::rpc_helpers::create_test_rpc_client;
///
/// let client = match create_test_rpc_client().await {
///     Ok(c) => c,
///     Err(e) => {
///         eprintln!("⏭️  Skipping test - Bitcoin RPC not available: {}", e);
///         return;
///     }
/// };
/// ```
pub async fn create_test_rpc_client() -> Result<BitcoinRpcClient, String> {
    let config = create_test_rpc_config();
    BitcoinRpcClient::new(config)
        .await
        .map_err(|e| format!("Failed to create RPC client: {}", e))
}

/// Helper to check if Bitcoin RPC is available
///
/// Returns `true` if RPC is available, `false` otherwise.
/// Prints a warning message if RPC is not available.
///
/// # Arguments
/// * `test_name` - Name of the test (for error message)
///
/// # Example
/// ```rust
/// if !is_rpc_available("my_test") {
///     // Skip test or return early
///     return Ok(());
/// }
/// ```
pub fn is_rpc_available(test_name: &str) -> bool {
    let config = create_test_rpc_config();

    // Try to create a simple RPC client and test connectivity
    match test_rpc_connectivity(&config) {
        Ok(_) => true,
        Err(e) => {
            eprintln!(
                "⚠️  Skipping {} - Bitcoin RPC not available: {}",
                test_name, e
            );
            false
        }
    }
}

/// Test RPC connectivity with the given configuration
///
/// Attempts to connect to Bitcoin Core RPC and verify it's responding.
///
/// # Arguments
/// * `config` - RPC configuration to test
///
/// # Returns
/// - `Ok(())` if RPC is reachable and responding
/// - `Err(e)` if RPC is unavailable or not responding
fn test_rpc_connectivity(config: &BitcoinRpcConfig) -> anyhow::Result<()> {
    // Basic connectivity check - just verify the URL is reachable
    // This is a lightweight check that doesn't require full RPC initialisation

    use std::net::TcpStream;
    use std::time::Duration;

    // Parse host and port from URL
    let url = config
        .url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host_port = if url.contains(':') {
        url.to_string()
    } else {
        format!("{}:8332", url)
    };

    // Try to connect with a short timeout
    TcpStream::connect_timeout(&host_port.parse()?, Duration::from_millis(500))?;

    Ok(())
}

/// Print skip message when RPC is unavailable
///
/// Used in integration tests to gracefully skip when Bitcoin Core RPC is not available.
/// Prints a warning message and should be followed by early return.
///
/// # Arguments
/// * `e` - The error from RPC operation
/// * `test_name` - Name of the test being skipped
///
/// # Example
/// ```rust
/// let decoder = match create_test_decoder().await {
///     Ok(d) => d,
///     Err(e) => {
///         skip_if_rpc_unavailable(e, "test_my_feature");
///         return Ok(());
///     }
/// };
/// ```
pub fn skip_if_rpc_unavailable(e: anyhow::Error, test_name: &str) {
    eprintln!(
        "⚠️  Skipping {} - Bitcoin RPC not available: {}",
        test_name, e
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_rpc_config() {
        let config = create_test_rpc_config();

        assert_eq!(config.url, TEST_RPC_URL);
        assert_eq!(config.username, TEST_RPC_USERNAME);
        assert_eq!(config.password, TEST_RPC_PASSWORD);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.timeout_seconds, 30);
    }

    #[test]
    fn test_rpc_constants() {
        assert_eq!(TEST_RPC_URL, "http://localhost:8332");
        assert_eq!(TEST_RPC_USERNAME, "bitcoin");
        assert_eq!(TEST_RPC_PASSWORD, "bitcoin");
    }
}
