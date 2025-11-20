use crate::config::BitcoinRpcConfig;
use crate::errors::{RpcError, RpcResult};
use crate::rpc::{calculate_next_backoff, execute_with_timeout, TransactionCache};
use corepc_client::bitcoin::{Transaction, Txid};
use corepc_client::client_sync::{v28::Client, Auth};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

/// RPC request types for the async worker pattern
#[allow(dead_code)]
#[derive(Debug)]
pub enum RpcRequest {
    GetTransaction {
        txid: String,
        tx: oneshot::Sender<RpcResult<Transaction>>,
    },
    TestConnection {
        tx: oneshot::Sender<RpcResult<()>>,
    },
}

/// Bitcoin RPC client with robust retry logic and async worker pattern
pub struct BitcoinRpcClient {
    request_tx: mpsc::Sender<RpcRequest>,
    error_count: Arc<AtomicU64>,
    cache: TransactionCache,
    concurrent_requests: usize,
}

impl BitcoinRpcClient {
    /// Create a new RPC client and spawn the worker task
    pub async fn new(config: BitcoinRpcConfig) -> RpcResult<Self> {
        let (request_tx, request_rx) = mpsc::channel(100);
        let error_count = Arc::new(AtomicU64::new(0));

        // Test connection before starting worker
        let test_client = Self::create_sync_client(&config)?;
        tokio::task::spawn_blocking({
            let client = test_client.clone();
            move || -> RpcResult<()> {
                client.get_blockchain_info()
                    .map_err(|e| RpcError::ConnectionFailed(format!("Failed to connect to Bitcoin RPC - check URL, credentials, and that Bitcoin Core is running: {}", e)))?;
                Ok(())
            }
        }).await
        .map_err(|e| RpcError::ConnectionFailed(format!("Connection test task failed: {}", e)))??;

        info!("Bitcoin RPC connection established successfully");

        // Create shared transaction cache
        let cache = TransactionCache::new();

        // Spawn the worker task
        let concurrent_requests = config.concurrent_requests;
        let worker = RpcWorker::new(config, test_client, Arc::clone(&error_count), cache.clone());
        tokio::spawn(worker.run(request_rx));

        Ok(Self {
            request_tx,
            error_count,
            cache,
            concurrent_requests,
        })
    }

    /// Get a transaction with retry logic and caching
    pub async fn get_transaction(&self, txid: &str) -> RpcResult<Transaction> {
        // Check cache first
        if let Some(cached_tx) = self.cache.get(txid) {
            return Ok(cached_tx);
        }

        // Fetch via worker with retry logic
        let (tx, rx) = oneshot::channel();

        self.request_tx
            .send(RpcRequest::GetTransaction {
                txid: txid.to_string(),
                tx,
            })
            .await
            .map_err(|_| RpcError::ConnectionFailed("Failed to send RPC request".to_string()))?;

        rx.await
            .map_err(|_| RpcError::ConnectionFailed("RPC worker channel closed".to_string()))?
    }

    /// Test RPC connection
    pub async fn test_connection(&self) -> RpcResult<()> {
        let (tx, rx) = oneshot::channel();

        self.request_tx
            .send(RpcRequest::TestConnection { tx })
            .await
            .map_err(|_| RpcError::ConnectionFailed("Failed to send RPC request".to_string()))?;

        rx.await
            .map_err(|_| RpcError::ConnectionFailed("RPC worker channel closed".to_string()))?
    }

    /// Get the current error count from RPC operations
    pub fn get_error_count(&self) -> u64 {
        self.error_count.load(Ordering::Relaxed)
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> crate::rpc::CacheStats {
        self.cache.get_stats()
    }

    /// Get the configured concurrent request limit
    pub fn get_concurrent_limit(&self) -> usize {
        self.concurrent_requests
    }

    /// Get sender address from largest input (for Omni deobfuscation)
    ///
    /// This replicates the database method used in Stage 3 processing, but via RPC.
    /// Groups all transaction inputs by source address and returns the address that
    /// contributed the most value (following Omni Layer specification).
    pub async fn get_sender_address_from_largest_input(
        &self,
        transaction: &Transaction,
    ) -> RpcResult<Option<String>> {
        use std::collections::HashMap;

        if transaction.input.is_empty() {
            debug!("Transaction has no inputs, cannot determine sender");
            return Ok(None);
        }

        // Group inputs by address and sum their values
        let mut address_sums: HashMap<String, u64> = HashMap::new();

        // Fetch all previous transactions to get source addresses and values
        for input in &transaction.input {
            let prev_txid = input.previous_output.txid.to_string();
            let prev_vout = input.previous_output.vout;

            // Fetch previous transaction
            let prev_tx = match self.get_transaction(&prev_txid).await {
                Ok(tx) => tx,
                Err(e) => {
                    debug!(
                        "Failed to fetch previous tx {} for input resolution: {}",
                        prev_txid, e
                    );
                    continue;
                }
            };

            // Extract the output that this input is spending
            if let Some(output) = prev_tx.output.get(prev_vout as usize) {
                let value = output.value.to_sat();

                // Convert corepc_client script to bitcoin crate Script via serialisation
                let script_bytes = output.script_pubkey.to_bytes();

                // Parse as bitcoin crate Script and extract address
                let script = bitcoin::ScriptBuf::from_bytes(script_bytes);
                if let Ok(address) =
                    bitcoin::Address::from_script(&script, bitcoin::Network::Bitcoin)
                {
                    let address_str = address.to_string();
                    *address_sums.entry(address_str.clone()).or_insert(0) += value;
                    debug!(
                        "Input from prev_tx {}:{} contributes {} sats (address: {})",
                        prev_txid, prev_vout, value, address_str
                    );
                }
            }
        }

        // Find the address with the largest total value
        if let Some((address, total_value)) = address_sums.iter().max_by_key(|(_, &v)| v) {
            debug!(
                "Largest input contributor: address {} with {} sats",
                address, total_value
            );
            Ok(Some(address.clone()))
        } else {
            debug!("No valid input addresses found");
            Ok(None)
        }
    }

    /// Create synchronous client for worker use
    fn create_sync_client(config: &BitcoinRpcConfig) -> RpcResult<Arc<Client>> {
        let auth = Auth::UserPass(config.username.clone(), config.password.clone());
        let client = Client::new_with_auth(&config.url, auth).map_err(|e| {
            RpcError::ConnectionFailed(format!("Failed to create Bitcoin RPC client: {}", e))
        })?;

        Ok(Arc::new(client))
    }
}

/// RPC worker that handles all Bitcoin Core communication in a dedicated task
struct RpcWorker {
    client: Arc<Client>,
    config: BitcoinRpcConfig,
    semaphore: Arc<Semaphore>,
    error_count: Arc<AtomicU64>,
    cache: TransactionCache,
}

impl RpcWorker {
    fn new(
        config: BitcoinRpcConfig,
        client: Arc<Client>,
        error_count: Arc<AtomicU64>,
        cache: TransactionCache,
    ) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.concurrent_requests));
        Self {
            client,
            config,
            semaphore,
            error_count,
            cache,
        }
    }

    async fn run(self, mut request_rx: mpsc::Receiver<RpcRequest>) {
        info!(
            "RPC worker started with {} concurrent request limit",
            self.config.concurrent_requests
        );

        while let Some(request) = request_rx.recv().await {
            let worker = self.clone();

            // Spawn each request in its own task for parallel processing
            tokio::spawn(async move {
                worker.handle_request(request).await;
            });
        }

        info!("RPC worker shutting down");
    }

    async fn handle_request(&self, request: RpcRequest) {
        match request {
            RpcRequest::GetTransaction { txid, tx } => {
                let result = self.get_transaction_with_retry(&txid).await;
                let _ = tx.send(result);
            }
            RpcRequest::TestConnection { tx } => {
                let result = self.test_connection_impl().await;
                let _ = tx.send(result);
            }
        }
    }

    async fn get_transaction_with_retry(&self, txid: &str) -> RpcResult<Transaction> {
        // Note: Cache checking now happens in the public method

        let _permit = self.semaphore.acquire().await.map_err(|e| {
            RpcError::ConnectionFailed(format!("Failed to acquire semaphore: {}", e))
        })?;
        let mut attempts = 0;
        let mut backoff = Duration::from_millis(self.config.initial_backoff_ms);

        let tx_hash = Txid::from_str(txid).map_err(|_| RpcError::InvalidTxid {
            txid: txid.to_string(),
        })?;

        while attempts < self.config.max_retries {
            let client = Arc::clone(&self.client);
            let hash = tx_hash;

            match execute_with_timeout(
                self.config.timeout_seconds,
                move || -> RpcResult<Transaction> {
                    let raw_result =
                        client
                            .get_raw_transaction(hash)
                            .map_err(|e| RpcError::CallFailed {
                                method: "get_raw_transaction".to_string(),
                                message: e.to_string(),
                            })?;

                    // Deserialise the hex string into a Transaction
                    let tx_bytes = hex::decode(&raw_result.0).map_err(|e| {
                        RpcError::DeserialisationFailed(format!(
                            "Failed to decode raw transaction hex: {}",
                            e
                        ))
                    })?;
                    let transaction: Transaction =
                        corepc_client::bitcoin::consensus::deserialize(&tx_bytes).map_err(|e| {
                            RpcError::DeserialisationFailed(format!(
                                "Failed to deserialise raw transaction: {}",
                                e
                            ))
                        })?;

                    Ok(transaction)
                },
            )
            .await
            {
                Ok(Ok(Ok(transaction))) => {
                    if attempts > 0 {
                        debug!(
                            "Successfully retrieved transaction {} after {} attempts",
                            txid,
                            attempts + 1
                        );
                    }
                    // Cache the successfully retrieved transaction
                    self.cache.put(txid.to_string(), transaction.clone());
                    return Ok(transaction);
                }
                Ok(Ok(Err(e))) => {
                    attempts += 1;
                    self.error_count.fetch_add(1, Ordering::Relaxed);

                    // Check if this is a non-retryable error (transaction not found)
                    let error_message = e.to_string();
                    if error_message.contains("No such mempool or blockchain transaction")
                        || error_message.contains("Invalid or non-wallet transaction id")
                    {
                        debug!(
                            "Transaction {} not found (non-retryable error): {}",
                            txid, e
                        );
                        return Err(RpcError::TransactionNotFound {
                            txid: txid.to_string(),
                        }); // Return immediately, don't retry
                    }

                    if attempts >= self.config.max_retries {
                        error!(
                            "Failed to get transaction {} after {} attempts: {}",
                            txid, attempts, e
                        );
                        return Err(RpcError::MaxRetriesExceeded {
                            operation: format!("get_transaction({})", txid),
                        });
                    }

                    warn!(
                        "RPC attempt {} failed for transaction {}, retrying in {:?}: {}",
                        attempts, txid, backoff, e
                    );
                    sleep(backoff).await;

                    backoff = calculate_next_backoff(
                        backoff,
                        self.config.backoff_multiplier,
                        self.config.max_backoff_seconds,
                    );
                }
                Ok(Err(e)) => {
                    self.error_count.fetch_add(1, Ordering::Relaxed);
                    error!("Spawn blocking error for transaction {}: {}", txid, e);
                    return Err(RpcError::CallFailed {
                        method: "spawn_blocking".to_string(),
                        message: format!("Task execution error: {}", e),
                    });
                }
                Err(_) => {
                    attempts += 1;
                    self.error_count.fetch_add(1, Ordering::Relaxed);

                    if attempts >= self.config.max_retries {
                        error!(
                            "RPC timeout for transaction {} after {} attempts ({}s timeout)",
                            txid, attempts, self.config.timeout_seconds
                        );
                        return Err(RpcError::Timeout {
                            timeout_seconds: self.config.timeout_seconds,
                            operation: format!("get_transaction({})", txid),
                        });
                    }

                    warn!(
                        "RPC timeout for transaction {} on attempt {}, retrying in {:?}",
                        txid, attempts, backoff
                    );
                    sleep(backoff).await;

                    backoff = calculate_next_backoff(
                        backoff,
                        self.config.backoff_multiplier,
                        self.config.max_backoff_seconds,
                    );
                }
            }
        }

        unreachable!("Should have returned or errored by now")
    }

    async fn test_connection_impl(&self) -> RpcResult<()> {
        let client = Arc::clone(&self.client);

        match execute_with_timeout(self.config.timeout_seconds, move || -> RpcResult<()> {
            let info = client
                .get_blockchain_info()
                .map_err(|e| RpcError::CallFailed {
                    method: "get_blockchain_info".to_string(),
                    message: e.to_string(),
                })?;
            debug!(
                "Bitcoin Core connection test successful - chain: {}, blocks: {}",
                info.chain, info.blocks
            );
            Ok(())
        })
        .await
        {
            Ok(result) => result.map_err(|e| RpcError::CallFailed {
                method: "spawn_blocking".to_string(),
                message: format!("Connection test task failed: {}", e),
            })?,
            Err(_) => Err(RpcError::Timeout {
                timeout_seconds: self.config.timeout_seconds,
                operation: "connection_test".to_string(),
            }),
        }
    }
}

impl Clone for RpcWorker {
    fn clone(&self) -> Self {
        Self {
            client: Arc::clone(&self.client),
            config: self.config.clone(),
            semaphore: Arc::clone(&self.semaphore),
            error_count: Arc::clone(&self.error_count),
            cache: self.cache.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    fn create_test_config() -> BitcoinRpcConfig {
        BitcoinRpcConfig {
            url: "http://localhost:8332".to_string(),
            username: "test".to_string(),
            password: "test".to_string(),
            timeout_seconds: 5,
            max_retries: 3,
            initial_backoff_ms: 10,
            backoff_multiplier: 1.5,
            max_backoff_seconds: 1,
            concurrent_requests: 2,
        }
    }

    #[tokio::test]
    async fn test_rpc_client_creation() {
        // This test will only work if a Bitcoin RPC server is available
        // In a real test environment, you would use a mock or test server
        let config = create_test_config();

        // This will fail in most test environments without a running Bitcoin node
        // but demonstrates the correct usage pattern
        match BitcoinRpcClient::new(config).await {
            Ok(_client) => {
                // If we have a real Bitcoin node available, test would continue here
                println!("RPC client created successfully");
            }
            Err(e) => {
                // Expected in most test environments
                println!(
                    "RPC client creation failed (expected without Bitcoin node): {}",
                    e
                );
            }
        }
    }

    #[test]
    fn test_rpc_config_defaults() {
        let config = BitcoinRpcConfig::default();
        assert_eq!(config.url, "http://localhost:8332");
        assert_eq!(config.username, "bitcoin");
        assert_eq!(config.max_retries, 10);
        assert!(config.concurrent_requests > 0);
    }

    #[test]
    fn test_sync_client_creation() {
        let config = create_test_config();

        // Test that we can create the client object (authentication will fail later)
        match BitcoinRpcClient::create_sync_client(&config) {
            Ok(client) => {
                // Client object created successfully - verify it's actually an Arc
                assert_eq!(Arc::strong_count(&client), 1); // Basic sanity check
            }
            Err(e) => {
                println!("Client creation failed: {}", e);
                // This might fail if the URL is invalid, but basic creation should work
            }
        }
    }
}
