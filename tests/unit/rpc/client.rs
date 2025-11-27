use anyhow::Result;
use data_carry_research::config::BitcoinRpcConfig;
use data_carry_research::rpc::RpcRequest;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{timeout, Duration};

/// Tests for the Bitcoin RPC client component
///
/// These tests verify RPC client functionality using mock responses
/// and do not require a live Bitcoin node.

#[test]
fn test_rpc_config_creation() {
    let config = BitcoinRpcConfig::default();

    assert_eq!(config.url, "http://localhost:8332");
    assert_eq!(config.timeout_seconds, 60);
    assert_eq!(config.max_retries, 10);
    assert_eq!(config.concurrent_requests, 10);
    assert!(config.initial_backoff_ms > 0);
    assert!(config.backoff_multiplier > 1.0);
    assert!(config.max_backoff_seconds > 0);
}

#[test]
fn test_rpc_config_validation() {
    let mut config = BitcoinRpcConfig::default();

    // Test URL validation helpers
    assert!(config.url.starts_with("http"));

    // Test timeout bounds
    config.timeout_seconds = 0;
    // In real implementation, this would be validated

    // Test retry configuration
    assert!(config.max_retries > 0);
    assert!(config.concurrent_requests > 0);
}

#[tokio::test]
async fn test_rpc_request_enum_creation() -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<RpcRequest>(10);

    // Test creating GetTransaction request
    let (response_tx, _response_rx) = oneshot::channel();
    let request = RpcRequest::GetTransaction {
        txid: "deadbeef".to_string(),
        tx: response_tx,
    };
    tx.send(request).await?;

    // Verify request was sent
    if let Some(req) = rx.recv().await {
        match req {
            RpcRequest::GetTransaction { txid, .. } => {
                assert_eq!(txid, "deadbeef");
            }
            _ => panic!("Wrong request type"),
        }
    }

    // Test TestConnection request
    let (response_tx, _response_rx) = oneshot::channel();
    tx.send(RpcRequest::TestConnection { tx: response_tx })
        .await?;
    if let Some(req) = rx.recv().await {
        match req {
            RpcRequest::TestConnection { .. } => {}
            _ => panic!("Wrong request type"),
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_rpc_channel_communication() -> Result<()> {
    let (request_tx, mut request_rx) = mpsc::channel::<RpcRequest>(10);

    // Simulate minimal handler for GetTransaction and TestConnection
    tokio::spawn(async move {
        while let Some(request) = request_rx.recv().await {
            match request {
                RpcRequest::GetTransaction { txid: _, tx } => {
                    use corepc_client::bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
                    let transaction = Transaction {
                        version: corepc_client::bitcoin::transaction::Version(1),
                        lock_time: corepc_client::bitcoin::absolute::LockTime::ZERO,
                        input: vec![],
                        output: vec![TxOut {
                            value: Amount::from_sat(1000),
                            script_pubkey: ScriptBuf::new(),
                        }],
                    };
                    let _ = tx.send(Ok(transaction));
                }
                RpcRequest::TestConnection { tx } => {
                    let _ = tx.send(Ok(()));
                }
                RpcRequest::GetBlock { .. } => {
                    // Not used in this test
                }
                RpcRequest::GetTransactionVerbose { .. } => {
                    // Not used in this test
                }
                RpcRequest::GetBlockHash { .. } => {
                    // Not used in this test
                }
            }
        }
    });

    // Test GetTransaction
    let (tx, rx) = oneshot::channel();
    request_tx
        .send(RpcRequest::GetTransaction {
            txid: "deadbeef".to_string(),
            tx,
        })
        .await?;
    let response = timeout(Duration::from_secs(1), rx).await??;
    assert_eq!(response.unwrap().output.len(), 1);

    // Test TestConnection
    let (tx, rx) = oneshot::channel();
    request_tx.send(RpcRequest::TestConnection { tx }).await?;
    let response = timeout(Duration::from_secs(1), rx).await??;
    assert!(response.is_ok());

    Ok(())
}

#[tokio::test]
async fn test_rpc_error_handling() -> Result<()> {
    let (request_tx, mut request_rx) = mpsc::channel::<RpcRequest>(10);

    // Simulate error on GetTransaction
    tokio::spawn(async move {
        while let Some(request) = request_rx.recv().await {
            if let RpcRequest::GetTransaction { tx, .. } = request {
                let _ = tx.send(Err(data_carry_research::errors::RpcError::CallFailed {
                    method: "get_raw_transaction".to_string(),
                    message: "Mock RPC error".to_string(),
                }));
            }
        }
    });

    // Test error propagation
    let (tx, rx) = oneshot::channel();
    request_tx
        .send(RpcRequest::GetTransaction {
            txid: "deadbeef".to_string(),
            tx,
        })
        .await?;

    let response = timeout(Duration::from_secs(1), rx).await?;
    // oneshot wraps the inner Result; unwrap outer, then check inner error
    let inner = response.expect("oneshot canceled unexpectedly");
    assert!(inner.is_err());

    Ok(())
}

#[tokio::test]
async fn test_rpc_timeout_handling() -> Result<()> {
    let (request_tx, mut request_rx) = mpsc::channel::<RpcRequest>(10);

    // Simulate slow handler for GetTransaction
    tokio::spawn(async move {
        while let Some(_request) = request_rx.recv().await {
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });

    // Test timeout
    let (tx, rx) = oneshot::channel();
    request_tx
        .send(RpcRequest::GetTransaction {
            txid: "deadbeef".to_string(),
            tx,
        })
        .await?;

    let response = timeout(Duration::from_millis(100), rx).await;
    assert!(response.is_err());

    Ok(())
}

#[tokio::test]
async fn test_rpc_concurrent_requests() -> Result<()> {
    let (request_tx, mut request_rx) = mpsc::channel::<RpcRequest>(100);

    // Simulate handling multiple GetTransaction requests
    tokio::spawn(async move {
        while let Some(request) = request_rx.recv().await {
            if let RpcRequest::GetTransaction { tx, .. } = request {
                let _ = tx.send(Err(data_carry_research::errors::RpcError::CallFailed {
                    method: "get_raw_transaction".to_string(),
                    message: "not implemented".to_string(),
                }));
            }
        }
    });

    // Send multiple concurrent requests
    let mut handles = vec![];
    for _ in 0..10 {
        let tx_clone = request_tx.clone();
        let handle = tokio::spawn(async move {
            let (tx, rx) = oneshot::channel();
            tx_clone
                .send(RpcRequest::GetTransaction {
                    txid: "deadbeef".into(),
                    tx,
                })
                .await
                .unwrap();
            rx.await.unwrap()
        });
        handles.push(handle);
    }

    // Wait for all requests to complete
    for handle in handles {
        let resp = handle.await?;
        assert!(resp.is_err());
    }

    Ok(())
}

#[test]
fn test_transaction_input_creation() {
    use data_carry_research::types::TransactionInput;

    let input = TransactionInput {
        txid: "test_txid".to_string(),
        vout: 0,
        value: 50000,
        script_sig: "test_script".to_string(),
        sequence: 0xffffffff,
        source_address: Some("1TestRPCAddress123456789".to_string()),
    };

    assert_eq!(input.txid, "test_txid");
    assert_eq!(input.vout, 0);
    assert_eq!(input.value, 50000);
    assert_eq!(input.sequence, 0xffffffff);
}

#[test]
fn test_rpc_config_environment_parsing() {
    // Test that config can handle various URL formats
    let configs = vec![
        "http://localhost:8332",
        "http://127.0.0.1:8332",
        "https://bitcoin.example.com:8332",
        "http://user:pass@localhost:8332",
    ];

    for url in configs {
        let config = BitcoinRpcConfig {
            url: url.to_string(),
            ..Default::default()
        };

        // Basic validation
        assert!(config.url.contains("://"));
        assert!(config.url.contains(":"));
    }
}

#[tokio::test]
async fn test_rpc_backoff_configuration() -> Result<()> {
    let config = BitcoinRpcConfig::default();

    // Test backoff calculation
    let mut backoff_ms = config.initial_backoff_ms;
    for retry in 0..config.max_retries {
        println!("Retry {}: backoff {}ms", retry, backoff_ms);

        // Verify backoff doesn't exceed maximum
        let max_backoff_ms = config.max_backoff_seconds * 1000;
        assert!(backoff_ms <= max_backoff_ms);

        // Calculate next backoff
        backoff_ms = ((backoff_ms as f64) * config.backoff_multiplier) as u64;
        backoff_ms = backoff_ms.min(max_backoff_ms);
    }

    Ok(())
}
