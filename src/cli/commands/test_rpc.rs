use crate::config::AppConfig;
use crate::errors::{AppError, AppResult};
use clap::Args;
use tracing::{error, info};

/// Test Bitcoin RPC connectivity
#[derive(Args)]
pub struct TestRpcCommand {
    /// Bitcoin RPC URL
    #[arg(long)]
    pub rpc_url: Option<String>,

    /// Bitcoin RPC username
    #[arg(long)]
    pub rpc_username: Option<String>,

    /// Bitcoin RPC password
    #[arg(long)]
    pub rpc_password: Option<String>,
}

impl TestRpcCommand {
    pub async fn run(&self) -> AppResult<()> {
        info!("=== Testing Bitcoin RPC Connection ===");

        // Load configuration or use defaults
        let app_config = AppConfig::get_defaults().map_err(|e| AppError::Config(e.to_string()))?;
        let mut rpc_config = app_config.bitcoin_rpc;

        // Override with CLI arguments
        if let Some(url) = &self.rpc_url {
            rpc_config.url = url.clone();
        }
        if let Some(username) = &self.rpc_username {
            rpc_config.username = username.clone();
        }
        if let Some(password) = &self.rpc_password {
            rpc_config.password = password.clone();
        }

        info!("Testing connection to: {}", rpc_config.url);
        info!("Username: {}", rpc_config.username);

        match crate::rpc::BitcoinRpcClient::new(rpc_config).await {
            Ok(client) => {
                info!("RPC connection successful!");

                // Test a simple RPC call
                match client.test_connection().await {
                    Ok(()) => {
                        println!("Bitcoin RPC connection test PASSED");
                        println!("Connection is working correctly!");
                    }
                    Err(e) => {
                        error!("RPC connection test failed: {}", e);
                        return Err(AppError::Config(format!("RPC test failed: {}", e)));
                    }
                }
            }
            Err(e) => {
                error!("Failed to create RPC client: {}", e);
                println!("Bitcoin RPC connection test FAILED");
                println!("Error: {}", e);
                println!("\nTroubleshooting tips:");
                println!("1. Check that Bitcoin Core is running");
                println!("2. Verify the RPC URL is correct");
                println!("3. Ensure RPC credentials are valid");
                println!("4. Check that RPC server is enabled in bitcoin.conf");

                return Err(AppError::Config(format!(
                    "RPC client creation failed: {}",
                    e
                )));
            }
        }

        Ok(())
    }
}
