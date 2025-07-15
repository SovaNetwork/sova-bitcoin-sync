use alloy::{
    hex,
    network::EthereumWallet,
    primitives::{Address, B256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use axum::{extract::State, http::StatusCode, response::Json, routing::get, Router};
use base64::Engine;
use clap::Parser;
use serde_json::{json, Value};
use std::{
    str::FromStr,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, time};
use tower::ServiceBuilder;
use tracing::{info, warn};

// Define the contract ABI using alloy's sol! macro
sol! {
    #[sol(rpc)]
    contract SovaL1Block {
        function setBitcoinBlockData(uint64 blockHeight, bytes32 blockHash) external;
        function currentBlockHeight() external view returns (uint64);
        function blockHashSixBlocksBack() external view returns (bytes32);
    }
}

#[derive(Debug, Clone)]
struct HealthStatus {
    pub started_at: u64,
    pub last_bitcoin_check: Option<u64>,
    pub last_contract_update: Option<u64>,
    pub bitcoin_rpc_healthy: bool,
    pub sequencer_rpc_healthy: bool,
    pub total_updates: u64,
    pub last_error: Option<String>,
}

impl HealthStatus {
    fn new() -> Self {
        Self {
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_bitcoin_check: None,
            last_contract_update: None,
            bitcoin_rpc_healthy: false,
            sequencer_rpc_healthy: false,
            total_updates: 0,
            last_error: None,
        }
    }

    fn is_healthy(&self) -> bool {
        self.bitcoin_rpc_healthy && self.sequencer_rpc_healthy
    }
}

#[derive(Parser)]
#[command(name = "sova-bitcoin-sync")]
#[command(about = "Sova Bitcoin Sync Service")]
struct Args {
    /// Bitcoin RPC URL
    #[arg(long, default_value = "http://bitcoin-regtest:18443")]
    btc_rpc_url: String,

    /// Bitcoin RPC username
    #[arg(long, default_value = "user")]
    btc_rpc_user: String,

    /// Bitcoin RPC password
    #[arg(long, default_value = "password")]
    btc_rpc_password: String,

    /// Sova sequencer RPC URL
    #[arg(long, default_value = "http://sova-reth:8545")]
    sequencer_rpc_url: String,

    /// Private key for the admin account (hex format without 0x prefix)
    #[arg(long, env = "ADMIN_PRIVATE_KEY")]
    admin_private_key: String,

    /// Contract address
    #[arg(long, default_value = "0x2100000000000000000000000000000000000015")]
    contract_address: String,

    /// Update interval in seconds
    #[arg(long, default_value = "10")]
    update_interval: u64,

    /// Confirmation blocks (how many blocks back to get hash)
    #[arg(long, default_value = "6")]
    confirmation_blocks: u64,

    /// Health check HTTP port
    #[arg(long, default_value = "8080")]
    health_port: u16,
}

struct BitcoinRpc {
    client: reqwest::Client,
    url: String,
    auth: String,
}

impl BitcoinRpc {
    fn new(url: String, user: String, password: String) -> Self {
        let auth =
            base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, password));
        Self {
            client: reqwest::Client::new(),
            url,
            auth,
        }
    }

    async fn get_block_count(&self) -> Result<u64, Box<dyn std::error::Error>> {
        let response = self
            .client
            .post(&self.url)
            .header("Authorization", format!("Basic {}", self.auth))
            .header("Content-Type", "application/json")
            .json(&json!({
                "jsonrpc": "1.0",
                "id": "getblockcount",
                "method": "getblockcount",
                "params": []
            }))
            .send()
            .await?;

        let json: Value = response.json().await?;
        if let Some(result) = json["result"].as_u64() {
            Ok(result)
        } else {
            Err(format!("Invalid response: {}", json).into())
        }
    }

    async fn get_block_hash(&self, height: u64) -> Result<String, Box<dyn std::error::Error>> {
        let response = self
            .client
            .post(&self.url)
            .header("Authorization", format!("Basic {}", self.auth))
            .header("Content-Type", "application/json")
            .json(&json!({
                "jsonrpc": "1.0",
                "id": "getblockhash",
                "method": "getblockhash",
                "params": [height]
            }))
            .send()
            .await?;

        let json: Value = response.json().await?;
        if let Some(result) = json["result"].as_str() {
            Ok(result.to_string())
        } else {
            Err(format!("Invalid response: {}", json).into())
        }
    }
}

struct AdminService {
    bitcoin_rpc: BitcoinRpc,
    sequencer_rpc_url: String,
    admin_private_key: String,
    contract_address: Address,
    confirmation_blocks: u64,
    health_status: Arc<RwLock<HealthStatus>>,
}

impl AdminService {
    async fn new(args: &Args) -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize Bitcoin RPC client
        let bitcoin_rpc = BitcoinRpc::new(
            args.btc_rpc_url.clone(),
            args.btc_rpc_user.clone(),
            args.btc_rpc_password.clone(),
        );

        // Parse contract address
        let contract_address: Address = args.contract_address.parse()?;

        Ok(Self {
            bitcoin_rpc,
            sequencer_rpc_url: args.sequencer_rpc_url.clone(),
            admin_private_key: args.admin_private_key.clone(),
            contract_address,
            confirmation_blocks: args.confirmation_blocks,
            health_status: Arc::new(RwLock::new(HealthStatus::new())),
        })
    }

    async fn get_bitcoin_block_data(&self) -> Result<(u64, B256), Box<dyn std::error::Error>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Get current block height
        let current_height = match self.bitcoin_rpc.get_block_count().await {
            Ok(height) => {
                // Update health status - Bitcoin RPC is healthy
                if let Ok(mut status) = self.health_status.write() {
                    status.bitcoin_rpc_healthy = true;
                    status.last_bitcoin_check = Some(now);
                }
                height
            }
            Err(e) => {
                // Update health status - Bitcoin RPC is unhealthy
                if let Ok(mut status) = self.health_status.write() {
                    status.bitcoin_rpc_healthy = false;
                    status.last_error = Some(format!("Bitcoin RPC error: {}", e));
                }
                return Err(e);
            }
        };

        // Calculate the height for the confirmation block
        let target_height = if current_height >= self.confirmation_blocks {
            current_height - self.confirmation_blocks
        } else {
            // If we don't have enough blocks yet, use block 0
            0
        };

        // Get the block hash at the target height
        let block_hash_str = self.bitcoin_rpc.get_block_hash(target_height).await?;

        // Convert hex string to B256
        let block_hash = B256::from_str(&block_hash_str)?;

        Ok((current_height, block_hash))
    }

    async fn update_contract(
        &self,
        block_height: u64,
        block_hash: B256,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!(
            "Updating contract with block height {} and hash 0x{}",
            block_height,
            hex::encode(block_hash)
        );

        // Parse private key and create signer
        let private_key = self.admin_private_key.trim_start_matches("0x");
        let signer: PrivateKeySigner = private_key.parse()?;
        let wallet = EthereumWallet::from(signer);

        // Create provider with wallet
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(self.sequencer_rpc_url.parse()?);

        // Create contract instance
        let contract = SovaL1Block::new(self.contract_address, provider);

        let tx = contract
            .setBitcoinBlockData(block_height, block_hash)
            .send()
            .await?;

        let receipt = tx.get_receipt().await?;

        info!(
            "Transaction successful: 0x{} (block: {})",
            hex::encode(receipt.transaction_hash),
            receipt.block_number.unwrap_or_default()
        );

        // Update health status - successful contract update
        if let Ok(mut status) = self.health_status.write() {
            status.sequencer_rpc_healthy = true;
            status.last_contract_update = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            );
            status.total_updates += 1;
        }

        Ok(())
    }

    async fn run(&self, update_interval: Duration) {
        let mut interval = time::interval(update_interval);

        info!("Starting Sova Bitcoin Sync Service...");
        info!("Update interval: {} seconds", update_interval.as_secs());
        info!("Confirmation blocks: {}", self.confirmation_blocks);

        loop {
            interval.tick().await;

            match self.get_bitcoin_block_data().await {
                Ok((block_height, block_hash)) => {
                    info!(
                        "Bitcoin block data: height={}, hash=0x{}",
                        block_height,
                        hex::encode(block_hash)
                    );

                    if let Err(e) = self.update_contract(block_height, block_hash).await {
                        warn!("Failed to update contract: {}", e);
                        // Update health status on contract update failure
                        if let Ok(mut status) = self.health_status.write() {
                            status.sequencer_rpc_healthy = false;
                            status.last_error = Some(format!("Contract update error: {}", e));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to get Bitcoin block data: {}", e);
                }
            }
        }
    }

    fn get_health_status(&self) -> Arc<RwLock<HealthStatus>> {
        self.health_status.clone()
    }
}

// Health check handlers
async fn health_check(
    State(health_status): State<Arc<RwLock<HealthStatus>>>,
) -> Result<Json<Value>, StatusCode> {
    match health_status.read() {
        Ok(status) => {
            let is_healthy = status.is_healthy();
            let response = json!({
                "status": if is_healthy { "healthy" } else { "unhealthy" },
                "started_at": status.started_at,
                "uptime_seconds": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() - status.started_at,
                "bitcoin_rpc_healthy": status.bitcoin_rpc_healthy,
                "sequencer_rpc_healthy": status.sequencer_rpc_healthy,
                "last_bitcoin_check": status.last_bitcoin_check,
                "last_contract_update": status.last_contract_update,
                "total_updates": status.total_updates,
                "last_error": status.last_error
            });

            if is_healthy {
                Ok(Json(response))
            } else {
                Err(StatusCode::SERVICE_UNAVAILABLE)
            }
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn readiness_check(
    State(health_status): State<Arc<RwLock<HealthStatus>>>,
) -> Result<Json<Value>, StatusCode> {
    match health_status.read() {
        Ok(status) => {
            // Service is ready if it has started and both RPCs are healthy
            let is_ready = status.bitcoin_rpc_healthy && status.sequencer_rpc_healthy;
            let response = json!({
                "status": if is_ready { "ready" } else { "not_ready" },
                "bitcoin_rpc_healthy": status.bitcoin_rpc_healthy,
                "sequencer_rpc_healthy": status.sequencer_rpc_healthy
            });

            if is_ready {
                Ok(Json(response))
            } else {
                Err(StatusCode::SERVICE_UNAVAILABLE)
            }
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn liveness_check() -> Json<Value> {
    Json(json!({ "status": "alive" }))
}

async fn start_health_server(
    health_status: Arc<RwLock<HealthStatus>>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        .route("/live", get(liveness_check))
        .layer(ServiceBuilder::new())
        .with_state(health_status);

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!("Health check server running on port {}", port);

    axum::serve(listener, app).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let args = Args::parse();

    // Create the admin service
    let service = AdminService::new(&args).await?;
    let update_interval = Duration::from_secs(args.update_interval);

    // Get health status for the health server
    let health_status = service.get_health_status();
    let health_port = args.health_port;

    info!(
        "Starting Sova Bitcoin Sync Service with health checks on port {}",
        health_port
    );

    // Run both the sync service and health server concurrently
    tokio::select! {
        _ = service.run(update_interval) => {
            warn!("Sync service exited unexpectedly");
        }
        result = start_health_server(health_status, health_port) => {
            if let Err(e) = result {
                warn!("Health server failed: {}", e);
            }
        }
    }

    Ok(())
}
