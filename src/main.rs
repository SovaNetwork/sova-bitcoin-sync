use alloy::{
    hex,
    network::EthereumWallet,
    primitives::{Address, B256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use async_trait::async_trait;
use bitcoincore_rpc::{Auth, Client as CoreClient, RpcApi};
use clap::Parser;
use serde_json::{json, Value};
use std::{
    error::Error,
    str::FromStr,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time,
};
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

    /// RPC connection type (bitcoincore, external)
    #[arg(
        long,
        default_value = "bitcoincore",
        help = "RPC connection type (bitcoincore, external)"
    )]
    rpc_connection_type: String,

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

impl Args {
    fn parse_connection_type(&self) -> Result<String, String> {
        match self.rpc_connection_type.to_lowercase().as_str() {
            "bitcoincore" | "external" => Ok(self.rpc_connection_type.to_lowercase()),
            other => Err(format!("Unsupported connection type: {other}")),
        }
    }
}

#[async_trait]
trait BitcoinRpcClient: Send + Sync {
    async fn get_block_count(&self) -> Result<u64, Box<dyn Error + Send + Sync>>;
    async fn get_block_hash(&self, height: u64) -> Result<String, Box<dyn Error + Send + Sync>>;
}

struct BitcoinCoreRpcClient {
    client: CoreClient,
}

impl BitcoinCoreRpcClient {
    fn new(url: &str, user: &str, password: &str) -> Result<Self, bitcoincore_rpc::Error> {
        let auth = if user.is_empty() && password.is_empty() {
            Auth::None
        } else {
            Auth::UserPass(user.to_string(), password.to_string())
        };
        let client = CoreClient::new(url, auth)?;
        Ok(Self { client })
    }
}

#[async_trait]
impl BitcoinRpcClient for BitcoinCoreRpcClient {
    async fn get_block_count(&self) -> Result<u64, Box<dyn Error + Send + Sync>> {
        Ok(self.client.get_block_count()?)
    }

    async fn get_block_hash(&self, height: u64) -> Result<String, Box<dyn Error + Send + Sync>> {
        Ok(self.client.get_block_hash(height)?.to_string())
    }
}

struct ExternalRpcClient {
    client: reqwest::Client,
    url: String,
    user: Option<String>,
    password: Option<String>,
}

impl ExternalRpcClient {
    fn new(url: String, user: String, password: String) -> Self {
        let user = if user.is_empty() { None } else { Some(user) };
        let password = if password.is_empty() {
            None
        } else {
            Some(password)
        };
        Self {
            client: reqwest::Client::new(),
            url,
            user,
            password,
        }
    }

    async fn call_rpc(
        &self,
        method: &str,
        params: Vec<Value>,
    ) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let mut req = self
            .client
            .post(&self.url)
            .json(&json!({
                "jsonrpc": "1.0",
                "id": "1",
                "method": method,
                "params": params
            }))
            .timeout(Duration::from_secs(60));

        if let Some(ref user) = self.user {
            req = req.basic_auth(user, self.password.as_deref());
        }

        let response = req
            .send()
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;

        let json: Value = response
            .json()
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        Ok(json)
    }
}

#[async_trait]
impl BitcoinRpcClient for ExternalRpcClient {
    async fn get_block_count(&self) -> Result<u64, Box<dyn Error + Send + Sync>> {
        let json = self.call_rpc("getblockcount", Vec::new()).await?;
        let result: u64 = serde_json::from_value(json["result"].clone())
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        Ok(result)
    }

    async fn get_block_hash(&self, height: u64) -> Result<String, Box<dyn Error + Send + Sync>> {
        let json = self.call_rpc("getblockhash", vec![json!(height)]).await?;
        let result: String = serde_json::from_value(json["result"].clone())
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        Ok(result)
    }
}

struct AdminService {
    bitcoin_rpc: Arc<dyn BitcoinRpcClient>,
    sequencer_rpc_url: String,
    admin_private_key: String,
    contract_address: Address,
    confirmation_blocks: u64,
    health_status: Arc<RwLock<HealthStatus>>,
}

impl AdminService {
    async fn new(args: &Args) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let connection_type = args.parse_connection_type().map_err(|e| {
            Box::new(std::io::Error::new(std::io::ErrorKind::Other, e))
                as Box<dyn Error + Send + Sync>
        })?;
        let bitcoin_rpc: Arc<dyn BitcoinRpcClient> = match connection_type.as_str() {
            "bitcoincore" => Arc::new(BitcoinCoreRpcClient::new(
                &args.btc_rpc_url,
                &args.btc_rpc_user,
                &args.btc_rpc_password,
            )?),
            "external" => Arc::new(ExternalRpcClient::new(
                args.btc_rpc_url.clone(),
                args.btc_rpc_user.clone(),
                args.btc_rpc_password.clone(),
            )),
            _ => unreachable!(),
        };

        // Parse contract address
        let contract_address: Address = args
            .contract_address
            .parse()
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;

        Ok(Self {
            bitcoin_rpc,
            sequencer_rpc_url: args.sequencer_rpc_url.clone(),
            admin_private_key: args.admin_private_key.clone(),
            contract_address,
            confirmation_blocks: args.confirmation_blocks,
            health_status: Arc::new(RwLock::new(HealthStatus::new())),
        })
    }

    async fn get_bitcoin_block_data(&self) -> Result<(u64, B256), Box<dyn Error + Send + Sync>> {
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
                    status.last_error = Some(format!("Bitcoin RPC error: {e}"));
                }
                return Err(e);
            }
        };

        // Calculate the height for the confirmation block
        // saturating_sub returns 0 if the subtraction would underflow
        let target_height = current_height.saturating_sub(self.confirmation_blocks);

        // Get the block hash at the target height
        let block_hash_str = self.bitcoin_rpc.get_block_hash(target_height).await?;

        // Convert hex string to B256
        let block_hash = B256::from_str(&block_hash_str)
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;

        Ok((current_height, block_hash))
    }

    async fn update_contract(
        &self,
        block_height: u64,
        block_hash: B256,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        info!(
            "Updating contract with block height {block_height} and hash 0x{}",
            hex::encode(block_hash)
        );

        // Parse private key and create signer
        let private_key = self.admin_private_key.trim_start_matches("0x");
        let signer: PrivateKeySigner = private_key
            .parse()
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        let wallet = EthereumWallet::from(signer);

        // Create provider with wallet
        let provider = ProviderBuilder::new().wallet(wallet).connect_http(
            self.sequencer_rpc_url
                .parse()
                .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?,
        );

        // Create contract instance
        let contract = SovaL1Block::new(self.contract_address, provider);

        let tx = contract
            .setBitcoinBlockData(block_height, block_hash)
            .send()
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;

        let receipt = tx
            .get_receipt()
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;

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
                        "Bitcoin block data: height={block_height}, hash=0x{}",
                        hex::encode(block_hash)
                    );

                    if let Err(e) = self.update_contract(block_height, block_hash).await {
                        warn!("Failed to update contract: {e}");
                        // Update health status on contract update failure
                        if let Ok(mut status) = self.health_status.write() {
                            status.sequencer_rpc_healthy = false;
                            status.last_error = Some(format!("Contract update error: {e}"));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to get Bitcoin block data: {e}");
                }
            }
        }
    }

    fn get_health_status(&self) -> Arc<RwLock<HealthStatus>> {
        self.health_status.clone()
    }
}

// Health check handlers
async fn handle_health_request(
    path: &str,
    health_status: Arc<RwLock<HealthStatus>>,
) -> (u16, String) {
    match path {
        "/health" => match health_status.read() {
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

                let status_code = if is_healthy { 200 } else { 503 };
                (status_code, response.to_string())
            }
            Err(_) => (500, json!({"error": "Internal server error"}).to_string()),
        },
        "/ready" => match health_status.read() {
            Ok(status) => {
                let is_ready = status.bitcoin_rpc_healthy && status.sequencer_rpc_healthy;
                let response = json!({
                    "status": if is_ready { "ready" } else { "not_ready" },
                    "bitcoin_rpc_healthy": status.bitcoin_rpc_healthy,
                    "sequencer_rpc_healthy": status.sequencer_rpc_healthy
                });

                let status_code = if is_ready { 200 } else { 503 };
                (status_code, response.to_string())
            }
            Err(_) => (500, json!({"error": "Internal server error"}).to_string()),
        },
        "/live" => (200, json!({ "status": "alive" }).to_string()),
        _ => (404, json!({"error": "Not found"}).to_string()),
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    health_status: Arc<RwLock<HealthStatus>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).await?;

    let request = String::from_utf8_lossy(&buffer[..n]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    let (status_code, body) = handle_health_request(path, health_status).await;

    let status_text = match status_code {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    };

    let response = format!(
        "HTTP/1.1 {status_code} {status_text}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn start_health_server(
    health_status: Arc<RwLock<HealthStatus>>,
    port: u16,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    info!("Health check server running on port {}", port);

    loop {
        let (stream, _) = listener.accept().await?;
        let health_status_clone = health_status.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, health_status_clone).await {
                warn!("Error handling health check connection: {}", e);
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
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
                warn!("Health server failed: {e}");
            }
        }
    }

    Ok(())
}
