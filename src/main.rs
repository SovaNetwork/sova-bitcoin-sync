mod bitcoin;
mod sync_service;

use alloy::{network::EthereumWallet, providers::WalletProvider, signers::local::PrivateKeySigner};
use anyhow::{anyhow, bail, Result as AnyResult};
use bitcoin::create_bitcoin_rpc_client;
use clap::Parser;
use serde_json::json;
use std::{
    error::Error,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use sync_service::{GasCfg, HealthStatus, SyncService};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{info, warn};

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

    /// RBF timeout in seconds
    #[arg(long, default_value = "60")]
    rbf_timeout_seconds: u64,

    /// Minimum tip in wei for gas calculations (default: 1 gwei)
    #[arg(long, default_value = "1000000000")]
    min_tip_wei: u128,

    /// Maximum fee cap in wei for gas calculations (default: 200 gwei)
    #[arg(long, default_value = "200000000000")]
    max_fee_cap_wei: u128,
}

impl Args {
    fn parse_connection_type(&self) -> Result<String, String> {
        match self.rpc_connection_type.to_lowercase().as_str() {
            "bitcoincore" | "external" => Ok(self.rpc_connection_type.to_lowercase()),
            other => Err(format!("Unsupported connection type: {other}")),
        }
    }
}

// Health check handlers
async fn handle_health_request(
    path: &str,
    health_status: Arc<RwLock<HealthStatus>>,
    gas_cfg: &GasCfg,
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
                    "last_error": status.last_error,
                    "nonce_metrics": {
                        "nonce_latest": status.nonce_metrics.nonce_latest,
                        "nonce_pending": status.nonce_metrics.nonce_pending,
                        "in_flight_count": status.nonce_metrics.in_flight_count,
                        "in_flight_nonce": status.nonce_metrics.in_flight_nonce,
                        "waiting_rbf": status.nonce_metrics.waiting_rbf,
                        "last_submitted": {
                            "height": status.nonce_metrics.last_submitted_height,
                            "hash": status.nonce_metrics.last_submitted_hash
                        },
                        "last_mined": {
                            "height": status.nonce_metrics.last_mined_height,
                            "hash": status.nonce_metrics.last_mined_hash
                        },
                        "last_tx_hash": status.nonce_metrics.last_tx_hash,
                        "last_rbf_count": status.nonce_metrics.last_rbf_count,
                        "last_max_fee_per_gas": status.nonce_metrics.last_max_fee_per_gas.map(|v| v.to_string()),
                        "last_priority_fee_per_gas": status.nonce_metrics.last_priority_fee_per_gas.map(|v| v.to_string()),
                        "observed_base_fee": status.nonce_metrics.observed_base_fee.map(|v| v.to_string()),
                        "last_max_fee_per_gas_gwei": status.nonce_metrics.last_max_fee_per_gas.map(|v| (v / 1_000_000_000).to_string()),
                        "last_priority_fee_per_gas_gwei": status.nonce_metrics.last_priority_fee_per_gas.map(|v| (v / 1_000_000_000).to_string()),
                        "observed_base_fee_gwei": status.nonce_metrics.observed_base_fee.map(|v| (v / 1_000_000_000).to_string())
                    },
                    "gas_policy": {
                        "min_tip_wei": gas_cfg.min_tip.to_string(),
                        "max_fee_cap_wei": gas_cfg.max_fee_cap.to_string(),
                        "min_tip_gwei": (gas_cfg.min_tip / 1_000_000_000).to_string(),
                        "max_fee_cap_gwei": (gas_cfg.max_fee_cap / 1_000_000_000).to_string()
                    },
                    "wallet": {
                        "balance_wei": status.wallet_balance_wei.map(|v| v.to_string()),
                        "balance_eth": status.wallet_balance_eth.map(|v| format!("{v:.6}")),
                        "low_balance_warning": status.low_balance_warning,
                        "last_balance_check": status.last_balance_check
                    }
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
        "/debug/nonces" => match health_status.read() {
            Ok(status) => {
                let in_flight_info = status.nonce_metrics.in_flight_nonce.map(|n| {
                    json!({
                        "nonce": n,
                        "tx_hash": status.nonce_metrics.last_tx_hash,
                        "rbf_count": status.nonce_metrics.last_rbf_count
                    })
                });

                let gap = status
                    .nonce_metrics
                    .nonce_pending
                    .saturating_sub(status.nonce_metrics.nonce_latest);

                let response = json!({
                    "latest": status.nonce_metrics.nonce_latest,
                    "pending": status.nonce_metrics.nonce_pending,
                    "gap": gap,
                    "in_flight": in_flight_info,
                });

                (200, response.to_string())
            }
            Err(_) => (500, json!({"error": "Internal server error"}).to_string()),
        },
        _ => (404, json!({"error": "Not found"}).to_string()),
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    health_status: Arc<RwLock<HealthStatus>>,
    gas_cfg: &GasCfg,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut buffer = [0; 8192]; // Increased for proxy compatibility
    let n = stream.read(&mut buffer).await?;

    let request = String::from_utf8_lossy(&buffer[..n]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    let (status_code, body) = handle_health_request(path, health_status, gas_cfg).await;

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
    gas_cfg: GasCfg,
    port: u16,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    info!("Health check server running on port {}", port);

    loop {
        let (stream, _) = listener.accept().await?;
        let health_status_clone = health_status.clone();
        let gas_cfg_clone = gas_cfg.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, health_status_clone, &gas_cfg_clone).await {
                warn!("Error handling health check connection: {}", e);
            }
        });
    }
}

#[tokio::main]
async fn main() -> AnyResult<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    // Validate CLI flags
    if args.min_tip_wei == 0 {
        bail!("--min-tip-wei must be > 0");
    }
    if args.min_tip_wei > args.max_fee_cap_wei {
        bail!(
            "--min-tip-wei ({}) cannot exceed --max-fee-cap-wei ({})",
            args.min_tip_wei,
            args.max_fee_cap_wei
        );
    }

    // gas floors/caps
    let gas_cfg = GasCfg {
        min_tip: args.min_tip_wei,
        max_fee_cap: args.max_fee_cap_wei,
    };

    let gwei = |v: u128| format!("{:.9}", (v as f64) / 1_000_000_000f64);

    // Bitcoin RPC selection
    let bitcoin_rpc = create_bitcoin_rpc_client(
        &args
            .parse_connection_type()
            .map_err(std::io::Error::other)?,
        &args.btc_rpc_url,
        &args.btc_rpc_user,
        &args.btc_rpc_password,
    )?;

    // Wallet & provider
    let signer: PrivateKeySigner = args.admin_private_key.trim_start_matches("0x").parse()?;
    let wallet = EthereumWallet::from(signer);
    let url = args.sequencer_rpc_url.parse()?;

    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(wallet.clone())
        .connect_http(url);

    // Get wallet address before moving provider
    let wallet_address = provider.default_signer_address();

    // Create SyncService
    let service = SyncService::new(
        bitcoin_rpc,
        provider,
        &args.contract_address,
        args.confirmation_blocks,
        args.rbf_timeout_seconds,
        gas_cfg.clone(),
    )
    .await
    .map_err(|e| anyhow!("Failed to create sync service: {}", e))?;

    // Initial balance check
    info!("Performing initial wallet balance check...");
    service.refresh_balance_metrics().await;

    let update_interval = Duration::from_secs(args.update_interval);
    let health_status = service.get_health_status();
    let health_port = args.health_port;

    info!(
        "Starting Sova Bitcoin Sync. Signer: {:#x} | Health server: http://0.0.0.0:{} |",
        wallet_address, health_port,
    );
    info!(
        "Gas policy: MIN_TIP={} gwei, MAX_FEE_CAP={} gwei",
        gwei(gas_cfg.min_tip),
        gwei(gas_cfg.max_fee_cap)
    );

    tokio::select! {
        _ = service.run(update_interval) => warn!("Sync service exited unexpectedly"),
        result = start_health_server(health_status, gas_cfg.clone(), health_port) => {
            if let Err(e) = result { warn!("Health server failed: {e}"); }
        }
    }

    Ok(())
}
