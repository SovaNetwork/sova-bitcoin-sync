use alloy::{
    hex,
    network::EthereumWallet,
    primitives::{Address, B256, U256},
    providers::{Provider, WalletProvider},
    rpc::types::BlockNumberOrTag,
    signers::local::PrivateKeySigner,
    sol,
};
use async_trait::async_trait;
use backoff::{backoff::Backoff, ExponentialBackoff};
use bitcoincore_rpc::{Auth, Client as CoreClient, RpcApi};
use clap::Parser;
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    error::Error,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time,
};
use tracing::{debug, info, warn};

// Gas management constants
const MAX_RBF_ATTEMPTS: u32 = 8;
const DEFAULT_BASE_FEE: u128 = 1_000_000_000; // 1 gwei fallback
const BUMP_MULTIPLIER: u32 = 15; // 15% increase per RBF

// Runtime gas configuration
#[derive(Debug, Clone)]
struct GasCfg {
    min_tip: u128,
    max_fee_cap: u128,
}

// SovaL1Block contract interface
sol! {
    #[sol(rpc)]
    contract SovaL1Block {
        function setBitcoinBlockData(uint64 blockHeight, bytes32 blockHash) external;
        function currentBlockHeight() external view returns (uint64);
        function blockHashSixBlocksBack() external view returns (bytes32);
    }
}

#[derive(Debug, Clone, Default)]
struct NonceMetrics {
    pub nonce_latest: u64,
    pub nonce_pending: u64,
    pub in_flight_count: u32,
    pub last_submitted_height: Option<u64>,
    pub last_submitted_hash: Option<String>,
    pub last_mined_height: Option<u64>,
    pub last_mined_hash: Option<String>,
    pub last_tx_hash: Option<String>,
    pub last_rbf_count: u32,
    pub last_max_fee_per_gas: Option<u128>,
    pub last_priority_fee_per_gas: Option<u128>,
    pub observed_base_fee: Option<u128>,
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
    pub nonce_metrics: NonceMetrics,
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
            nonce_metrics: NonceMetrics::default(),
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

    /// RBF timeout in seconds
    #[arg(long, default_value = "60")]
    rbf_timeout_seconds: u64,

    /// Minimum tip in gwei (floor for maxPriorityFeePerGas)
    #[arg(long, default_value = "1")]
    min_tip_gwei: u128,

    /// Maximum maxFeePerGas cap in gwei (ceiling for fees)
    #[arg(long, default_value = "200")]
    max_fee_cap_gwei: u128,
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
    request_id: AtomicU64,
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
            request_id: AtomicU64::new(0),
        }
    }

    async fn call_rpc(
        &self,
        method: &str,
        params: Vec<Value>,
    ) -> Result<Value, Box<dyn Error + Send + Sync>> {
        let id = self.request_id.fetch_add(1, Ordering::SeqCst);
        let mut req = self
            .client
            .post(&self.url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": id,
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

        if json.get("error").is_some() && !json["error"].is_null() {
            return Err(format!("RPC error on {method}: {}", json["error"]).into());
        }
        Ok(json["result"].clone())
    }
}

#[async_trait]
impl BitcoinRpcClient for ExternalRpcClient {
    async fn get_block_count(&self) -> Result<u64, Box<dyn Error + Send + Sync>> {
        let res = self.call_rpc("getblockcount", Vec::new()).await?;
        let result: u64 =
            serde_json::from_value(res).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        Ok(result)
    }

    async fn get_block_hash(&self, height: u64) -> Result<String, Box<dyn Error + Send + Sync>> {
        let res = self.call_rpc("getblockhash", vec![json!(height)]).await?;
        let result: String =
            serde_json::from_value(res).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        Ok(result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BitcoinBlockUpdate {
    confirmed_height: u64, // The actual confirmed block height
    hash: B256,            // Hash at the confirmed height
}

#[derive(Debug, Clone)]
struct InFlightTransaction {
    tx_hash: B256,
    nonce: u64,
    block_update: BitcoinBlockUpdate,
    submitted_at: u64,
    rbf_count: u32,
    last_tip: u128,
}

struct SyncService<P>
where
    P: Provider + WalletProvider + Clone + Send + Sync + 'static,
{
    bitcoin_rpc: Arc<dyn BitcoinRpcClient>,
    confirmation_blocks: u64,
    rbf_timeout_seconds: u64,
    health_status: Arc<RwLock<HealthStatus>>,
    processed_blocks: Arc<RwLock<HashSet<BitcoinBlockUpdate>>>,
    in_flight_tx: Arc<RwLock<Option<InFlightTransaction>>>,
    provider: P,
    contract: SovaL1Block::SovaL1BlockInstance<P>,
    gas: GasCfg,
}

impl<P> SyncService<P>
where
    P: Provider + WalletProvider + Clone + Send + Sync + 'static,
{
    async fn new_with(
        args: &Args,
        bitcoin_rpc: Arc<dyn BitcoinRpcClient>,
        provider: P,
        gas_cfg: GasCfg,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Parse contract address once
        let contract_address: Address = args.contract_address.parse()?;
        let contract = SovaL1Block::new(contract_address, provider.clone());

        Ok(Self {
            bitcoin_rpc,
            confirmation_blocks: args.confirmation_blocks,
            rbf_timeout_seconds: args.rbf_timeout_seconds,
            health_status: Arc::new(RwLock::new(HealthStatus::new())),
            processed_blocks: Arc::new(RwLock::new(HashSet::new())),
            in_flight_tx: Arc::new(RwLock::new(None)),
            provider,
            contract,
            gas: gas_cfg,
        })
    }

    async fn suggest_tip_and_basefee_with<T: Provider>(
        provider: &T,
        gas_cfg: &GasCfg,
    ) -> Result<(u128, u128), Box<dyn Error + Send + Sync>> {
        // 1) Try feeHistory for last 5 blocks, 50th percentile
        if let Ok(hist) = provider
            .get_fee_history(
                5u64,                      // blockCount
                BlockNumberOrTag::Pending, // newestBlock
                &[50.0],                   // reward percentiles
            )
            .await
        {
            let base_fees = hist.base_fee_per_gas;
            // base_fee of the pending block is last baseFee in feeHistory
            let base = match base_fees.last() {
                Some(v) => {
                    let u256_val = U256::from(*v);
                    u256_val.to::<u128>().min(gas_cfg.max_fee_cap)
                }
                None => DEFAULT_BASE_FEE,
            };

            // reward is Vec<Vec<u128 or U256>>; use last reward's 50th percentile
            if let Some(rew) = hist.reward.as_ref().and_then(|r| r.last()) {
                if let Some(mid) = rew.first() {
                    // Cast robustly and apply floor policy
                    let u256_tip = U256::from(*mid);
                    let p50_tip = u256_tip.to::<u128>();
                    let mpg = provider
                        .get_max_priority_fee_per_gas()
                        .await
                        .ok()
                        .map(|v| U256::from(v).to::<u128>())
                        .unwrap_or(0);

                    // Compute effective tip = max(p50, maxPriority, min_tip)
                    let tip = std::cmp::max(std::cmp::max(p50_tip, mpg), gas_cfg.min_tip)
                        .min(gas_cfg.max_fee_cap);

                    info!(
                        "Tip sources: p50={} gwei, maxPriority={} gwei, floor={} gwei -> chosen={} gwei",
                        p50_tip / 1_000_000_000,
                        mpg / 1_000_000_000,
                        gas_cfg.min_tip / 1_000_000_000,
                        tip / 1_000_000_000
                    );
                    return Ok((tip, base));
                }
            }
            return Ok((gas_cfg.min_tip, base));
        }

        // 2) Fallback to maxPriorityFeePerGas + pending.baseFee
        let mpg = provider
            .get_max_priority_fee_per_gas()
            .await
            .ok()
            .map(|v| U256::from(v).to::<u128>())
            .unwrap_or(0);

        // Apply floor policy: max(maxPriority, min_tip)
        let tip_fallback = std::cmp::max(mpg, gas_cfg.min_tip).min(gas_cfg.max_fee_cap);

        let base = provider
            .get_block_by_number(BlockNumberOrTag::Pending)
            .await
            .ok()
            .flatten()
            .and_then(|b| b.header.base_fee_per_gas)
            .map(|v| {
                // works whether v is U256-like or primitive via Into<U256>
                let u = U256::from(v);
                u.to::<u128>().min(gas_cfg.max_fee_cap)
            })
            .unwrap_or(DEFAULT_BASE_FEE);

        info!(
            "Tip sources: p50=0 gwei, maxPriority={} gwei, floor={} gwei -> chosen={} gwei",
            mpg / 1_000_000_000,
            gas_cfg.min_tip / 1_000_000_000,
            tip_fallback / 1_000_000_000
        );
        Ok((tip_fallback, base))
    }

    async fn calculate_gas_fees_with<T: Provider>(
        provider: &T,
        gas_cfg: &GasCfg,
        rbf_count: u32,
        last_tip: Option<u128>,
    ) -> (u128, u128) {
        // Get suggested values with sane fallbacks
        let (suggested_tip, base_fee) = Self::suggest_tip_and_basefee_with(provider, gas_cfg)
            .await
            .unwrap_or((gas_cfg.min_tip, DEFAULT_BASE_FEE));

        // Base tip to start from (use last_tip if we have it, else the suggestion)
        let base_tip = last_tip.unwrap_or(suggested_tip).max(gas_cfg.min_tip);

        // Compute compound bump factors for this attempt count
        let bump_per = 100u128 + (BUMP_MULTIPLIER as u128);
        let r = rbf_count.min(MAX_RBF_ATTEMPTS); // clamp just in case
        let num = bump_per.saturating_pow(r);
        let den = 100u128.saturating_pow(r);

        // Bumped tip (compounded). Guard and cap.
        let mut tip = base_tip
            .saturating_mul(num)
            .checked_div(den)
            .unwrap_or(base_tip)
            .clamp(gas_cfg.min_tip, gas_cfg.max_fee_cap);

        // Compute a bumped max_fee from (base_fee + tip), then apply invariants & cap.
        let mut max_fee = base_fee
            .saturating_add(tip)
            .saturating_mul(num)
            .checked_div(den)
            .unwrap_or_else(|| base_fee.saturating_add(tip));

        // Early sanity clamp in calculate_gas_fees_with (belt & suspenders)
        if gas_cfg.max_fee_cap <= base_fee {
            // cap cannot cover base fee; force a small headroom above base so tx is valid
            let needed = base_fee.saturating_add(1);
            // pick the largest tip we can under the cap
            tip = tip
                .min(
                    gas_cfg
                        .max_fee_cap
                        .saturating_sub(base_fee)
                        .saturating_sub(1),
                )
                .max(gas_cfg.min_tip);
            max_fee = needed.saturating_add(tip);
        }

        // Enforce invariants
        let min_required = base_fee.saturating_add(tip).saturating_add(1);
        if max_fee < min_required {
            max_fee = min_required;
        }
        if max_fee <= tip {
            max_fee = tip.saturating_add(1);
        }
        if max_fee > gas_cfg.max_fee_cap {
            max_fee = gas_cfg.max_fee_cap;
            // Ensure tip never exceeds (capped) max_fee - base_fee - 1
            let max_allowed_tip = max_fee.saturating_sub(base_fee).saturating_sub(1);
            if tip > max_allowed_tip {
                tip = max_allowed_tip.max(gas_cfg.min_tip);
            }
        }

        // Pretty logging with decimals so sub-gwei bumps are visible
        let gwei = |v: u128| {
            let v_f = (v as f64) / 1_000_000_000f64;
            format!("{v_f:.3}")
        };

        info!(
            "Gas calculation: base_fee={} gwei, tip={} gwei, max_fee={} gwei (RBF: {})",
            gwei(base_fee),
            gwei(tip),
            gwei(max_fee),
            rbf_count
        );

        (max_fee, tip)
    }

    fn is_underpriced_error(err_str: &str) -> bool {
        let s = err_str.to_lowercase();
        s.contains("replacement transaction underpriced")
            || s.contains("replacement underpriced")
            || s.contains("fee too low")
            || s.contains("underpriced")
            || s.contains("max fee per gas less than block base fee")
            || s.contains("tip too low")
            || s.contains("intrinsic gas too low") // sometimes a side effect
    }

    fn is_nonce_too_low_error(err_str: &str) -> bool {
        let s = err_str.to_lowercase();
        s.contains("nonce too low")
    }

    fn is_known_transaction_error(err_str: &str) -> bool {
        let s = err_str.to_lowercase();
        s.contains("already known") || s.contains("known transaction")
    }

    async fn get_bitcoin_block_data(
        &self,
    ) -> Result<(u64, u64, B256), Box<dyn Error + Send + Sync>> {
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
        let confirmed_height = current_height.saturating_sub(self.confirmation_blocks);

        // Get the block hash at the confirmed height
        let block_hash_str = self.bitcoin_rpc.get_block_hash(confirmed_height).await?;

        // Convert hex string to B256
        let block_hash = B256::from_str(&block_hash_str)
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;

        Ok((current_height, confirmed_height, block_hash))
    }

    async fn get_pending_nonce(&self) -> Result<u64, Box<dyn Error + Send + Sync>> {
        let mut backoff = ExponentialBackoff::default();
        let from = self.provider.default_signer_address();

        loop {
            match self.provider.get_transaction_count(from).pending().await {
                Ok(nonce) => {
                    if let Ok(mut status) = self.health_status.write() {
                        status.nonce_metrics.nonce_pending = nonce;
                    }
                    return Ok(nonce);
                }
                Err(e) => {
                    warn!("Failed to get pending nonce: {e}");
                    if let Ok(mut status) = self.health_status.write() {
                        status.last_error = Some(format!("Nonce fetch error: {e}"));
                    }

                    if let Some(delay) = backoff.next_backoff() {
                        time::sleep(delay).await;
                    } else {
                        return Err(Box::new(e) as Box<dyn Error + Send + Sync>);
                    }
                }
            }
        }
    }

    async fn refresh_nonce_metrics(&self) {
        // Get both latest and pending nonces for reconciliation using stored provider
        let from = self.provider.default_signer_address();

        if let Ok(latest) = self.provider.get_transaction_count(from).latest().await {
            if let Ok(mut s) = self.health_status.write() {
                s.nonce_metrics.nonce_latest = latest;
            }
        }

        if let Ok(pending) = self.provider.get_transaction_count(from).pending().await {
            if let Ok(mut s) = self.health_status.write() {
                s.nonce_metrics.nonce_pending = pending;
            }
        }
    }

    async fn check_transaction_receipt(
        &self,
        tx_hash: B256,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let mut backoff = ExponentialBackoff::default();

        loop {
            match self.provider.get_transaction_receipt(tx_hash).await {
                Ok(Some(receipt)) => {
                    if let Ok(mut status) = self.health_status.write() {
                        status.nonce_metrics.last_mined_height =
                            Some(receipt.block_number.unwrap_or_default());
                        status.nonce_metrics.last_mined_hash = Some(format!(
                            "0x{}",
                            hex::encode(receipt.block_hash.unwrap_or_default())
                        ));
                    }
                    return Ok(true);
                }
                Ok(None) => return Ok(false),
                Err(e) => {
                    warn!("Failed to check transaction receipt: {e}");

                    if let Some(delay) = backoff.next_backoff() {
                        time::sleep(delay).await;
                    } else {
                        return Err(Box::new(e) as Box<dyn Error + Send + Sync>);
                    }
                }
            }
        }
    }

    fn is_already_processed(&self, block_update: &BitcoinBlockUpdate) -> bool {
        if let Ok(processed) = self.processed_blocks.read() {
            processed.contains(block_update)
        } else {
            false
        }
    }

    fn mark_as_processed(&self, block_update: BitcoinBlockUpdate) {
        if let Ok(mut processed) = self.processed_blocks.write() {
            processed.insert(block_update);
        }
    }

    async fn update_contract_with_rbf(
        &self,
        confirmed_height: u64,
        block_hash: B256,
        nonce: u64,
        rbf_count: u32,
        last_tip: Option<u128>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let block_update = BitcoinBlockUpdate {
            confirmed_height,
            hash: block_hash,
        };

        // Deduplicate by BTC state
        if self.is_already_processed(&block_update) {
            info!("Contract update not necessary, BTC block update already processed: confirmed_height={confirmed_height}, hash=0x{}", hex::encode(block_hash));
            return Ok(());
        }

        // Check RBF attempt limit
        if rbf_count > MAX_RBF_ATTEMPTS {
            let err = format!("Max RBF attempts ({MAX_RBF_ATTEMPTS}) exceeded for nonce {nonce}");
            warn!("{}", err);
            if let Ok(mut status) = self.health_status.write() {
                status.last_error = Some(err.clone());
            }
            return Err(Box::new(std::io::Error::other(err)) as Box<dyn Error + Send + Sync>);
        }

        info!(
            "Updating contract with RBF #{rbf_count}: confirmed_height {confirmed_height}, hash 0x{}, nonce: {nonce}",
            hex::encode(block_hash)
        );

        let mut current_rbf_count = rbf_count;

        loop {
            // Calculate gas fees with Reth's fee history API using stored provider
            let (mut max_fee, tip) = Self::calculate_gas_fees_with(
                &self.provider,
                &self.gas,
                current_rbf_count,
                last_tip,
            )
            .await;

            // Enforce base_fee + tip at send time (base fee can move)
            let (_, base_fee_now) = Self::suggest_tip_and_basefee_with(&self.provider, &self.gas)
                .await
                .unwrap_or((self.gas.min_tip, DEFAULT_BASE_FEE));
            if max_fee <= base_fee_now.saturating_add(tip) {
                max_fee = base_fee_now.saturating_add(tip) + 1;
                info!(
                    "Adjusted max_fee to {} gwei for current base fee",
                    max_fee / 1_000_000_000
                );
            }

            let tx_builder = self
                .contract
                .setBitcoinBlockData(confirmed_height, block_hash)
                .nonce(nonce)
                .max_fee_per_gas(max_fee)
                .max_priority_fee_per_gas(tip);

            match tx_builder.send().await {
                Ok(tx) => {
                    let tx_hash = *tx.tx_hash();
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    // Store in-flight transaction
                    if let Ok(mut in_flight) = self.in_flight_tx.write() {
                        *in_flight = Some(InFlightTransaction {
                            tx_hash,
                            nonce,
                            block_update: block_update.clone(),
                            submitted_at: now,
                            rbf_count: current_rbf_count,
                            last_tip: tip,
                        });
                    }

                    // Update metrics with fee information
                    let observed_base =
                        Self::suggest_tip_and_basefee_with(&self.provider, &self.gas)
                            .await
                            .ok()
                            .map(|(_, base)| base);
                    if let Ok(mut status) = self.health_status.write() {
                        status.nonce_metrics.in_flight_count = 1;
                        status.nonce_metrics.last_submitted_height = Some(confirmed_height);
                        status.nonce_metrics.last_submitted_hash =
                            Some(format!("0x{}", hex::encode(block_hash)));
                        status.nonce_metrics.last_tx_hash =
                            Some(format!("0x{}", hex::encode(tx_hash)));
                        status.nonce_metrics.last_rbf_count = current_rbf_count;
                        status.nonce_metrics.last_max_fee_per_gas = Some(max_fee);
                        status.nonce_metrics.last_priority_fee_per_gas = Some(tip);
                        status.nonce_metrics.observed_base_fee = observed_base;
                        status.sequencer_rpc_healthy = true;
                    }

                    info!(
                        "RBF transaction submitted: 0x{} (nonce: {nonce}, RBF: {current_rbf_count})",
                        hex::encode(tx_hash)
                    );

                    return Ok(());
                }
                Err(e) => {
                    let err_str = e.to_string();

                    // Handle specific error types with improved matching
                    if Self::is_nonce_too_low_error(&err_str) {
                        warn!("Nonce too low - reconciling state and refreshing metrics");
                        // Refresh nonce metrics to get latest state
                        self.refresh_nonce_metrics().await;
                        // Clear in-flight and let normal flow check contract state
                        if let Ok(mut in_flight) = self.in_flight_tx.write() {
                            *in_flight = None;
                        }
                        return Ok(());
                    }

                    if Self::is_known_transaction_error(&err_str) {
                        info!("Transaction already known, keeping polling state");
                        // Keep polling - set in-flight placeholder to continue monitoring
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        if let Ok(mut slot) = self.in_flight_tx.write() {
                            *slot = Some(InFlightTransaction {
                                tx_hash: B256::ZERO, // unknown hash, but keep the nonce/block_update
                                nonce,
                                block_update: block_update.clone(),
                                submitted_at: now,
                                rbf_count: current_rbf_count,
                                last_tip: tip,
                            });
                        }
                        return Ok(());
                    }

                    if Self::is_underpriced_error(&err_str) {
                        current_rbf_count += 1;
                        if current_rbf_count > MAX_RBF_ATTEMPTS {
                            warn!("Max RBF attempts exceeded after replacement underpriced error");
                            break;
                        }
                        warn!("Replacement underpriced, retrying with higher fees (attempt {current_rbf_count})");
                        continue; // retry immediately with higher fees
                    }

                    warn!("Failed to submit RBF transaction: {e}");
                    if let Ok(mut status) = self.health_status.write() {
                        status.sequencer_rpc_healthy = false;
                        status.last_error = Some(format!("RBF transaction submit error: {e}"));
                    }
                    return Err(Box::new(e) as Box<dyn Error + Send + Sync>);
                }
            }
        }

        let err = format!("Max RBF attempts ({MAX_RBF_ATTEMPTS}) exceeded for confirmed_height {confirmed_height}, nonce {nonce}");
        warn!("{}", err);
        Err(Box::new(std::io::Error::other(err)) as Box<dyn Error + Send + Sync>)
    }

    async fn update_contract(
        &self,
        confirmed_height: u64,
        block_hash: B256,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let block_update = BitcoinBlockUpdate {
            confirmed_height,
            hash: block_hash,
        };

        // Deduplicate by BTC state
        if self.is_already_processed(&block_update) {
            info!("Contract update not necessary, BTC block update already processed: confirmed_height={confirmed_height}, hash=0x{}", hex::encode(block_hash));
            return Ok(());
        }

        // Use pending nonce and cap in-flight = 1
        if let Ok(in_flight) = self.in_flight_tx.read() {
            if in_flight.is_some() {
                debug!("Transaction already in flight, skipping new submission");
                return Ok(());
            }
        }

        let pending_nonce = self.get_pending_nonce().await?;

        info!(
            "Updating contract with confirmed height {confirmed_height} and hash 0x{} (nonce: {pending_nonce})",
            hex::encode(block_hash)
        );

        let mut backoff = ExponentialBackoff::default();
        let mut rbf_count = 0u32;

        loop {
            // Calculate gas fees with Reth's fee history API using stored provider
            let (mut max_fee, tip) =
                Self::calculate_gas_fees_with(&self.provider, &self.gas, rbf_count, None).await;

            // Enforce base_fee + tip at send time (base fee can move)
            let (_, base_fee_now) = Self::suggest_tip_and_basefee_with(&self.provider, &self.gas)
                .await
                .unwrap_or((self.gas.min_tip, DEFAULT_BASE_FEE));
            if max_fee <= base_fee_now.saturating_add(tip) {
                max_fee = base_fee_now.saturating_add(tip) + 1;
                info!(
                    "Adjusted max_fee to {} gwei for current base fee",
                    max_fee / 1_000_000_000
                );
            }

            let tx_builder = self
                .contract
                .setBitcoinBlockData(confirmed_height, block_hash)
                .nonce(pending_nonce)
                .max_fee_per_gas(max_fee)
                .max_priority_fee_per_gas(tip);

            match tx_builder.send().await {
                Ok(tx) => {
                    let tx_hash = *tx.tx_hash();
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    // Store in-flight transaction
                    if let Ok(mut in_flight) = self.in_flight_tx.write() {
                        *in_flight = Some(InFlightTransaction {
                            tx_hash,
                            nonce: pending_nonce,
                            block_update: block_update.clone(),
                            submitted_at: now,
                            rbf_count,
                            last_tip: tip,
                        });
                    }

                    // Update metrics with fee information
                    let observed_base =
                        Self::suggest_tip_and_basefee_with(&self.provider, &self.gas)
                            .await
                            .ok()
                            .map(|(_, base)| base);
                    if let Ok(mut status) = self.health_status.write() {
                        status.nonce_metrics.in_flight_count = 1;
                        status.nonce_metrics.last_submitted_height = Some(confirmed_height);
                        status.nonce_metrics.last_submitted_hash =
                            Some(format!("0x{}", hex::encode(block_hash)));
                        status.nonce_metrics.last_tx_hash =
                            Some(format!("0x{}", hex::encode(tx_hash)));
                        status.nonce_metrics.last_rbf_count = rbf_count;
                        status.nonce_metrics.last_max_fee_per_gas = Some(max_fee);
                        status.nonce_metrics.last_priority_fee_per_gas = Some(tip);
                        status.nonce_metrics.observed_base_fee = observed_base;
                        status.sequencer_rpc_healthy = true;
                    }

                    info!(
                        "Transaction submitted: 0x{} (nonce: {pending_nonce}, RBF: {rbf_count})",
                        hex::encode(tx_hash)
                    );

                    return Ok(());
                }
                Err(e) => {
                    let err_str = e.to_string();

                    // Handle specific error types with improved matching
                    if Self::is_nonce_too_low_error(&err_str) {
                        warn!("Nonce too low - reconciling state and refreshing metrics");
                        // Refresh nonce metrics to get latest state
                        self.refresh_nonce_metrics().await;
                        return Ok(());
                    }

                    if Self::is_known_transaction_error(&err_str) {
                        info!("Transaction already known, keeping polling state");
                        // Keep polling - set in-flight placeholder to continue monitoring
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        if let Ok(mut slot) = self.in_flight_tx.write() {
                            *slot = Some(InFlightTransaction {
                                tx_hash: B256::ZERO, // unknown hash, but keep the nonce/block_update
                                nonce: pending_nonce,
                                block_update: block_update.clone(),
                                submitted_at: now,
                                rbf_count,
                                last_tip: tip,
                            });
                        }
                        return Ok(());
                    }

                    if Self::is_underpriced_error(&err_str) {
                        rbf_count += 1;
                        if rbf_count > MAX_RBF_ATTEMPTS {
                            let err = format!("Max RBF attempts ({MAX_RBF_ATTEMPTS}) exceeded for confirmed_height {confirmed_height}, nonce {pending_nonce}");
                            warn!("{}", err);
                            return Err(Box::new(std::io::Error::other(err))
                                as Box<dyn Error + Send + Sync>);
                        }
                        warn!("Transaction underpriced, retrying with higher fees immediately (attempt {rbf_count})");
                        continue; // retry immediately with higher fees
                    }

                    warn!("Failed to submit transaction: {e}");
                    if let Ok(mut status) = self.health_status.write() {
                        status.sequencer_rpc_healthy = false;
                        status.last_error = Some(format!("Transaction submit error: {e}"));
                    }

                    // Backoff & jitter on RPC error or timeout
                    if let Some(delay) = backoff.next_backoff() {
                        rbf_count += 1;
                        if rbf_count > MAX_RBF_ATTEMPTS {
                            let err = format!("Max RBF attempts ({MAX_RBF_ATTEMPTS}) exceeded during backoff for confirmed_height {confirmed_height}, nonce {pending_nonce}");
                            warn!("{}", err);
                            return Err(Box::new(std::io::Error::other(err))
                                as Box<dyn Error + Send + Sync>);
                        }
                        info!(
                            "Retrying transaction with RBF in {:?} (attempt {})",
                            delay, rbf_count
                        );
                        time::sleep(delay).await;
                    } else {
                        return Err(Box::new(e) as Box<dyn Error + Send + Sync>);
                    }
                }
            }
        }
    }

    async fn run(&self, update_interval: Duration) {
        let mut interval = time::interval(update_interval);

        info!("Starting Sova Bitcoin Sync Service...");
        info!("Update interval: {} seconds", update_interval.as_secs());
        info!("Confirmation blocks: {}", self.confirmation_blocks);

        loop {
            // poll for receipts or RBF
            let tx_to_check = if let Ok(in_flight) = self.in_flight_tx.read() {
                in_flight.clone()
            } else {
                None
            };

            if let Some(tx) = tx_to_check {
                // Check if the in-flight transaction has been mined
                match self.check_transaction_receipt(tx.tx_hash).await {
                    Ok(true) => {
                        info!("Transaction 0x{} confirmed!", hex::encode(tx.tx_hash));

                        // Mark block as processed and clear in-flight state
                        self.mark_as_processed(tx.block_update.clone());

                        // Update metrics and status
                        if let Ok(mut status) = self.health_status.write() {
                            status.total_updates += 1;
                            status.last_contract_update = Some(
                                SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                            );
                            status.nonce_metrics.in_flight_count = 0;
                            status.nonce_metrics.nonce_latest = tx.nonce + 1;
                        }

                        // Clear in-flight transaction
                        if let Ok(mut in_flight_mut) = self.in_flight_tx.write() {
                            *in_flight_mut = None;
                        }
                    }
                    Ok(false) => {
                        // Transaction still pending
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();

                        // Check if we should RBF (Replace-By-Fee) after waiting too long
                        if now - tx.submitted_at > self.rbf_timeout_seconds {
                            warn!(
                                "Transaction 0x{} taking too long, attempting RBF",
                                hex::encode(tx.tx_hash)
                            );

                            // Clear in-flight to allow re-submission with higher gas
                            if let Ok(mut in_flight_mut) = self.in_flight_tx.write() {
                                *in_flight_mut = None;
                            }

                            // Try to re-submit with same nonce but higher gas (RBF)
                            if let Err(e) = self
                                .update_contract_with_rbf(
                                    tx.block_update.confirmed_height,
                                    tx.block_update.hash,
                                    tx.nonce,
                                    tx.rbf_count + 1,
                                    Some(tx.last_tip),
                                )
                                .await
                            {
                                warn!("RBF failed: {e}");
                            }
                        } else {
                            info!("Transaction 0x{} still pending...", hex::encode(tx.tx_hash));
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to check receipt for 0x{}: {e}",
                            hex::encode(tx.tx_hash)
                        );
                    }
                }

                // Sleep shorter when monitoring in-flight transaction
                time::sleep(Duration::from_secs(5)).await;
                continue;
            }

            // Normal interval tick when no in-flight transactions
            interval.tick().await;

            match self.get_bitcoin_block_data().await {
                Ok((current_height, confirmed_height, block_hash)) => {
                    debug!(
                        "Retrieved Bitcoin block data: current_height={current_height}, confirmed_height={confirmed_height}, hash=0x{}",
                        hex::encode(block_hash)
                    );

                    if let Err(e) = self.update_contract(confirmed_height, block_hash).await {
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
                        "min_tip_gwei": (gas_cfg.min_tip / 1_000_000_000).to_string(),
                        "max_fee_cap_gwei": (gas_cfg.max_fee_cap / 1_000_000_000).to_string()
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
        _ => (404, json!({"error": "Not found"}).to_string()),
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    health_status: Arc<RwLock<HealthStatus>>,
    gas_cfg: &GasCfg,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut buffer = [0; 1024];
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
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    // Validate CLI flags
    if args.min_tip_gwei == 0 {
        anyhow::bail!("--min-tip-gwei must be > 0");
    }
    if args.min_tip_gwei > args.max_fee_cap_gwei {
        anyhow::bail!(
            "--min-tip-gwei ({}) cannot exceed --max-fee-cap-gwei ({})",
            args.min_tip_gwei,
            args.max_fee_cap_gwei
        );
    }

    // Runtime-configured gas floors/caps from CLI args
    let gas_cfg = GasCfg {
        min_tip: args.min_tip_gwei.saturating_mul(1_000_000_000), // convert gwei to wei
        max_fee_cap: args.max_fee_cap_gwei.saturating_mul(1_000_000_000), // convert gwei to wei
    };

    info!(
        "Gas policy: MIN_TIP={} gwei, MAX_FEE_CAP={} gwei",
        gas_cfg.min_tip / 1_000_000_000,
        gas_cfg.max_fee_cap / 1_000_000_000
    );

    // Bitcoin RPC selection (unchanged)
    let bitcoin_rpc: Arc<dyn BitcoinRpcClient> = match args
        .parse_connection_type()
        .map_err(std::io::Error::other)?
        .as_str()
    {
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

    // Wallet & provider (exactly once)
    let signer: PrivateKeySigner = args.admin_private_key.trim_start_matches("0x").parse()?;
    let wallet = EthereumWallet::from(signer);
    let url = args.sequencer_rpc_url.parse()?;

    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(wallet.clone())
        .connect_http(url);

    // Type of `provider` is concrete and satisfies the bounds.
    let service = SyncService::new_with(&args, bitcoin_rpc, provider, gas_cfg.clone())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create sync service: {}", e))?;

    // rest unchanged...
    let update_interval = Duration::from_secs(args.update_interval);
    let health_status = service.get_health_status();
    let health_port = args.health_port;

    info!(
        "Starting Sova Bitcoin Sync Service with health checks on port {}",
        health_port
    );

    tokio::select! {
        _ = service.run(update_interval) => warn!("Sync service exited unexpectedly"),
        result = start_health_server(health_status, gas_cfg.clone(), health_port) => {
            if let Err(e) = result { warn!("Health server failed: {e}"); }
        }
    }

    Ok(())
}
