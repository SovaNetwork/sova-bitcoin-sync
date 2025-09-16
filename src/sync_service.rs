use crate::bitcoin::{BitcoinBlockUpdate, BitcoinRpcClient};
use alloy::{
    hex,
    primitives::{Address, B256, U256},
    providers::{Provider, WalletProvider},
    rpc::types::BlockNumberOrTag,
    sol,
};
use anyhow::Result as AnyResult;
use backoff::{backoff::Backoff, ExponentialBackoff};
use std::{
    collections::HashSet,
    error::Error,
    str::FromStr,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time;
use tracing::{debug, info, warn};

// Gas management constants
const MAX_RBF_ATTEMPTS: u32 = 8;
const DEFAULT_BASE_FEE: u128 = 10; // 10 wei fallback
const BUMP_MULTIPLIER: u32 = 15; // 15% increase per RBF

// Processed blocks pruning
const KEEP_WINDOW: u64 = 10_000; // Keep last 10k blocks to prevent unbounded growth

// Runtime gas configuration
#[derive(Debug, Clone)]
pub struct GasCfg {
    pub min_tip: u128,     // minimum tip in wei
    pub max_fee_cap: u128, // maximum fee cap in wei
}

// SovaL1Block contract interface
sol! {
    #[sol(rpc)]
    contract SovaL1Block {
        function setBitcoinBlockData(uint64 blockHeight, bytes32 blockHash) external;
    }
}

#[derive(Debug, Clone, Default)]
pub struct NonceMetrics {
    pub nonce_latest: u64,
    pub nonce_pending: u64,
    pub in_flight_count: u32,
    pub in_flight_nonce: Option<u64>,
    pub waiting_rbf: bool,
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
pub struct HealthStatus {
    pub started_at: u64,
    pub last_bitcoin_check: Option<u64>,
    pub last_contract_update: Option<u64>,
    pub bitcoin_rpc_healthy: bool,
    pub sequencer_rpc_healthy: bool,
    pub total_updates: u64,
    pub last_error: Option<String>,
    pub nonce_metrics: NonceMetrics,
    pub wallet_balance_wei: Option<u128>,
    pub wallet_balance_eth: Option<f64>,
    pub low_balance_warning: bool,
    pub last_balance_check: Option<u64>,
}

impl HealthStatus {
    pub fn new() -> Self {
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
            wallet_balance_wei: None,
            wallet_balance_eth: None,
            low_balance_warning: false,
            last_balance_check: None,
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.bitcoin_rpc_healthy && self.sequencer_rpc_healthy && !self.low_balance_warning
    }
}

#[derive(Debug, Clone)]
pub struct InFlightTransaction {
    pub tx_hash: B256,
    pub nonce: u64,
    pub block_update: BitcoinBlockUpdate,
    pub submitted_at: u64,
    pub rbf_count: u32,
    pub last_tip: u128,
}

pub struct SyncService<P>
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
    pub async fn new(
        bitcoin_rpc: Arc<dyn BitcoinRpcClient>,
        provider: P,
        contract_address: &str,
        confirmation_blocks: u64,
        rbf_timeout_seconds: u64,
        gas_cfg: GasCfg,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Parse contract address once
        let contract_address: Address = contract_address.parse()?;
        let contract = SovaL1Block::new(contract_address, provider.clone());

        Ok(Self {
            bitcoin_rpc,
            confirmation_blocks,
            rbf_timeout_seconds,
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

                    let gwei = |v: u128| format!("{:.9}", (v as f64) / 1_000_000_000f64);
                    info!(
                        "Tip sources: p50={} gwei, maxPriority={} gwei, floor={} gwei -> chosen={} gwei",
                        gwei(p50_tip),
                        gwei(mpg),
                        gwei(gas_cfg.min_tip),
                        gwei(tip)
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

        let gwei = |v: u128| format!("{:.9}", (v as f64) / 1_000_000_000f64);
        info!(
            "Tip sources: p50=0 gwei, maxPriority={} gwei, floor={} gwei -> chosen={} gwei",
            gwei(mpg),
            gwei(gas_cfg.min_tip),
            gwei(tip_fallback)
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
        let r = rbf_count.min(MAX_RBF_ATTEMPTS);
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

        // Early sanity clamp (belt & suspenders)
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
            format!("{v_f:.9}")
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

    async fn find_available_nonce(&self) -> AnyResult<u64> {
        let from = self.provider.default_signer_address();
        let mut nonce = self.provider.get_transaction_count(from).latest().await?;

        loop {
            if !self.tx_known_for_nonce(from, nonce).await.unwrap_or(true) {
                return Ok(nonce);
            }
            nonce += 1;
        }
    }

    async fn tx_known_for_nonce(&self, from: Address, nonce: u64) -> AnyResult<bool> {
        // Prefer {:#x} for 0x-lowerhex
        let params = serde_json::json!([format!("{:#x}", from), format!("0x{:x}", nonce)]);

        // Try client() method first as it's most commonly available
        let v: serde_json::Value = self
            .provider
            .client()
            .request("eth_getTransactionBySenderAndNonce", params)
            .await?;

        Ok(!v.is_null())
    }

    async fn tx_hash_by_sender_and_nonce<T: Provider>(
        provider: &T,
        from: Address,
        nonce: u64,
    ) -> AnyResult<Option<B256>> {
        let params = serde_json::json!([format!("{:#x}", from), format!("0x{:x}", nonce)]);
        let v: serde_json::Value = provider
            .client()
            .request("eth_getTransactionBySenderAndNonce", params)
            .await?;
        let h = v
            .get("hash")
            .and_then(|x| x.as_str())
            .and_then(|s| B256::from_str(s).ok());
        Ok(h)
    }

    async fn is_transaction_confirmed(&self, from: Address, nonce: u64) -> AnyResult<bool> {
        let params = serde_json::json!([format!("{:#x}", from), format!("0x{:x}", nonce)]);
        let v: serde_json::Value = self
            .provider
            .client()
            .request("eth_getTransactionBySenderAndNonce", params)
            .await?;

        if v.is_null() {
            return Ok(false);
        }

        if let Some(block_number) = v.get("blockNumber") {
            Ok(!block_number.is_null())
        } else {
            Ok(false)
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

    pub async fn refresh_balance_metrics(&self) {
        let from = self.provider.default_signer_address();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Get wallet balance
        if let Ok(balance) = self.provider.get_balance(from).await {
            let balance_wei = balance.to::<u128>();
            let balance_eth = (balance_wei as f64) / 1_000_000_000_000_000_000.0; // Convert wei to ETH

            // Define minimum balance threshold (e.g., 0.01 ETH)
            const MIN_BALANCE_ETH: f64 = 0.01;
            let is_low_balance = balance_eth < MIN_BALANCE_ETH;

            if let Ok(mut status) = self.health_status.write() {
                status.wallet_balance_wei = Some(balance_wei);
                status.wallet_balance_eth = Some(balance_eth);
                status.low_balance_warning = is_low_balance;
                status.last_balance_check = Some(now);
            }

            if is_low_balance {
                warn!(
                    "Wallet balance is low: {} ETH (< {} ETH threshold). Address: {:#x}",
                    balance_eth, MIN_BALANCE_ETH, from
                );
            }
        } else if let Ok(mut status) = self.health_status.write() {
            // Failed to fetch balance
            status.last_balance_check = Some(now);
            warn!("Failed to fetch wallet balance for address: {:#x}", from);
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

    fn prune_processed(&self, min_height: u64) {
        if let Ok(mut set) = self.processed_blocks.write() {
            set.retain(|u| u.confirmed_height >= min_height.saturating_sub(KEEP_WINDOW));
        }
    }

    async fn update_contract_with_rbf(
        &self,
        current_height: u64,
        confirmed_height: u64,
        block_hash: B256,
        nonce: u64,
        rbf_count: u32,
        last_tip: Option<u128>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let block_update = BitcoinBlockUpdate {
            current_height,
            confirmed_height,
            hash: block_hash,
        };

        // Deduplicate by BTC state
        if self.is_already_processed(&block_update) {
            info!("Contract update not necessary, BTC block update already processed: confirmed_height={confirmed_height}, hash=0x{}", hex::encode(block_hash));
            return Ok(());
        }

        // Validate nonce before sending - should match the in-flight transaction nonce
        let is_valid_nonce = if let Ok(in_flight) = self.in_flight_tx.read() {
            if let Some(ref tx) = *in_flight {
                nonce == tx.nonce
            } else {
                false
            }
        } else {
            false
        };

        if !is_valid_nonce {
            let from = self.provider.default_signer_address();
            warn!(%from, nonce, "Invalid nonce for RBF; refusing to send");
            return Ok(());
        }

        // Check RBF attempt limit
        if rbf_count > MAX_RBF_ATTEMPTS {
            let err = format!("Max RBF attempts ({MAX_RBF_ATTEMPTS}) exceeded for nonce {nonce}");
            warn!("{err}");
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
                let gwei = |v: u128| format!("{:.9}", (v as f64) / 1_000_000_000f64);
                info!(
                    "Adjusted max_fee to {} gwei for current base fee",
                    gwei(max_fee)
                );
            }

            let tx_builder = self
                .contract
                .setBitcoinBlockData(current_height, block_hash)
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
                        status.nonce_metrics.in_flight_nonce = Some(nonce);
                        status.nonce_metrics.waiting_rbf = false;
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

                        let from = self.provider.default_signer_address();
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        let resolved =
                            Self::tx_hash_by_sender_and_nonce(&self.provider, from, nonce)
                                .await
                                .ok()
                                .flatten();

                        if let Ok(mut slot) = self.in_flight_tx.write() {
                            *slot = Some(InFlightTransaction {
                                tx_hash: resolved.unwrap_or(B256::ZERO), // keep placeholder if still unknown
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
        current_height: u64,
        confirmed_height: u64,
        block_hash: B256,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let block_update = BitcoinBlockUpdate {
            current_height,
            confirmed_height,
            hash: block_hash,
        };

        // Deduplicate by BTC state
        if self.is_already_processed(&block_update) {
            info!("Contract update not necessary, BTC block update already processed: confirmed_height={confirmed_height}, hash=0x{}", hex::encode(block_hash));
            return Ok(());
        }

        // Use proper nonce selection and confirmation gating
        if let Ok(in_flight) = self.in_flight_tx.read() {
            if in_flight.is_some() {
                debug!("Transaction already in flight, skipping new submission");
                return Ok(());
            }
        }

        let nonce_to_use = self.find_available_nonce().await?;

        info!(
            "Updating contract with confirmed height {confirmed_height} and hash 0x{} (nonce: {nonce_to_use})",
            hex::encode(block_hash)
        );

        let mut backoff = ExponentialBackoff {
            max_interval: Duration::from_secs(15),
            max_elapsed_time: Some(Duration::from_secs(90)),
            ..ExponentialBackoff::default()
        };
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
                let gwei = |v: u128| format!("{:.9}", (v as f64) / 1_000_000_000f64);
                info!(
                    "Adjusted max_fee to {} gwei for current base fee",
                    gwei(max_fee)
                );
            }

            let tx_builder = self
                .contract
                .setBitcoinBlockData(current_height, block_hash)
                .nonce(nonce_to_use)
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
                            nonce: nonce_to_use,
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
                        status.nonce_metrics.in_flight_nonce = Some(nonce_to_use);
                        status.nonce_metrics.waiting_rbf = false;
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
                        "Transaction submitted: 0x{} (nonce: {nonce_to_use}, RBF: {rbf_count})",
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

                        let from = self.provider.default_signer_address();
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        let resolved =
                            Self::tx_hash_by_sender_and_nonce(&self.provider, from, nonce_to_use)
                                .await
                                .ok()
                                .flatten();

                        if let Ok(mut slot) = self.in_flight_tx.write() {
                            *slot = Some(InFlightTransaction {
                                tx_hash: resolved.unwrap_or(B256::ZERO), // keep placeholder if still unknown
                                nonce: nonce_to_use,
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
                            let err = format!("Max RBF attempts ({MAX_RBF_ATTEMPTS}) exceeded for confirmed_height {confirmed_height}, nonce {nonce_to_use}");
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
                            let err = format!("Max RBF attempts ({MAX_RBF_ATTEMPTS}) exceeded during backoff for confirmed_height {confirmed_height}, nonce {nonce_to_use}");
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

    pub async fn run(&self, update_interval: Duration) {
        let mut interval = time::interval(update_interval);

        info!("Starting Sova Bitcoin Sync Service...");
        info!("Update interval: {} seconds", update_interval.as_secs());
        info!("Confirmation blocks: {}", self.confirmation_blocks);

        loop {
            // poll for receipts or RBF
            let tx_to_check = if let Ok(in_flight) = self.in_flight_tx.read() {
                (*in_flight).clone()
            } else {
                None
            };

            if let Some(tx) = tx_to_check {
                // Try to resolve zero hash before proceeding
                if tx.tx_hash == B256::ZERO {
                    if let Ok(Some(h)) = Self::tx_hash_by_sender_and_nonce(
                        &self.provider,
                        self.provider.default_signer_address(),
                        tx.nonce,
                    )
                    .await
                    {
                        if let Ok(mut g) = self.in_flight_tx.write() {
                            if let Some(mut cur) = g.take() {
                                cur.tx_hash = h;
                                *g = Some(cur);
                            }
                        }
                    } else {
                        debug!("Still no hash for nonce {}; retrying", tx.nonce);
                        time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                }

                // Check if the in-flight transaction has been confirmed using proper confirmation gating
                let from = self.provider.default_signer_address();
                match self.is_transaction_confirmed(from, tx.nonce).await {
                    Ok(true) => {
                        info!(
                            "Transaction for nonce {} confirmed with blockNumber!",
                            tx.nonce
                        );

                        // Mark block as processed and clear in-flight state
                        self.mark_as_processed(tx.block_update.clone());
                        // Prune old entries to prevent unbounded growth
                        self.prune_processed(tx.block_update.confirmed_height);

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
                            status.nonce_metrics.in_flight_nonce = None;
                            status.nonce_metrics.waiting_rbf = false;
                            status.nonce_metrics.nonce_latest = tx.nonce + 1;
                        }

                        // Clear in-flight transaction
                        if let Ok(mut in_flight_mut) = self.in_flight_tx.write() {
                            *in_flight_mut = None;
                        }

                        // Refresh nonce metrics after clearing in-flight
                        self.refresh_nonce_metrics().await;
                    }
                    Ok(false) => {
                        // Transaction still pending
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();

                        // Update waiting_rbf status based on how long we've been waiting
                        let waiting_rbf = now - tx.submitted_at > self.rbf_timeout_seconds;
                        if let Ok(mut status) = self.health_status.write() {
                            status.nonce_metrics.waiting_rbf = waiting_rbf;
                        }

                        // Check if we should RBF (Replace-By-Fee) after waiting too long
                        if waiting_rbf {
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
                                    tx.block_update.current_height,
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
                        warn!("Failed to check confirmation for nonce {}: {e}", tx.nonce);
                    }
                }

                // Sleep shorter when monitoring in-flight transaction
                time::sleep(Duration::from_secs(5)).await;
                continue;
            }

            // Normal interval tick when no in-flight transactions
            interval.tick().await;

            // check balance metrics
            self.refresh_balance_metrics().await;

            match self.get_bitcoin_block_data().await {
                Ok((current_height, confirmed_height, block_hash)) => {
                    debug!(
                        "Retrieved Bitcoin block data: current_height={current_height}, confirmed_height={confirmed_height}, hash=0x{}",
                        hex::encode(block_hash)
                    );

                    // Periodically prune old processed blocks to prevent unbounded growth
                    self.prune_processed(confirmed_height);

                    if let Err(e) = self
                        .update_contract(current_height, confirmed_height, block_hash)
                        .await
                    {
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

    pub fn get_health_status(&self) -> Arc<RwLock<HealthStatus>> {
        self.health_status.clone()
    }
}
