# Sova Bitcoin Sync Service

A service that synchronizes Bitcoin blockchain data to the Sova L2 `SovaL1Block` smart contract. It fetches the latest Bitcoin block information and updates the `SovaL1Block` contract with block height and hash data.

## Features

- **Dual Bitcoin RPC modes**
  - `bitcoincore` — native JSON-RPC via `bitcoincore_rpc`
  - `external` — generic JSON-RPC over `reqwest` with clear error surfacing
- **Contract synchronization**
  - Automatically updates the `SovaL1Block` contract with confirmed Bitcoin block data
- **Resilient gas & fee policy**
  - EIP-1559 estimation from `eth_feeHistory(… pending, p50)`
  - Fallback to `maxPriorityFeePerGas + pending.baseFee`
  - **Automatic RBF** on stuck or underpriced txs, with configurable timeout and max attempts
- **Nonce & duplication safety**
  - Caps to a single in-flight transaction
  - Deduplicates by BTC state `(confirmed_height, block_hash)`
  - Self-heals on “nonce too low” / “already known”
- **Health monitoring**
  - Built-in endpoints: `/live`, `/ready`, `/health`
  - Exposes status, last errors, gas/nonce metrics, observed base fee, and uptime
- **Fault tolerance**
  - Exponential backoff with jitter on transient RPC errors
- **Configurable confirmations**
  - Uses N-blocks back (default: 6) for safe BTC finality

## Quick Start

### Prerequisites

- Rust (latest stable version)
- Access to a Bitcoin RPC node
- Access to a Sova sequencer RPC endpoint
- Admin private key (must be provided via `ADMIN_PRIVATE_KEY` env var)

### Build

```bash
cargo build --release
```

## Run

```bash
# 1) Provide the admin key (no 0x prefix)
export ADMIN_PRIVATE_KEY="aaaaaaaa...bbbb"

# 2) Run with defaults (regtest-friendly)
cargo run

# 3) Or customize:
cargo run -- \
  --btc-rpc-url "http://your-bitcoin-node:8332" \
  --btc-rpc-user "rpcuser" \
  --btc-rpc-password "rpcpass" \
  --rpc-connection-type external \
  --sequencer-rpc-url "http://your-sova-reth:8545" \
  --contract-address "0x2100000000000000000000000000000000000015" \
  --update-interval 30 \
  --confirmation-blocks 6 \
  --health-port 8080 \
  --rbf-timeout-seconds 60
```

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--btc-rpc-url` | `http://bitcoin-regtest:18443` | Bitcoin RPC endpoint |
| `--btc-rpc-user` | `user` | Bitcoin RPC username |
| `--btc-rpc-password` | `password` | Bitcoin RPC password |
| `--rpc-connection-type` | `bitcoincore` | RPC connection type (`bitcoincore` or `external`) |
| `--sequencer-rpc-url` | `http://sova-reth:8545` | Sova sequencer RPC endpoint |
| `--admin-private-key` | (env: `ADMIN_PRIVATE_KEY`) | Private key for contract updates |
| `--contract-address` | `0x2100000000000000000000000000000000000015` | SovaL1Block contract address |
| `--update-interval` | `10` | Update interval in seconds |
| `--confirmation-blocks` | `6` | Number of confirmation blocks |
| `--health-port` | `8080` | Health check server port |
| `--rbf-timeout-seconds` | `60` | Pending window before attempting RBF |

## In-code gas constants
- MIN_TIP = 1 gwei
- MAX_FEE_CAP = 200 gwei
- DEFAULT_BASE_FEE = 1 gwei (fallback)
- BUMP_MULTIPLIER = 15% per RBF attempt
- MAX_RBF_ATTEMPTS = 8

## How it chooses fees (EIP-1559) & handles RBF

### Estimate fees
- Use `eth_feeHistory(5, pending, [50])`
  - **Base fee**: last `baseFeePerGas` (pending)
  - **Tip**: 50th percentile reward
- **Fallback**: `maxPriorityFeePerGas` + pending block base fee

### Compute `maxFeePerGas`
- Formula: `(base + tip) * (1 + attempts * BUMP_MULTIPLIER)`
- Guards:
  - Must be ≥ `base + tip + 1`
  - Cap both tip and max fee at `MAX_FEE_CAP`

### RBF (Replace-By-Fee)
- If a tx is still pending for `--rbf-timeout-seconds`, re-submit with same nonce and bumped fees
- Stop after `MAX_RBF_ATTEMPTS`

## Nonce & duplication safety

- Only **one** in-flight tx at a time  
- Deduplicates by BTC state `(confirmed_height, block_hash)` so the same BTC block isn’t posted twice  
- **“Nonce too low”**: refreshes metrics and reconciles with chain state  
- **“Already known”**: keeps polling for receipt  

## Health Endpoints

Served on `0.0.0.0:<health-port>`:

- **GET `/live`** — liveness (process running)  
- **GET `/ready`** — readiness (Bitcoin RPC **and** Sova RPC healthy)  
- **GET `/health`** — detailed status & metrics (including nonces and gas telemetry)  

### Example `/health` response

```json
{
  "status": "healthy",
  "started_at": 1731540000,
  "uptime_seconds": 742,
  "bitcoin_rpc_healthy": true,
  "sequencer_rpc_healthy": true,
  "last_bitcoin_check": 1731540701,
  "last_contract_update": 1731540695,
  "total_updates": 42,
  "last_error": null,
  "nonce_metrics": {
    "nonce_latest": 123,
    "nonce_pending": 123,
    "in_flight_count": 0,
    "last_submitted": {
      "height": 878000,
      "hash": "0xabc…def"
    },
    "last_mined": {
      "height": 877994,
      "hash": "0x123…789"
    },
    "last_tx_hash": "0xfeed…beef",
    "last_rbf_count": 2,
    "last_max_fee_per_gas": "30000000000",
    "last_priority_fee_per_gas": "2000000000",
    "observed_base_fee": "28000000000",
    "last_max_fee_per_gas_gwei": "30",
    "last_priority_fee_per_gas_gwei": "2",
    "observed_base_fee_gwei": "28"
  }
}
```

## License

This project is licensed under either of:

- [MIT License](LICENSE-MIT)  
- [Apache License, Version 2.0](LICENSE-APACHE)  

at your option.