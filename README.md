# Sova Bitcoin Sync Service

A service that synchronizes Bitcoin blockchain data to the Sova L1 smart contract. It fetches the latest Bitcoin block information and updates the `SovaL1Block` contract with block height and hash data.

## Features

- **Bitcoin RPC Integration**: Connects to Bitcoin node via RPC to fetch block data
- **Smart Contract Updates**: Automatically updates the Sova L1 contract with Bitcoin block information
- **Health Monitoring**: Built-in health check endpoints for monitoring service status
- **Configurable Confirmations**: Uses confirmed blocks (default: 6 blocks back) for reliability
- **Automatic Syncing**: Runs continuously with configurable update intervals

## Quick Start

### Prerequisites

- Rust (latest stable version)
- Access to a Bitcoin RPC node
- Access to a Sova sequencer RPC endpoint
- Admin private key for contract interactions

### Build

```bash
cargo build --release
```

## Run

```bash
# Set your admin private key
export ADMIN_PRIVATE_KEY="your_private_key_without_0x_prefix"

# Run with default settings
cargo run

# Or with custom parameters
cargo run -- \
  --btc-rpc-url "http://your-bitcoin-node:8332" \
  --btc-rpc-user "your_user" \
  --btc-rpc-password "your_password" \
  --sequencer-rpc-url "http://your-sova-node:8545" \
  --contract-address "0x2100000000000000000000000000000000000015" \
  --update-interval 30
```

  ## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--btc-rpc-url` | `http://bitcoin-regtest:18443` | Bitcoin RPC endpoint |
| `--btc-rpc-user` | `user` | Bitcoin RPC username |
| `--btc-rpc-password` | `password` | Bitcoin RPC password |
| `--sequencer-rpc-url` | `http://sova-reth:8545` | Sova sequencer RPC endpoint |
| `--admin-private-key` | (env: `ADMIN_PRIVATE_KEY`) | Private key for contract updates |
| `--contract-address` | `0x2100000000000000000000000000000000000015` | SovaL1Block contract address |
| `--update-interval` | `10` | Update interval in seconds |
| `--confirmation-blocks` | `6` | Number of confirmation blocks |
| `--health-port` | `8080` | Health check server port |

## Health Check Endpoints

The service exposes health check endpoints on the configured port (default: 8080):

- **`GET /health`** - Overall health status with detailed metrics
- **`GET /ready`** - Readiness check (both Bitcoin and Sova RPCs healthy)
- **`GET /live`** - Liveness check (service is running)

### Example Health Response

```json
{
  "status": "healthy",
  "started_at": 1642694400,
  "uptime_seconds": 3600,
  "bitcoin_rpc_healthy": true,
  "sequencer_rpc_healthy": true,
  "last_bitcoin_check": 1642698000,
  "last_contract_update": 1642698000,
  "total_updates": 360,
  "last_error": null
}
```