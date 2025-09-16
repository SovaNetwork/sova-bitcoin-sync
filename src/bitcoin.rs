use alloy::primitives::B256;
use async_trait::async_trait;
use bitcoincore_rpc::{Auth, Client as CoreClient, RpcApi};
use serde_json::{json, Value};
use std::{
    error::Error,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

#[async_trait]
pub trait BitcoinRpcClient: Send + Sync {
    async fn get_block_count(&self) -> Result<u64, Box<dyn Error + Send + Sync>>;
    async fn get_block_hash(&self, height: u64) -> Result<String, Box<dyn Error + Send + Sync>>;
}

pub struct BitcoinCoreRpcClient {
    client: CoreClient,
}

impl BitcoinCoreRpcClient {
    pub fn new(url: &str, user: &str, password: &str) -> Result<Self, bitcoincore_rpc::Error> {
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

pub struct ExternalRpcClient {
    client: reqwest::Client,
    url: String,
    user: Option<String>,
    password: Option<String>,
    request_id: AtomicU64,
}

impl ExternalRpcClient {
    pub fn new(url: String, user: String, password: String) -> Self {
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
pub struct BitcoinBlockUpdate {
    pub current_height: u64,   // The current Bitcoin block height
    pub confirmed_height: u64, // The confirmed block height (current - confirmation_blocks)
    pub hash: B256,            // Hash at the confirmed height
}

pub fn create_bitcoin_rpc_client(
    connection_type: &str,
    url: &str,
    user: &str,
    password: &str,
) -> anyhow::Result<Arc<dyn BitcoinRpcClient>> {
    let client: Arc<dyn BitcoinRpcClient> = match connection_type {
        "bitcoincore" => Arc::new(BitcoinCoreRpcClient::new(url, user, password)?),
        "external" => Arc::new(ExternalRpcClient::new(
            url.to_string(),
            user.to_string(),
            password.to_string(),
        )),
        _ => {
            anyhow::bail!("Unsupported connection type: {connection_type}");
        }
    };
    Ok(client)
}
