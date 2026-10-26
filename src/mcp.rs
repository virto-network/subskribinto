// Copyright (c) Virto Network
// SPDX-License-Identifier: MIT

//! A stdio MCP server that lets AI assistants use stored accounts without ever seeing a key.
//!
//! Every signature goes through [`guard::Request`]: the account's policy must allow the call, and
//! a human must approve it, through the MCP client (elicitation) and, on macOS, through Touch ID
//! or the account password, which the model can't provide.

use std::{collections::HashMap, sync::Arc};

use rmcp::{
    Json, Peer, RoleServer, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerConfig},
    service::ElicitationError,
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{
    audit::AuditLog,
    call::DecodedCall,
    guard::Request,
    policy::{Approval, ProxyConfig, Rule},
    presence,
    store::Accounts,
    tx::{self, Api, Outcome},
};

const INSTRUCTIONS: &str = "\
Signs and submits Kreivo (Substrate) transactions with accounts the user stored in their system \
keystore. You never see keys. Each account has a policy listing the calls it may sign and a pinned \
endpoint; it may also sign as a proxy of another account.

Workflow: `list_accounts` to see accounts and what they may do; `encode_call` (from pallet, call \
and arguments) or `decode_call` (from hex call data) to build and check a call; then \
`sign_and_submit`. `encode_call` and `decode_call` report the `approval` a call needs:
- `unattended`: every call in it matches rules the user marked unattended, so it is signed right \
away, without asking them. Still tell them what you submitted and why.
- `required`: the user approves it themselves (a prompt in this client and, on macOS, Touch ID); \
you can't approve on their behalf, so tell them what you are about to submit and why. If they are \
away from their computer, it will wait for them.
Calls the policy doesn't allow are rejected before the user is asked: suggest a policy change for \
them to make, don't try to work around it. Every signature is recorded in a local audit log.";

pub async fn serve(accounts: Accounts) -> anyhow::Result<()> {
    let server = Server::new(accounts, AuditLog::default_location()?);
    let running = server.serve(rmcp::transport::stdio()).await?;
    running.waiting().await?;
    Ok(())
}

#[derive(Clone)]
pub struct Server {
    accounts: Arc<Accounts>,
    chains: Arc<Mutex<HashMap<String, Api>>>,
    /// One signature at a time: keeps nonces in order and prompts from piling up.
    signing: Arc<Mutex<()>>,
    audit: Arc<AuditLog>,
    tool_router: ToolRouter<Self>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CallArgs {
    /// Name of a stored account (see `list_accounts`).
    pub account: String,
    /// SCALE-encoded call data, hex (`0x…`).
    pub call: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EncodeArgs {
    /// Name of a stored account (see `list_accounts`); its chain's metadata is used.
    pub account: String,
    /// Pallet name, e.g. `Balances`.
    pub pallet: String,
    /// Call name, e.g. `transfer_keep_alive`.
    pub call: String,
    /// The call's arguments in scale-value syntax: a named composite such as
    /// `{ dest: Id(5FHneW46…), value: 1_000_000_000_000 }`. SS58 addresses and `0x…` hex are
    /// accepted; enum variants are written `Variant(…)` or `Variant { … }`, and variants without
    /// data as `Variant()`. Omit for no arguments.
    pub args: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AccountInfo {
    pub name: String,
    pub address: String,
    pub scheme: String,
    pub endpoint: String,
    pub proxy: Option<ProxyConfig>,
    /// The calls this account may sign.
    pub allow: Vec<Rule>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AccountList {
    pub accounts: Vec<AccountInfo>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CallReport {
    /// The call data, hex. Pass it to `sign_and_submit`.
    pub call_data: String,
    /// The decoded call, with accounts in SS58.
    pub description: String,
    /// The call and every call nested in it, as `Pallet.call`.
    pub calls: Vec<String>,
    /// Whether the account's policy allows it.
    pub allowed: bool,
    /// When allowed: `unattended` (signed without asking the user) or `required` (the user
    /// approves it first).
    pub approval: Option<Approval>,
    /// Why the policy rejects it, when it does.
    pub rejection: Option<String>,
    /// The account it will be signed for, when the account signs as a proxy.
    pub proxy_for: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ApprovalForm {
    /// Approve signing and submitting this transaction.
    approve: bool,
}

rmcp::elicit_safe!(ApprovalForm);

#[tool_router(router = tool_router)]
impl Server {
    pub fn new(accounts: Accounts, audit: AuditLog) -> Self {
        Self {
            accounts: Arc::new(accounts),
            chains: Default::default(),
            signing: Default::default(),
            audit: Arc::new(audit),
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "List the stored accounts: address, endpoint, proxy and the calls each may sign."
    )]
    async fn list_accounts(&self) -> Result<Json<AccountList>, String> {
        let accounts = self
            .accounts
            .names()
            .and_then(|names| {
                names
                    .iter()
                    .map(|name| self.accounts.get(name))
                    .collect::<Result<Vec<_>, _>>()
            })
            .map_err(error)?;
        Ok(Json(AccountList {
            accounts: accounts
                .into_iter()
                .map(|record| AccountInfo {
                    name: record.name.clone(),
                    address: record.address.clone(),
                    scheme: record.scheme.to_string(),
                    endpoint: record.policy.endpoint.clone(),
                    proxy: record.policy.proxy.clone(),
                    allow: record.policy.allow.clone(),
                })
                .collect(),
        }))
    }

    #[tool(
        description = "Decode hex call data with the account's chain and check it against the account's policy. Signs nothing."
    )]
    async fn decode_call(
        &self,
        Parameters(args): Parameters<CallArgs>,
    ) -> Result<Json<CallReport>, String> {
        let call = parse_hex_call(&args.call)?;
        let request = self.request(&args.account, &call).await?;
        report(&request).map(Json)
    }

    #[tool(
        description = "Build call data from a pallet, a call and its arguments, using the account's chain metadata, and check it against the account's policy. Signs nothing."
    )]
    async fn encode_call(
        &self,
        Parameters(args): Parameters<EncodeArgs>,
    ) -> Result<Json<CallReport>, String> {
        let record = self.accounts.get(&args.account).map_err(error)?;
        let api = self.api(&record.policy.endpoint).await?;
        let metadata = api.metadata();
        let call = DecodedCall::encode(&metadata, &args.pallet, &args.call, args.args.as_deref())
            .map_err(error)?;
        let request = Request::new(record, &metadata, call.bytes()).map_err(error)?;
        report(&request).map(Json)
    }

    #[tool(
        description = "Sign and submit a call with a stored account, once its policy allows it and, unless every call matches an unattended rule, the user approves it. Waits for finalization and returns the block and events."
    )]
    async fn sign_and_submit(
        &self,
        Parameters(args): Parameters<CallArgs>,
        peer: Peer<RoleServer>,
    ) -> Result<Json<Outcome>, String> {
        let call = parse_hex_call(&args.call)?;
        let _signing = self.signing.lock().await;

        let request = self.request(&args.account, &call).await?;
        let approval = request.check().map_err(error)?;
        if approval == Approval::Required {
            approve(&peer, &request).await?;
        }

        let api = self.api(&request.account.policy.endpoint).await?;
        request
            .sign(&api, approval, &self.audit, |_| {})
            .await
            .map(Json)
            .map_err(error)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "subskribinto",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(INSTRUCTIONS)
    }
}

impl Server {
    /// A client for `endpoint`. It is reused while its connection is alive and the chain runs the
    /// same runtime, and replaced otherwise: after a dropped websocket or a runtime upgrade.
    async fn api(&self, endpoint: &str) -> Result<Api, String> {
        let mut chains = self.chains.lock().await;
        if let Some(api) = chains.get(endpoint) {
            if tx::is_current(api).await {
                return Ok(api.clone());
            }
            chains.remove(endpoint);
        }
        let api = tx::connect(endpoint).await.map_err(error)?;
        chains.insert(endpoint.to_owned(), api.clone());
        Ok(api)
    }

    async fn request(&self, account: &str, call: &[u8]) -> Result<Request, String> {
        let record = self.accounts.get(account).map_err(error)?;
        let api = self.api(&record.policy.endpoint).await?;
        Request::new(record, &api.metadata(), call).map_err(error)
    }
}

/// Ask the human: through the MCP client when it supports it, and through the operating system
/// when it can. At least one must happen, and every one that happens must approve.
async fn approve(peer: &Peer<RoleServer>, request: &Request) -> Result<(), String> {
    let asked_in_client = match peer.elicit::<ApprovalForm>(request.summary()).await {
        Ok(Some(ApprovalForm { approve: true })) => true,
        Ok(_) | Err(ElicitationError::UserDeclined | ElicitationError::UserCancelled) => {
            return Err("The user did not approve this transaction".into());
        }
        Err(ElicitationError::CapabilityNotSupported) => false,
        Err(e) => return Err(format!("Could not ask the user for approval: {e}")),
    };

    if presence::STRONG {
        presence::confirm(&request.reason()).await.map_err(error)
    } else if asked_in_client {
        Ok(())
    } else {
        Err(
            "This MCP client can't ask the user to approve transactions, and this platform has \
             no other way to; refusing to sign"
                .into(),
        )
    }
}

fn report(request: &Request) -> Result<CallReport, String> {
    let (approval, rejection) = match request.check() {
        Ok(approval) => (Some(approval), None),
        Err(e) => (None, Some(e.to_string())),
    };
    Ok(CallReport {
        call_data: format!("0x{}", hex::encode(request.call.bytes())),
        description: request.call.describe(),
        calls: request.call_names().map_err(error)?,
        allowed: approval.is_some(),
        approval,
        rejection,
        proxy_for: request.proxy().map(|proxy| proxy.real.clone()),
    })
}

fn parse_hex_call(call: &str) -> Result<Vec<u8>, String> {
    hex::decode(call.trim().trim_start_matches("0x")).map_err(|e| format!("`call` is not hex: {e}"))
}

fn error(e: anyhow::Error) -> String {
    format!("{e:#}")
}

#[cfg(test)]
mod tests {
    use std::{
        process::{Child, Command, Stdio},
        time::Duration,
    };

    use super::*;
    use crate::store::memory::MemoryKeystore;

    const PORT: u16 = 19955;

    fn start_dev_node() -> Child {
        Command::new("polkadot")
            .args(["--dev", "--tmp", "--no-telemetry", "--no-prometheus"])
            .args(["--no-hardware-benchmarks", "--rpc-port", &PORT.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("`polkadot` must be on the PATH")
    }

    /// The server's client for the dev node, waiting for the node to accept connections.
    async fn api_when_up(server: &Server, endpoint: &str) -> Api {
        for _ in 0..120 {
            if let Ok(api) = server.api(endpoint).await {
                return api;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        panic!("the dev node didn't come up");
    }

    #[tokio::test]
    #[ignore = "starts a local dev chain with the `polkadot` binary"]
    async fn replaces_a_client_whose_connection_died() {
        let endpoint = format!("ws://127.0.0.1:{PORT}");
        let audit = AuditLog::at(std::env::temp_dir().join("subskribinto-reconnect-audit.jsonl"));
        let server = Server::new(Accounts::new(MemoryKeystore::default()), audit);

        let mut node = start_dev_node();
        let first = api_when_up(&server, &endpoint).await;
        assert!(tx::is_current(&first).await);

        // The node goes away: the cached client's websocket dies with it.
        node.kill().unwrap();
        node.wait().unwrap();
        assert!(!tx::is_current(&first).await);

        // Once the node is back, the server must hand out a working client, not the dead one.
        let mut node = start_dev_node();
        let second = api_when_up(&server, &endpoint).await;
        let head = second
            .blocks()
            .at_latest()
            .await
            .map(|block| block.number());
        node.kill().unwrap();
        node.wait().unwrap();
        assert!(head.is_ok(), "{head:?}");
        assert!(!tx::is_current(&first).await, "the old client stays dead");
    }
}
