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
    call::DecodedCall,
    guard::Request,
    policy::{ProxyConfig, Rule},
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
`sign_and_submit`. The user approves every signature themselves (a prompt in this client and, on \
macOS, Touch ID); you can't approve on their behalf, so tell them what you are about to submit and \
why. Calls the policy doesn't allow are rejected before the user is asked: suggest a policy change \
for them to make, don't try to work around it.";

pub async fn serve(accounts: Accounts) -> anyhow::Result<()> {
    let server = Server::new(accounts);
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
    /// Why the policy rejects it, when it does.
    pub rejection: Option<String>,
    /// The account it will be signed for, when the account signs as a proxy.
    pub proxy_for: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct Approval {
    /// Approve signing and submitting this transaction.
    approve: bool,
}

rmcp::elicit_safe!(Approval);

#[tool_router(router = tool_router)]
impl Server {
    pub fn new(accounts: Accounts) -> Self {
        Self {
            accounts: Arc::new(accounts),
            chains: Default::default(),
            signing: Default::default(),
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
        description = "Sign and submit a call with a stored account, after its policy allows it and the user approves it. Waits for finalization and returns the block and events."
    )]
    async fn sign_and_submit(
        &self,
        Parameters(args): Parameters<CallArgs>,
        peer: Peer<RoleServer>,
    ) -> Result<Json<Outcome>, String> {
        let call = parse_hex_call(&args.call)?;
        let _signing = self.signing.lock().await;

        let request = self.request(&args.account, &call).await?;
        request.check().map_err(error)?;
        approve(&peer, &request).await?;

        let signer = request.account.signer().map_err(error)?;
        let api = self.api(&request.account.policy.endpoint).await?;
        tx::sign_and_submit(&api, &request.signed, &signer, |_| {})
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
    async fn api(&self, endpoint: &str) -> Result<Api, String> {
        let mut chains = self.chains.lock().await;
        if let Some(api) = chains.get(endpoint) {
            return Ok(api.clone());
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
    let asked_in_client = match peer.elicit::<Approval>(request.summary()).await {
        Ok(Some(Approval { approve: true })) => true,
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
    let rejection = request.check().err().map(|e| e.to_string());
    Ok(CallReport {
        call_data: format!("0x{}", hex::encode(request.call.bytes())),
        description: request.call.describe(),
        calls: request.call_names().map_err(error)?,
        allowed: rejection.is_none(),
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
