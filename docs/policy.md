# Policies

Every account stored with `subskribinto accounts add` has a **policy**: which node it talks to, which
calls it may sign, with what limits, and whether it signs as a proxy of another account. The policy is
kept in the system keystore next to the key, so editing files can't loosen it, and replacing it needs
your approval (Touch ID or your password on macOS).

Policies apply to everything a stored account signs, whether through the MCP server or with
`subskribinto --account <name>`. Anything a policy doesn't allow is rejected **before** you are asked
to approve anything.

## At a glance

```toml
# The only node this account talks to.
endpoint = "wss://kreivo.io"

# Optional: sign every call as a proxy of another account.
[proxy]
real = "HNZata7iMYWmk5RvZRTiAsSDhV8366zq2YGb3tLH5Upf74F"
type = "NonTransfer"

# Allowed calls. Anything not listed here is rejected.
[[allow]]
call = "Balances.transfer_keep_alive"
max = { value = "10_000_000_000_000" }     # at most 10 KSM
to = { dest = ["HNZata7iMYWmk5RvZRTiAsSDhV8366zq2YGb3tLH5Upf74F"] }

[[allow]]
call = "System.remark"
```

The addresses are examples. An annotated version lives in [`examples/policy.toml`](../examples/policy.toml).

## Fields

| Field | Required | Meaning |
|---|---|---|
| `endpoint` | yes | The WebSocket URL (`ws://` or `wss://`) of the only node this account uses. Calls are decoded with that node's metadata. Tools and `--account` can't pick a different node. |
| `[proxy]` | no | Wrap every call in `Proxy.proxy(real, type, call)` before signing. See [Signing as a proxy](#signing-as-a-proxy). |
| `proxy.real` | with `[proxy]` | The account being proxied (SS58, any network prefix). |
| `proxy.type` | no | The `ProxyType` to force, e.g. `"NonTransfer"`. When omitted, the chain uses whichever proxy relationship matches. |
| `[[allow]]` | no | One rule per allowed call. **No rules means nothing can be signed.** |
| `allow.call` | yes | `"Pallet.call"`, or `"Pallet.*"` for every call of a pallet. Names are case-sensitive and match the metadata (`Balances.transfer_keep_alive`, not `balances.transferKeepAlive`). |
| `allow.max` | no | Upper bounds for numeric arguments: `{ argument = amount }`. |
| `allow.to` | no | Allowed accounts for account arguments: `{ argument = ["SS58", …] }`. |

Unknown fields are an error, so a typo (`allows`, `maximum`) never silently weakens a policy.

## How a request is checked

1. The call is decoded with the metadata of the policy's `endpoint`.
2. Every call **nested** in it is found too: the calls inside `Utility.batch_all`, `Proxy.proxy`,
   `Multisig.as_multi` and anything else whose arguments contain a runtime call.
3. Each of those calls, the outer one included, must be allowed by **at least one rule**, and **all of
   that rule's limits** must hold. If several rules name the same call, any one of them passing is enough.
4. If a call or a limit can't be checked (a missing argument, a value that isn't a number or an
   account), the request is rejected. Policies fail closed.
5. Only then is the call wrapped for the proxy (if configured), shown to you, and signed after you
   approve it.

So a batch needs a rule for the batch itself **and** for every call inside it:

```toml
[[allow]]
call = "Utility.batch_all"

[[allow]]
call = "Balances.transfer_keep_alive"
max = { value = "1_000_000_000_000" }
```

## Rules

### `max`: capping amounts

```toml
max = { value = "10_000_000_000_000" }
```

- Keys are **argument names** of the call (see [Finding argument names](#finding-argument-names)).
- Amounts are in the chain's **smallest unit**. On Kreivo, KSM has 12 decimals, so 1 KSM is
  `1_000_000_000_000`.
- Write amounts as integers or strings. Strings can use `_` separators and go beyond the range of TOML
  integers (2⁶³), which matters for tokens with 18 decimals.
- The argument must be a number. Compact encodings and single-field wrappers are looked through.

### `to`: allowed recipients

```toml
to = { dest = ["HNZata7iMYWmk5RvZRTiAsSDhV8366zq2YGb3tLH5Upf74F", "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"] }
```

- Keys are argument names; values are lists of SS58 addresses in **any** network format (Kreivo's
  `H…`/`F…` style, or generic `5…`). They're compared as raw account IDs.
- Every account found in the argument must be in the list. Accounts are recognised by their type
  (`AccountId32`), wherever they sit inside the argument, e.g. `dest: Id(…)`. A hash of the same length
  never counts as an account.
- If the argument holds no account at all (for example `dest: Index(…)`), the call is rejected.

### Wildcards

`"Pallet.*"` allows every call of a pallet, **including calls a future runtime upgrade adds**. Prefer
explicit call names for anything that can move funds. `*.*` and other forms are rejected.

## Signing as a proxy

With `[proxy]`, you store a key that is a proxy of the account that holds the funds
(`Proxy.add_proxy` from that account), and every call is sent as
`Proxy.proxy(real, type, call)`:

- The **policy applies to the call you asked for**, not to the `Proxy.proxy` wrapper: you don't need a
  rule for `Proxy.proxy`.
- The chain enforces the proxy type on top of the policy. On Kreivo, a `NonTransfer` proxy can't move
  funds even if a policy were too loose, and you can revoke it from the real account at any time.
- Fees are paid by the proxy key, so keeping it lightly funded also caps how much fees can be spent.

This is the recommended setup for any account an AI assistant can use.

## Finding argument names

`max` and `to` are keyed by the call's argument names as they appear in the runtime metadata:

- The MCP tools `decode_call` and `encode_call` show the decoded call with its argument names, and
  whether the policy allows it (and why not).
- polkadot.js Apps → Developer → Extrinsics lists every call's arguments, but in camelCase: use the
  snake_case form in policies (`poll_index`, not `pollIndex`).

Common calls on Kreivo:

| Call | Arguments |
|---|---|
| `Balances.transfer_keep_alive` / `transfer_allow_death` | `dest` (account), `value` (KSM, 12 decimals) |
| `Assets.transfer_keep_alive` / `transfer` | `id` (asset), `target` (account), `amount` (in that asset's decimals) |
| `System.remark` / `remark_with_event` | `remark` (bytes) |
| `Utility.batch_all` | `calls` (each one is checked too) |
| `KreivoCollective.vote` | `poll`, `aye` |
| `Communities.vote` | `membership_id`, `poll_index`, `vote` (`Standard(aye)`, `NativeBalance(aye, amount)` or `AssetBalance(aye, asset, amount)`) |

## Managing policies

```bash
# Store an account with a policy…
subskribinto accounts add ops --key-file ./ops.json --policy ./policy.toml
# …or with only an endpoint: nothing can be signed until you set a policy.
subskribinto accounts add ops --key-file ./ops.json --endpoint wss://kreivo.io

subskribinto accounts show ops                    # prints the current policy as TOML
subskribinto accounts policy ops ./policy.toml    # replaces it (needs your approval)
```

`accounts show` prints a policy you can save, edit and load back with `accounts policy`. A policy is
validated before it's stored: a bad endpoint, an invalid address, a malformed `call`, an empty `to`
list or an unknown field are all errors.

## Limitations

- **Limits apply to a call's own arguments** (by name), not to fields deep inside them. For example,
  you can't cap the amount inside `Communities.vote`'s `vote` argument, or allow only `Standard`
  votes; a `NativeBalance` or `AssetBalance` vote locks funds until the poll ends.
- **No rate or period limits** (e.g. "at most 10 KSM a day"). Every request is judged on its own.
- **Calls that dispatch other calls from bytes or hashes** (schedulers, preimages, `Multisig` approvals
  by call hash) can't be inspected. Allowing them effectively allows anything.
- **On Linux and Windows**, any program running as you can read and change keystore entries, policies
  included. See the platform notes in the [README](../README.md#platform-notes); rely on restricted
  proxies there.
