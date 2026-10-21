# Tempo usage

See [Build from source](../README.md#build-from-source) to install the CLI.

## Vault payments

Tempo uses the separately versioned `allowit tempo` command set.
Import the owner's exported executor bundle:

```sh
allowit tempo import EXECUTOR_JSON
export ALLOWIT_REQUEST_ID='REQUEST_ID'
export ALLOWIT_TEMPO_EXECUTOR_KEY_FILE='/path/to/executor-key'
allowit tempo pay RECIPIENT AMOUNT
```

`pay` validates the exact policy and authority signature.
It signs a native `0x76` vault call with the designated executor key, broadcasts it, and checks canonical finality, token transfer and backend settlement.
The binary needs no payment wrapper or Node runtime.
Owner create/fund/revoke/withdraw operations stay in the browser.
The agent never receives an owner or authority key.

`pay` prints the request, vault, amount, transaction hash and final status.
`--json` returns these fields with `state` and `exitCode`.
Policy denials exit 20 without signing or sending.
Owner-input requests exit 11, and settled replays exit 6.

`allowit tempo execute RECIPIENT AMOUNT` prepares a payment and exits 10 without loading keys or broadcasting.
`submit REQUEST_ID TRANSACTION_HASH` reports an externally signed transaction.
`status REQUEST_ID` reads the backend record.
These commands do not implement owner lifecycle operations or change wallet interfaces.

## Payment intent

`execute` and `pay` read the exact policy input from the environment:

```sh
export ALLOWIT_REQUEST_ID='invoice-0001'
export ALLOWIT_EXECUTION_ACTION='Buy one API credit pack'
export ALLOWIT_EXECUTION_MERCHANT='api.example.com'
export ALLOWIT_EXECUTION_CONTEXT_JSON='{"purpose":"Weekly report data"}'
allowit tempo execute 0xRECIPIENT 0.25
```

- `ALLOWIT_REQUEST_ID` is required: 8 to 100 characters from `A-Z a-z 0-9 . _ : -`. Use a fresh ID for each new intent.
- `ALLOWIT_EXECUTION_ACTION` defaults to `transfer`.
- `ALLOWIT_EXECUTION_MERCHANT` defaults to an empty string.
- `ALLOWIT_EXECUTION_CONTEXT_JSON` must be a JSON object of at most 16 KB and defaults to `{}`. It is sent to the backend as an unauthenticated claim, so never put credentials in it.
- `RECIPIENT` is a `0x` EVM address. `AMOUNT` is a positive decimal with at most six fractional places, without sign, exponent or separators.

The request ID, recipient, amount, action, merchant and context form one exact intent.
Keep all of them unchanged when you retry, resume or recheck a request.
A different intent under the same ID is refused.

`execute` always prints the backend result as JSON.
After an allowed decision it prints the authority-signed wallet plan and exits 10; nothing is signed or broadcast.
`pay` signs and sends that plan itself.

## Exit codes

| Exit | Meaning |
|---|---|
| 0 | imported, settled, or help |
| 2 | invalid usage |
| 3 | configuration, platform or bundle error |
| 5 | uncertain: the outcome is unknown, or the backend returned no usable record |
| 6 | replay of an already settled request; nothing new was paid |
| 10 | wallet plan prepared (`execute`, or `status` of a prepared request) |
| 11 | awaiting owner input |
| 12 | submitted, finality pending |
| 20 | policy denial, or a finalized failure |

Exits 5, 10, 11 and 12 never mean a confirmed payment.
`status` maps the backend operation state: `settled` 0, `prepared` 10, `submitted` 12, `failed` 20, anything else 5.

`status` can find only requests that reached a payment operation.
A request the policy denied (exit 20) or paused for owner input (exit 11) has no payment record, so `status` for that ID exits 5 with "outcome is unknown".
That exit 5 does not mean a payment may exist: no payment was authorized under that ID.
The denial or question printed by `execute`, `pay` or `call` is the authoritative result.
To recheck such a request, for example after the owner answers, rerun the identical command with the same ID and intent; the policy is evaluated again and cannot create a duplicate payment.

## Configuration

- `ALLOWIT_TEMPO_STATE_DIR` defaults to `$XDG_STATE_HOME/allowit/tempo` or `$HOME/.local/state/allowit/tempo`, with a separate executor/chain subdirectory.
- Keys and journals require a private local POSIX filesystem. On Windows, use WSL's Linux filesystem.
- The key file contains a 32-byte hexadecimal secp256k1 key, with an optional `0x` prefix. The current user must own it, with mode `0600`.
- The executor needs its own fee-token balance.
- RPC defaults to the exported configuration. `ALLOWIT_TEMPO_RPC_URL` may override it, but the live chain must match. Only Tempo testnet/localnet is supported.
- Gas defaults to a maximum of 1,500,000. The maximum total fee defaults to 0.1 test dollar. See `allowit tempo help` for bounded overrides through `ALLOWIT_TEMPO_MAX_GAS` and `ALLOWIT_TEMPO_MAX_FEE`.
- Fees use attodollars per gas, independently of token decimal precision.
- Finality waiting defaults to 120 seconds. `ALLOWIT_TEMPO_WAIT_SECONDS` accepts 0–600. Exit 12 means pending, and exit 5 means uncertain. Neither means confirmed.

## Payment recovery

`allowit tempo resume REQUEST_ID` recovers the saved transaction without a signing key or another authorization.
The CLI saves signed bytes and the local hash durably before broadcast.
Retries reconcile that same hash.
They may rebroadcast only the exact saved bytes if the transaction is absent.

Keep the original bundle, exact intent and executor-wide journal, including after timeouts.
A missing receipt cannot prove the transaction was never sent.
The CLI serializes payments across vaults that use the same executor and chain until the earlier signed transaction reaches finality.
Keep this executor dedicated to these payments.
Use the same state directory in every process.

Recovery never chooses a new account nonce, requests another authorization or signs a replacement.
Rebroadcasting the same signed bytes cannot create a second payment.

## Paid API requests

```sh
allowit tempo call https://merchant.example/paid --id purchase-0001 --max-amount 0.25
```

`call` buys an API response through the same native vault.
It parses an HTTP 402 using the official [Rust MPP SDK](https://github.com/tempoxyz/mpp-rs).
It validates the exact Tempo testnet charge against the exported token and maximum.
It binds the original HTTP request and challenge into the policy authorization.
The confirmed vault transfer carries the merchant's challenge/realm attribution memo.
Its transaction hash credential identifies the vault as the token sender.
The CLI submits that credential once to the original HTTPS GET URL.
It does not pay directly from the executor wallet.

The API call requires explicit Tempo chain 42431, push/hash credentials and client-paid fees.
It accepts only canonical HTTPS URLs without query, credentials or fragment.
It refuses redirects, custom request headers, split payments and sponsored/pull transactions.
A successful HTTP response needs a matching `Payment-Receipt`.
The CLI returns an escaped UTF-8 body up to 64 KB, including in `--json`.
It stores the response only in the private journal.
Backend history records the executor's bounded report and receipt reference.
These records do not establish independent proof from the provider.

## API response recovery

Repeating the call with the same ID reuses the saved challenge and signed transaction.
`tempo resume` cannot authorize another charge, request a replacement challenge, or blindly resend an already-attempted HTTP credential.
If payment is confirmed but the response was lost, it reports `response_unavailable` and exits 5.
Recovery returns a saved successful API response with exit 6.

Keep the original bundle and journal.
After owner input and before a signature exists, rerun the exact original call with its URL, ID and maximum.
Legacy native-v1 journals remain readable.
