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
