# Policies

Owner policy lifecycle, local agent wallets, Stellar execution and hosted execution authorization. The [README](../README.md#wallets-and-policies) has the short version.

## Owner policy lifecycle

`allowit policy` calls the pinned `allowit-native` Rust SDK library. The SDK generates policy parameters, signs locally, keeps its durable journal and talks to the network. These commands need no `ALLOWIT_TOKEN` and do not read `ALLOWIT_URL`. The CLI has no Node runtime or subprocess adapter.

Native `policy` commands require a local POSIX filesystem for private, durable journals. On Windows, use Linux/WSL and keep state in the Linux filesystem, not `/mnt/c` or `/mnt/d`. The CLI refuses unsupported platforms before loading keys or creating policy state. Keep existing journals for recovery. Do not regenerate or resubmit an uncertain operation.

```sh
allowit policy generate "Spend up to 5 test tokens per day"   # prints the generated Rust source
allowit policy import EXECUTOR_JSON          # import the browser policy bundle
allowit policy deploy 25                    # print the owner browser signing link
allowit policy fund 25                      # prints the transaction's explorer link
allowit policy execute RECIPIENT_TOKEN_ACCOUNT 1.5
allowit policy status
allowit policy revoke
allowit policy withdraw 10
allowit policy close
allowit policy tune 0.5
allowit policy tune-action 0.25
allowit policy help                         # or: allowit policy COMMAND --help
```

| Command | Arguments |
|---|---|
| `generate` | Exactly one `PROMPT`. Quote it; several words unquoted are refused. Put `--` before a prompt that begins with `-`. |
| `import` | The owner-exported executor bundle file. |
| `status`, `revoke`, `close` | None. |
| `deploy`, `fund`, `withdraw` | One positive decimal `AMOUNT` (e.g. `5`, `0.25`). `deploy` binds this initial funding in the browser signing intent. `deploy --network stellar:testnet` approves an existing installed policy from `ALLOWIT_STELLAR_POLICY_FILE` and moves no funds. |
| `execute` | `RECIPIENT` (a Solana token account address, checked offline) and a positive decimal `AMOUNT`. |
| `tune`, `tune-action` | One non-negative daily or per-action limit `VALUE`. |

Decimals are plain digits with an optional fraction: no sign, exponent, separator, leading zero or bare `.`, at most 40 characters. The SDK checks precision and limits. Every command accepts `--json`, which asks the SDK for a machine-readable result on stdout; any other flag is refused. Invalid arguments exit 2 before anything runs.

**Network.** Testnet by default. `ALLOWIT_NETWORK=solana:devnet` selects Devnet explicitly; configure its RPC as well. Mainnet is refused. Generate never signs. Execute needs `ALLOWIT_OWNER` (public key), the executor key, and the imported scoped server capability; the authority key remains server-side. Status needs no secret signing key. Owner keys stay on the owner device.

**Exit codes.** 0 settled, new generation or status; 2 usage; 3 configuration; 5 uncertain; 6 replay of an earlier settled operation; 20 policy denial or finalized failure. `ALLOWIT_REQUEST_ID` identifies a new intended operation; keep it unchanged for retries.

An expired unsigned server approval exits 3 with its original request ID and never requests an executor signature. The scoped executor endpoint returns that same stored approval on a retry; it cannot refresh it. Retain the original ID and approval, then have the owner authorize an explicit replacement before selecting a fresh ID. A settled `close` retry verifies and replays the saved receipt (exit 6) after the vault accounts disappear. A new close ID still requires a live vault, and a recreated vault uses its current instance instead of the old close receipt.

### Local configuration

| Variable | Meaning |
|---|---|
| `ALLOWIT_POLICY_DIR` | Local policy and journal directory. Default `.allowit`. |
| `ALLOWIT_POLICY_FILE` | Optional policy file override. |
| `ALLOWIT_NETWORK` | `solana:testnet` (default) or `solana:devnet`. |
| `ALLOWIT_RPC_URL` | Optional network RPC URL. |
| `ALLOWIT_MINT` | Six-decimal classic SPL test mint. |
| `ALLOWIT_EXECUTOR` | Designated executor public key. |
| `ALLOWIT_AUTHORITY` | Trusted server authority public key. |
| `ALLOWIT_DEPLOYMENT_FILE` | Verified native deployment manifest. |
| `ALLOWIT_STELLAR_POLICY_FILE` | Public existing owner-configured native Stellar policy JSON. |
| `ALLOWIT_OWNER` | Owner public key for browser deployment, execution and status. Deployment never loads an owner private key. |
| `ALLOWIT_OWNER_KEYPAIR` | Private owner key file for local owner operations other than deployment. |
| `ALLOWIT_EXECUTOR_KEYPAIR` | Private executor key file for execution. |
| `ALLOWIT_REQUEST_ID` | Required for execution; the durable operation ID. |
| `ALLOWIT_EXECUTION_ACTION` | Exact action for the server policy. Default `transfer`. |
| `ALLOWIT_EXECUTION_MERCHANT` | Exact merchant, when applicable. |
| `ALLOWIT_EXECUTION_CONTEXT_JSON` / `ALLOWIT_EXECUTION_CONTEXT_FILE` | The exact policy context object, inline or as a file path (not both). Context is sent to the trusted backend, so do not put credentials in it. |
| `ALLOWIT_ADDITIONAL_OWNER_OPERATION=1` | Together with a fresh ID, marks an explicitly additional fund or withdraw after an expired uncertain operation. |

Import persists a public context and refuses conflicting configuration. Keys are private local files.

### Hosted execution authorization

A backend-exported executor bundle contains `audit: {origin, token}`. Import saves this policy-scoped capability in the private local journal. The CLI sends only the high-level action, merchant, context, recipient and amount to `POST /api/native/execute`; the backend evaluates the owner-bound policy and returns an authority-only signature over its exact prepared transaction. The CLI reconstructs and checks the approval commitment, signer set, instructions and message, adds only the executor signature, persists the complete proof, then requires a durable `POST /api/native/report` acknowledgment before chain broadcast. Identical retries reconcile the saved proof without obtaining another approval or allocating another payment. Missing, redirected or inconsistent responses block broadcast or produce exit 5. `policy status` retries reporting without signing or broadcasting. The token is never printed; the executor bundle and journal contain this private capability and must not be shared publicly. Denial, unresolved owner input, or a required provider failure produces no execution signature. Owner operations remain independent of the provider and authority.

## Local agent wallets

```sh
allowit wallet generate --network solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1 --output /private/path/agent.json
allowit wallet show --network solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1 /private/path/agent.json
allowit wallet configure --network stellar:testnet --owner G_ADDRESS --agent G_ADDRESS --engine G_ADDRESS --request-id ID
allowit wallet approve --network stellar:testnet --policy-file PUBLIC_POLICY_JSON --owner G_ADDRESS --request-id ID
```

The parent directory is private (0700). New secret files are 0600 and never replace existing keys. Solana uses its native JSON keypair, Tempo uses hex and Stellar uses a StrKey seed. Output contains public metadata only. Use that metadata for `setup`, which registers public `{network, address, publicKey, keyType}` metadata with the server; remote account key generation, secret import and secret export are refused. Server validation and the server's independent authority do not require the agent's private key.

`--network` accepts x402 CAIP-2 identifiers and must match the wallet or deployment. An ambiguous address cannot select a network. Tempo generic execution accepts only its bound token-transfer operation.

Stellar `configure` prints an owner signing link for a fresh funded native account. Stellar `approve` prints a source approval link for an existing owner-configured policy.

### Solana Devnet deployment

Solana Devnet `policy deploy` requires the public owner and configured public wallet roles, plus `ALLOWIT_REQUEST_ID`. It prints a browser link and the intent fingerprint, then exits 10. Compare that fingerprint in the browser before signing. The browser requires the exact source, network, amount, deployment, mint, executor and authority. The backend's configured executor public key must match the CLI agent key. A mismatch fails before signing. A signing link does not establish a finalized deployment. Other rail lifecycle restrictions remain explicit.

For an authoritatively expired unsigned browser preparation, choose a new `ALLOWIT_REQUEST_ID` and set `ALLOWIT_RETRY_PREPARATION_OF` to the original preparation ID. The browser checks explicit replacement permission. Signed uncertain transactions retain their original proof and are never replaced through this option.

## Stellar execution

This mode activates when `ALLOWIT_TOKEN` starts with `allowit-stellar-v1.`. Scalar request flags and curl requests are not part of this Stellar transfer profile.

Create `ALLOWIT_TOKEN` in the owner browser from the public deployment metadata and the customer's signing key. Pass the token in the agent prompt. The CLI decodes the token and signs requests locally. It never reads the backend environment or sends the token or signing key to the server. `ALLOWIT_URL` defaults to `https://app.allowit.xyz`; set it only to use another trusted service origin.

The token has no automatic expiration. The server does not store or recover it. If it is lost, use the owner account to undeploy the policy on chain. Request signatures and prepared transactions have their own short validity windows; these do not expire the customer token.

Run `allowit exec POLICY --request-file request.json --wait 0s`. The file uses the canonical typed request envelope:

```json
{"requestId":"stable-request-001","input":{"kind":"execution-request","request":{}}}
```

Replace `request` with the complete installed-profile `ExecutionRequest`. Its operation nonce is SHA-256 of UTF-8 `allowit-workflow-operation-v1`, NUL, the exact policy ID, NUL and the exact request ID. Amounts use native Stellar base units. The CLI checks the token metadata, request, policy source and exact prepared transaction before signing. The server checks the presented customer key against current on-chain authority together with its own signer. The CLI does not validate membership against an old server agent configuration. The existing execute endpoint supplies the engine authorization and submits the exact transaction.

`allowit status POLICY REQUEST_ID --wait 60s` recovers the original transaction. After agent authorization, repeating `exec` with the same ID only queries status. It does not sign or submit again.

An explicit `exec` can continue an unsigned attempt using its exact original prepared bytes. A never-prepared intent can retry preparation with the same ID and input only after status confirms no server record.

Keep the private journal in `.allowit/stellar-journal` in the working directory. It contains public operation proofs, never the token or signing seed. Preserve it after a timeout. A confirmed chain transaction does not establish delivery of an external service.
