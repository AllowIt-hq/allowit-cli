# Commands

The complete reference for `allowit show`, `eval`, `exec` and `status`. The [README](../README.md#core-commands) has the short version; the [HTTP API contract](http-api.md) has the exact response validation rules.

## Configuration

Environment only; the token is never accepted as a flag or URL parameter.

```sh
export ALLOWIT_URL='https://app.allowit.xyz'   # exact service origin; also the default when unset
export ALLOWIT_TOKEN='owner.policy.secret'     # the policy's harness token
# optional: export ALLOWIT_CA_FILE=/path/extra-roots.pem
```

- `ALLOWIT_URL` must be `https://host[:port]` with no path, query, fragment or credentials. Plain `http` is accepted only for `localhost` and loopback addresses.
- Redirects are never followed, so the `Authorization` header cannot leave the origin.
- The `POLICY` argument must match the token's policy; otherwise the CLI stops before any request.
- The token and its secret are scrubbed from everything the CLI prints, along with terminal control characters. The secret part must be 16 to 128 URL-safe characters.
- Requests time out after 60 s; responses are capped at 2 MB, requests at 64 KB.

## Usage

```sh
allowit show POLICY                      # policy, network, budget, rails, checks, original request
allowit show POLICY --json               # machine contract (credentials removed); --source adds the Rust policy

allowit eval POLICY --request-id dataset-001-eval --rail stellar --op transferXLM --addr G... --amount 5 --action research \
  --context '{"decision":"Buy dataset","evidence":{"source":"https://...","observed_at":"2026-09-28T12:00:00Z"}}'
allowit exec POLICY --request-id dataset-001-exec --rail stellar --op transferXLM --addr G... --amount 5 --action research \
  --context '{"decision":"Buy dataset","evidence":{"source":"https://...","observed_at":"2026-09-28T12:00:00Z"}}'

allowit status POLICY REQUEST_ID [--wait 60s]
```

For IDs beginning with `-`, place `--` before `POLICY` (and `REQUEST_ID` for `status`). Flags may follow these identifiers.

USDC transfer with the customer-workspace template (`transfer` and `research` actions):

```sh
allowit eval POLICY --request-id pay-001-eval --rail solana --op transferUSDC --addr SOLANA_ADDRESS --amount 1 --action transfer
allowit exec POLICY --request-id pay-001-exec --rail solana --op transferUSDC --addr SOLANA_ADDRESS --amount 1 --action transfer
```

`eval` calls `/judge`: it checks permission and never spends or reserves budget. `exec` calls `/transactions`.

## Request flags

| Flag | Meaning |
|---|---|
| `--action` | **Required.** The action the policy evaluates, sent exactly as given (e.g. `transfer`, `research`). |
| `--rail solana\|stellar`, `--op transferSOL\|transferXLM\|transferUSDC` | Transport only: the transfer on a rail. `--rail` and `--op` are always given together. `--op` is never sent as the action. Local dev: the rails the service publishes (Solana SOL/USDC, Stellar XLM/USDC; mock plan). Wallet networks: `--rail solana --op transferUSDC` only (enforced by the CLI, whatever the service advertises). |
| `--addr` | Recipient (Solana base58 or Stellar G/M/C strkey), checked offline and again by the server. |
| `--amount` | Exact decimal. Without `--rail` and `--op`, the USDC amount. With them, the transferred asset's quantity: the USDC amount for `transferUSDC`, and for a Local dev SOL or XLM plan the quantity the CLI converts to the USDC charge. |
| `--merchant` | Optional merchant. |
| `--context JSON\|@file\|-` | Runtime context object. Forwarded as the exact JSON value; numbers are never converted. |
| `--memo`, `--data TEXT\|@file` | Local dev plan memo and payload bytes (base64-encoded by the CLI). |
| `--before`, `--after JSON\|@file` | Local dev contract calls: `[{"type":"contract_call","contract":"...","method":"...","args":{},"maxCostUSDC":"0"}]`. |
| `--request-id` | Explicit client request ID (8–100 chars). |
| `--budget` | Assert the computed USDC charge. |
| `--wait DURATION` | How long to wait for a pending evaluation. Default `60s` for `eval` and `exec`, `0s` for `status`. |
| `--json` | Machine-readable output. |

**Budget charge.** Local dev uses integer arithmetic: `ceil_to_0.000001(quantity × rate) + Σ maxCostUSDC`. `/skill` publishes test rates: SOL 100, XLM 0.1, USDC 1.

**Actions.** Missing `--action` exits 2 before sending. To retry a 0.1.1 request that omitted it, set `--action` to its original `--op`. Keep every other flag. Explicit actions retain the same request body and derived ID.

**Request IDs.** Give each operation its own `--request-id`, including separate IDs for `eval` and `exec`. Retry unchanged with the same ID. The server returns the stored result and rejects changed details. Without this flag, identical purchases share a derived ID. It hashes owner, policy, command and exact request (plan, not rate-derived charge, for Local dev). Policy revision, source hash and test rates do not affect it. The CLI prints the ID and budget charge on stderr before sending. Network failures and HTTP 502/503/504 retry twice with the same body.

**Uncertain results (exit 5).** Payment may have occurred. Never choose a new ID. Follow the printed retry or status command:

- Without an answer, rerun unchanged with the printed `--request-id`. Changed details, including a changed charge, leave the original unresolved. Check `status`.
- After acceptance, an unreadable result prints both client and server IDs. Run `allowit status --wait 60s -- POLICY ID` with either ID, or retry with the client ID. If neither ID resolves, the exec may still be in flight. Rerun that identical exec.

**Replays.** Stored results carry `replayed: true`. Explicit-ID retries retain the stored state and exit code. Derived-ID repeats return `state: replayed`, exit 6 and `replayedState`. Neither submits anything new.

**Input and output.** Duplicate request flags exit 2. Multiline server text prints as one quoted value. `--context` requires one JSON object: maximum 16 KB, depth 8 and 128 values. Repeated keys and top-level `allowitExecution` are forbidden. The server applies the same limits.

**Protocol checks.** The CLI checks `/skill`, canonical routes, networks and response states. Inconsistent responses remain uncertain. `status` can recover without a usable policy description, subject to authentication, routing and state checks. It never resends `judge` or `transactions`. See the [HTTP API contract](http-api.md) for exact validation and recovery rules.

## States and exit codes

| Exit | State | Meaning |
|---|---|---|
| 0 | `passed` | eval: the policy permits the request. |
| 0 | `recorded` | Local dev exec: mock action recorded against the budget; no funds moved. |
| 0 | `settled` | Wallet transfer confirmed on chain. |
| 10 | `owner_signature` | Wallet transaction passed (or was submitted); the owner must sign in Allowit or the network must confirm. |
| 10 | `ready` | Passed but the server did not say whether it is a judgment or a transaction; not complete. |
| 11 | `awaiting_input` | The owner must answer the printed question in Allowit. |
| 12 | `pending` | Still evaluating after `--wait`. |
| 20 | `denied` | The policy refused; the reason is printed. |
| 2 | usage | Invalid flags or input; nothing sent. |
| 3 | config/auth/unsupported | Bad configuration, policy mismatch, untrusted TLS, redirect on `GET /skill`, HTTP 401/403 before a request is accepted, or a policy description that names another owner, policy or route, or an unknown network, profile or contract version. Nothing was sent to `judge` or `transactions`. |
| 4 | rejected | Server rejected the request (400/429) before accepting it; its message is printed. |
| 5 | uncertain | Network or server failure, an accepted request whose result could not be read, a `--request-id` already used with other details (HTTP 409), or a `status` that finds no request; follow the printed retry (same `--request-id`) or `allowit status` command. |
| 6 | `replayed` | exec/eval without `--request-id` matched an identical earlier request; nothing new was submitted. `replayedState` is its stored state. |

`status` reads by the server `requestId`, then by the client `--request-id` (`clientRequestId`); the returned request must carry the requested ID as one of them. It uses the server's `kind`: a ready `judgment` is `passed`, a ready `transaction` is `owner_signature`. All fields the server returns (reason, prompt, `decisionCode`, `workflowNodeId`, revision, source hash, receipt steps) are printed.

## API used

HTTP action commands use `GET /api/harness/{owner}/{policy}/skill` and `POST` routes for `judge`, `transactions` and `status`, with the policy-scoped bearer token. The frontend proxies this public API to the Rust backend, the Allowit engine. The CLI does not link backend or engine crates.

The HTTP commands report server states and preserve owner approval. Native `policy execute` uses the executor's local key plus the trusted server authority signature and cannot sign owner operations. Owner withdrawal and closure never depend on the executor, authority, or semantic provider.

The [gateway compatibility checks](../integration/README.md) retain pinned Go gateways and their Rust SDK runtimes as compatibility fixtures. Run `make integration APP_REPO=/path/to/AllowIt-app` alongside `make test` when both fixture commits are available locally.
