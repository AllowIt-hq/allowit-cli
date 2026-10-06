# allowit

`allowit` sends an agent's actions through an AllowIt policy. It is a thin, strict client for one policy's harness API; the policy itself (restricted Rust, evaluated by the shared SDK WASM on the AllowIt server) decides. The CLI cannot bypass the policy, the owner-input gate or the server's request schema.

Rust harness-client migration candidate. The native `policy` lifecycle still uses the temporary Node SDK adapter in this checkpoint and is not ready to ship; that adapter will be replaced by the Rust native SDK before handoff. The Go implementation is retained under `reference/go/` as a differential test oracle; it is not the default command or distribution build.

This branch is the untagged `0.3.0-dev` candidate. Build from this checkout to use its gateway compatibility fixes and the `allowit policy` owner lifecycle commands. The tagged `v0.1.1` installation below remains the earlier release.

## Install

`github.com/ackrate/allowit-cli` is private; installing needs authorized GitHub access. There is no public download.

```sh
GOPRIVATE=github.com/ackrate/* go install github.com/ackrate/allowit-cli/cmd/allowit@v0.1.1
allowit version
```

Or build the Rust candidate from a checkout (Rust 1.85 or later):

```sh
cargo build --locked --release         # target/release/allowit
make test                             # Rust tests + Go reference regressions
make parity                           # original harness cases against Rust
make integration APP_REPO=/path/to/AllowIt-app
make dist                             # static Linux/musl distribution
```

`make dist` requires the `x86_64-unknown-linux-musl` target and a suitable musl linker. CI installs both and uploads `dist/allowit-linux-amd64` with its SHA-256. The lockfile pins the complete dependency graph. The old Go installation above remains available for the earlier tagged release.

The CLI is independent of the optional hosted-agent runtime. A host can install the same binary used by an external agent; this repository contains no sandbox launcher, supervisor or model proxy.

## Configure

Environment only; the token is never accepted as a flag or URL parameter.

```sh
export ALLOWIT_URL='https://allowit.example'   # exact service origin
export ALLOWIT_TOKEN='owner.policy.secret'     # the policy's harness token
# optional: export ALLOWIT_CA_FILE=/path/extra-roots.pem
```

The generated `SKILL.md` for a policy contains exactly these two lines.

- `ALLOWIT_URL` must be `https://host[:port]` with no path, query, fragment or credentials. Plain `http` is accepted only for `localhost`/loopback (local development and tests).
- Redirects are never followed, so the `Authorization` header cannot leave the origin.
- The `POLICY` argument must match the token's policy; otherwise the CLI stops before any request.
- The token and its secret are scrubbed from everything the CLI prints, along with terminal control characters.
- Requests time out after 60 s; responses are capped at 2 MB, requests at 64 KB.

## Use

```sh
allowit show POLICY                      # policy, network, budget, rails, checks, original request
allowit show POLICY --json               # machine contract (credentials removed); --source adds the Rust policy

allowit eval POLICY --request-id dataset-001-eval --rail stellar --op transferXLM --addr G... --amount 5 --action research \
  --context '{"decision":"Buy dataset","evidence":{"source":"https://...","observed_at":"2026-09-28T12:00:00Z"}}'
allowit exec POLICY --request-id dataset-001-exec --rail stellar --op transferXLM --addr G... --amount 5 --action research \
  --context '{"decision":"Buy dataset","evidence":{"source":"https://...","observed_at":"2026-09-28T12:00:00Z"}}'

allowit status POLICY REQUEST_ID [--wait 60s]
```

Gateway-generated policy and request IDs can begin with `-`. Use `--` before the remaining identifiers, for example `allowit status --wait 60s -- POLICY REQUEST_ID` or `allowit exec --amount 1 --action transfer --addr ADDRESS -- POLICY`. For compatibility with the gateway's generated skills, `--` protects the remaining identifier slots (one policy, or policy plus request for `status`); flags may follow those slots too.

A plain USDC transfer under the customer-workspace policy template, whose actions are `transfer` and `research`:

```sh
allowit eval POLICY --request-id pay-001-eval --rail solana --op transferUSDC --addr SOLANA_ADDRESS --amount 1 --action transfer
allowit exec POLICY --request-id pay-001-exec --rail solana --op transferUSDC --addr SOLANA_ADDRESS --amount 1 --action transfer
```

`eval` calls `/judge`: it checks permission and never spends or reserves budget. `exec` calls `/transactions`.

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
| `--json` | Machine-readable output. |

**Budget charge.** For Local dev plans the CLI computes the USDC charge the server requires, exactly (integer arithmetic): `ceil_to_0.000001(quantity × rate) + Σ maxCostUSDC`, with the fixed test rates published by the server's `/skill` response (SOL 100, XLM 0.1, USDC 1).

**`--action` is required.** allowit 0.1.1 defaulted the action to the `--op` value (`transferUSDC`), which made a transport name look like the policy's action. The CLI now refuses a request without `--action` before sending anything (exit 2). Explicit actions produce the same body and the same derived request ID as before. To retry a request that 0.1.1 sent without `--action`, add `--action` set to its op (e.g. `--action transferUSDC`) and keep every other flag: that is the identical request, with the identical derived ID.

**Request IDs.** Give every intended operation its own `--request-id`, and use different IDs for `eval` and `exec` (e.g. `dataset-001-eval`, `dataset-001-exec`). To retry the same request, rerun it unchanged with the same ID: the server returns the stored result instead of applying it again, and rejects the ID if any detail changed. Without `--request-id` the ID is a hash of the owner, policy, command and exact request (for Local dev plans, the plan rather than the rate-derived charge), so an accidental retry is safe but a deliberate identical second purchase collapses into the first. Server state such as the policy revision, source hash or test rates is not part of the ID, so it does not change if the owner edits the policy between attempts. The CLI prints the ID on stderr before sending: `allowit: exec request <ID> (budget charge <AMOUNT> USDC)`, then for `exec`, `allowit: if the result is unknown, retry only with --request-id <ID>`. Network failures and 502/503/504 are retried twice with the same body.

**Uncertain results (exit 5).** The request may have been applied. Never retry with a new request ID. The CLI prints the exact next step:

- If no answer arrived, rerun the same command with the printed `--request-id ID`. AllowIt returns the stored result instead of applying it again, marked `replayed: true`. If the details changed since (e.g. a new test rate changed the charge), AllowIt refuses the reused ID rather than spending twice; that request may already have been applied, so the CLI exits 5 and prints the `allowit status` command that reads it by your `--request-id`.
- If AllowIt accepted the request but its result could not be read (a failed or invalid `/status` answer while waiting, or an empty, unknown or self-contradictory result), the CLI prints both the client ID and the server `requestId`. Check it with `allowit status --wait 60s -- POLICY ID` (the server `requestId` or your `--request-id`), or rerun with `--request-id CLIENT_ID`. A `status` that finds no request by either ID exits 5: an exec may still be in flight, so rerun that identical exec instead of choosing a new ID.

**Replays (exit 6).** AllowIt marks a stored result returned for a reused request ID with `replayed: true`. With an explicit `--request-id` that is the documented retry: the CLI keeps the stored state and exit code and notes that nothing new was submitted. With a derived ID (no `--request-id`), a separate run of an identical command only matched the earlier request, so the CLI reports `state: replayed` (exit 6) with the stored state as `replayedState`; nothing new was submitted. Pass a new `--request-id` for each intended operation.

**Flags and output.** A request flag given twice is refused (exit 2). Server text that spans lines is printed as one quoted value, so it cannot add lines that read as fields.

A result is reported only when it is one of the known combinations: `pass` with status `ready`, `submitted`, `recorded` (with `localRecorded: true`) or `settled` (with `executed: true`); `pending`/`evaluating`; `awaiting_input`/`awaiting_input`; `fail`/`denied`. `executed` and `localRecorded`, when present, must agree with the status. `kind`, when present, must be `judgment` or `transaction` and match the command; without it, `status` never reports `ready` as complete. Anything else is reported as uncertain, never as denied or complete. That includes a missing status, `pass` with `evaluating`, `pending` with `denied`, `ready` with `executed: true`, an on-chain status on Local dev, a mock recording on a wallet network, a spend for `eval`/`judgment`, and a `/status` answer for a different request or without its `requestId`. Non-200 2xx answers and redirects to `judge`/`transactions`/`status` are also uncertain.

**Policy description.** Every command first reads `GET …/skill` and checks it before anything is sent to `judge` or `transactions`:

- `owner` and `policyId`, when published, must match `ALLOWIT_TOKEN`.
- `endpoints.judge`, `.transactions`, `.status` and `.skill`, when published, must name exactly the canonical route `ALLOWIT_URL/api/harness/{owner}/{policy}/{action}`. Relative URLs are resolved against the skill URL. Another origin, scheme, port, path, query or fragment is refused (exit 3). The CLI never sends to a published endpoint: requests and the bearer token go only to the canonical route on `ALLOWIT_URL`.
- `network` is required and must be `local:dev` (mock execution) or `solana:devnet`, `solana:testnet` or `solana:mainnet` (owner-signed USDC transfers). Any other network is refused, never treated as a wallet network.
- `executionMode` (`local` / `owner_signed`), `capabilities.mode` / `capabilities.execution` and the typed `contract.profile` (`local_dev` / `solana_owner_signed`) and `contract.capabilities.execution` (`mock` / `owner_signed`), when published, must match the network. Unknown values, a `contract.version` other than 1, or a contract bound to a different `sourceHash` are refused (exit 3).
- Rails, test rates and plan support come from `contract.capabilities`, then the legacy `capabilities`. A wallet policy that publishes no rails still allows the one transfer its profile defines (`--rail solana --op transferUSDC`). A Local dev policy that publishes none accepts only plain USDC requests. When a typed contract sets `executionPlans`, `memoData` or `contractCalls` to false, the matching flags are refused.

Fields a service omits (`title`, `policyId`, `owner`, `endpoints`, `capabilities`, `contract`) are accepted as omitted. `show` uses `name` when there is no `title`, and prints the token's policy ID marked as not reported by AllowIt.

**Status without a policy description.** `status` only reads a stored request, so it continues when `/skill` fails for a reason other than authentication: a typed-skill assembly refusal (HTTP 409), another non-auth HTTP error, a network failure, or an unreadable or unsupported description. It prints `allowit: the policy description is unavailable (...)` on stderr and reads `…/status` on the canonical route. HTTP 401/403, a redirect, or a description that names another owner, policy or route still stop it (exit 3). Without the network, these are reported normally because they mean the same on every network: `pending`, `awaiting_input`, `denied` and a `ready` judgment (`passed`). `recorded`, `submitted`, `settled`, and a `ready` transaction or a `ready` result without a `kind` could be either a mock recording or a wallet transfer. Those exit 5 with stdout empty and nothing reported as confirmed, including after `--wait`. `status` never resends `judge` or `transactions`.

**Context.** `--context` must be a single JSON object of at most 16 KB, depth 8 and 128 values, with no repeated keys and no top-level `allowitExecution` (AllowIt supplies that field). The server enforces the same limits.

## Owner policy lifecycle

`allowit policy` runs the owner's policy lifecycle through the AllowIt SDK CLI (`native/cli.mjs` in AllowIt-sdk, Node 22). The SDK does the work: it generates the policy, signs with the owner's key, keeps its journal and talks to the network. allowit only checks the arguments, then runs the SDK CLI. These commands need no `ALLOWIT_TOKEN` and do not read `ALLOWIT_URL`.

```sh
allowit policy generate "Spend up to 5 test tokens per day"   # prints the generated Rust source
allowit policy deploy                       # prints the generated skill and the transaction's explorer link
allowit policy fund 25                      # prints the transaction's explorer link
allowit policy execute RECIPIENT_TOKEN_ACCOUNT 1.5
allowit policy status
allowit policy revoke
allowit policy withdraw 10
allowit policy tune 0.5
allowit policy help                         # or: allowit policy COMMAND --help
```

| Command | Arguments |
|---|---|
| `generate` | Exactly one `PROMPT`. Quote it; several words unquoted are refused. Put `--` before a prompt that begins with `-`. |
| `deploy`, `status`, `revoke` | None. |
| `fund`, `withdraw` | One positive decimal `AMOUNT` (e.g. `5`, `0.25`). |
| `execute` | `RECIPIENT` (a Solana token account address, checked offline) and a positive decimal `AMOUNT`. |
| `tune` | One non-negative decimal `VALUE`. |

Decimals are plain digits with an optional fraction: no sign, exponent, separator, leading zero or bare `.`, at most 40 characters. The SDK checks precision and limits. Every command accepts `--json`, which asks the SDK for a machine-readable result on stdout; any other flag is refused. Invalid arguments exit 2 before anything runs.

**Network.** Testnet by default. `ALLOWIT_NETWORK=solana:devnet` selects Devnet explicitly; configure its RPC as well. Mainnet is refused. Generate never signs. Execute needs `ALLOWIT_OWNER` (public key) and the executor key only; status needs no secret key. Owner keys stay on the owner device.

**Native lifecycle exits.** 0 settled/new generation or status, 5 uncertain, 6 replay of an earlier settled operation, 20 policy denial or finalized failure, 3 configuration. `ALLOWIT_REQUEST_ID` identifies a new intended operation; keep it unchanged for retries.

**Locating the SDK CLI.** In this order:

1. `ALLOWIT_SDK_CLI`, which must be an absolute path to the SDK's `native/cli.mjs` (a relative or missing path is refused, exit 3).
2. `native-sdk/cli.mjs` in the directory of the `allowit` executable, with symlinks resolved, so an install that ships the SDK beside the binary needs no configuration.

`ALLOWIT_NODE` names the Node 22 executable (default `node`, found on `PATH`).

**Invocation.** allowit runs `ALLOWIT_NODE SDK_CLI COMMAND [--json] [-- ARG...]` directly with Rust `std::process::Command`, never through a shell. Positional arguments follow `--` exactly as given; `--json` comes before `--` when requested. The SDK CLI inherits allowit's stdin, stdout, stderr and environment, so its output (Rust source, skill, explorer links, prompts) reaches the terminal unaltered and is not scrubbed by allowit. allowit exits with the SDK CLI's exit status, and for a non-zero status also prints `allowit: policy COMMAND: the SDK CLI exited with status N` on stderr. A child killed by a signal gives 128 + the signal number. An interrupt from the terminal reaches the SDK CLI directly; allowit waits for it to exit. If the SDK CLI cannot be found or started, allowit exits 3.

## States and exit codes

| Exit | State | Meaning |
|---|---|---|
| 0 | `passed` | eval: the policy permits the request. |
| 0 | `recorded` | Local dev exec: mock action recorded against the budget; no funds moved. |
| 0 | `settled` | Wallet transfer confirmed on chain. |
| 10 | `owner_signature` | Wallet transaction passed (or was submitted); the owner must sign in AllowIt or the network must confirm. |
| 10 | `ready` | Passed but the server did not say whether it is a judgment or a transaction; not complete. |
| 11 | `awaiting_input` | The owner must answer the printed question in AllowIt. |
| 12 | `pending` | Still evaluating after `--wait`. |
| 20 | `denied` | The policy refused; the reason is printed. |
| 2 | usage | Invalid flags or input; nothing sent. |
| 3 | config/auth/unsupported | Bad configuration, policy mismatch, untrusted TLS, redirect on `GET /skill`, HTTP 401/403 before a request is accepted, or a policy description that names another owner, policy or route, or an unknown network, profile or contract version. Nothing was sent to `judge` or `transactions`. |
| 4 | rejected | Server rejected the request (400/429) before accepting it; its message is printed. |
| 5 | uncertain | Network or server failure, an accepted request whose result could not be read, a `--request-id` already used with other details (HTTP 409), or a `status` that finds no request; follow the printed retry (same `--request-id`) or `allowit status` command. |
| 6 | `replayed` | exec/eval without `--request-id` matched an identical earlier request; nothing new was submitted. `replayedState` is its stored state. |

`status` reads by the server `requestId`, then by the client `--request-id` (`clientRequestId`); the returned request must carry the requested ID as one of them. It uses the server's `kind`: a ready `judgment` is `passed`, a ready `transaction` is `owner_signature`. All fields the server returns (reason, prompt, `decisionCode`, `workflowNodeId`, revision, source hash, receipt steps) are printed.

The configured token is redacted in full from all output, whatever its length. Its secret part must be 16–128 URL-safe characters.

## API used

`GET /api/harness/{owner}/{policy}/skill`, `POST …/judge`, `POST …/transactions`, `POST …/status`, with `Authorization: Bearer owner.policy.secret`. See `AllowIt-app/server/app/policy_requests.go` for validation.

## Server compatibility

The agent interface is exactly these four commands (`show`, `eval`, `exec`, `status`). `allowit policy` is the owner's tool, not the agent's; see [Owner policy lifecycle](#owner-policy-lifecycle). Otherwise policy creation, editing, allocation and owner approval stay in the AllowIt web app; the token cannot answer owner questions, sign or change the policy.

| Server | `/skill` shape | CLI behaviour |
|---|---|---|
| AllowIt backend with typed skill assembly (`server/app/skill.go`, `skill_contract.go`) | `title`, `policyId`, `owner`, absolute `endpoints`, `executionMode`, legacy `capabilities`, typed `contract` (profile, binding, capabilities, `contextU64Keys`). Results carry `kind`, `revision`, `sourceHash`. A policy whose skill cannot be assembled gets HTTP 409. | All checks above apply. `show` also prints the IR binding and the integer `context` fields the policy may read. On a 409, `show`/`eval`/`exec` stop with exit 4; `status` still reads existing requests. |
| Customer-workspace frontend server (AllowIt-app PR6) | `name`, `network`, `executionMode`, relative `endpoints`; no `title`, `policyId`, `owner`, `capabilities` or `contract`. Results omit `kind`, `revision` and `sourceHash`. | Supported as described: relative endpoints must resolve to the canonical routes and the network must be supported. A wallet policy allows `--rail solana --op transferUSDC` or plain USDC requests with `--action transfer` or `--action research`. Without `kind`, a `ready` status result is reported as `ready` (exit 10, not complete), never as passed or awaiting signature. |
| Older backends | No `endpoints`, `owner` or `contract`. | Supported as before, except that `--action` is now required. |

The CLI reports the server's states. It has not been exercised against live wallet settlement, and no paid service is delivered through this interface.

**Remaining backend handoff work** (none of it is in this CLI):

- Customer server: publish `policyId`, `owner`, absolute canonical `endpoints`, and the typed `contract` (profile, binding, capabilities) in `/skill`. Return `kind` in results so a ready `status` can be classified.
- Preserve the tested `executionMode` values (`local` and `owner_signed`); a new execution profile needs an explicit CLI implementation.
- Customer UI: explicit allocation activation, capability handoff, and the owner review and transaction path. Until those exist, `exec` on a wallet policy stops at `owner_signature`.
- Wiring the frontend server to the standalone SDK/engine is later work. The engine's `/v1` API takes trusted service credentials and signed owner bindings, so a harness token must never be sent to it. The adapter must also keep `eval` non-reserving, request identity, revisions, owner continuations and settlement evidence.
- The app's SKILL.md CLI adapter documents allowit `0.1.1`; update `cliVersion` there when this release is tagged.

The [pinned integration checks](integration/README.md) exercise both actual Go gateways and their Rust SDK runtimes without editing the app checkout. Run `make integration APP_REPO=/path/to/AllowIt-app` in addition to `make test` when both backend commits are available locally.

Skill format: [Agent Skills specification](https://agentskills.io/specification) and [best practices](https://agentskills.io/skill-creation/best-practices).
