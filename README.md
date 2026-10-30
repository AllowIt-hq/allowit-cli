# allowit

`allowit` is a native Rust CLI for Allowit policies. HTTP commands send agent requests through the Allowit service. Commands use the pinned Rust SDK client facade for orchestration, vendor selection, receipt validation and recovery. Agent keys are generated and retained locally. The CLI cannot bypass the policy, owner approval or server request schema.

[Service commands](docs/services.md) cover direct account calls, policy revisions, HTTP tools,
native Claude/Codex sessions, MCP, account controls and registered seller resources.

## Build from source

Use Rust 1.98 or later; CI pins Rust 1.98.0. Go is needed only for reference and integration tests.

Native `policy` commands require a local POSIX filesystem for private, durable journals.
On Windows, use Linux/WSL and keep state in the Linux filesystem, not `/mnt/c` or `/mnt/d`.
The CLI refuses unsupported platforms before loading keys or creating policy state.
Keep existing journals for recovery. Do not regenerate or resubmit an uncertain operation.

```sh
git clone --recurse-submodules https://github.com/allowit-hq/allowit-cli.git
cd allowit-cli
python3 scripts/sync-native-sdk.py verify
cargo build --locked --release
./target/release/allowit version
```

The SDK is the `repos/AllowIt-hq--allowit-sdk` Git submodule. In an existing clone, or after switching to a revision with another SDK pin, run:

```sh
git submodule update --init --recursive
```

Validation and distribution builds:

```sh
make test                             # Rust tests + Go reference regressions
make parity                           # original harness cases against Rust
make integration APP_REPO=/path/to/AllowIt-app
make dist                             # static Linux/musl distribution
```

`make dist` requires the `x86_64-unknown-linux-musl` target and a suitable musl linker. CI installs both and uploads `dist/allowit-linux-amd64` with its SHA-256. The lockfile pins the complete dependency graph.

The **Native binaries** workflow validates PRs and supports manual builds of Linux x64 (static musl), macOS Apple Silicon and macOS Intel, with checksums and a source-free smoke test whose PATH has no Node installation. It uploads workflow artifacts; it does not publish a GitHub Release. Windows is not yet validated. Distribution checks must pass for the exact release revision before a release is accepted.

The CLI is independent of the optional hosted-agent runtime. A host can install the same binary used by an external agent; this repository contains no sandbox launcher, supervisor or model proxy.

Each **Native binaries** artifact also includes `allowit-PLATFORM.provenance.json` (schema version 1, kind `rust-native`). It records the binary target and SHA-256, exact CLI commit and source tree, the SDK submodule path, canonical URL, pinned commit and consumed file hashes, and native contract release identity. It is written only after the shared SDK verifier passes and the CLI root's Cargo inputs match the committed source (see **SDK source pin**). Staging consumers should select a trusted workflow run, verify the binary checksum against this manifest, and compare the release identity with their backend before executing a downloaded skill. The manifest describes the workflow build; it is not a signature or a standalone attestation from an arbitrary download.

All commands call Rust modules directly. The binary needs no Node runtime. The Go implementation under `reference/go/` is a differential test oracle; the default command and distribution build use Rust. Its historical Go module path remains unchanged.

Main contains the untagged `0.3.0-dev` implementation. No native Rust GitHub Release has been published. The existing `v0.1.0` and `v0.1.1` tags identify earlier Go releases.

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

For IDs beginning with `-`, place `--` before `POLICY` (and `REQUEST_ID` for `status`). Flags may follow these identifiers.

USDC transfer with the customer-workspace template (`transfer` and `research` actions):

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

**Budget charge.** Local dev uses integer arithmetic: `ceil_to_0.000001(quantity × rate) + Σ maxCostUSDC`. `/skill` publishes test rates: SOL 100, XLM 0.1, USDC 1.

**Actions.** Missing `--action` exits 2 before sending. To retry a 0.1.1 request that omitted it, set `--action` to its original `--op`. Keep every other flag. Explicit actions retain the same request body and derived ID.

**Request IDs.** Give each operation its own `--request-id`, including separate IDs for `eval` and `exec`. Retry unchanged with the same ID. The server returns the stored result and rejects changed details. Without this flag, identical purchases share a derived ID. It hashes owner, policy, command and exact request (plan, not rate-derived charge, for Local dev). Policy revision, source hash and test rates do not affect it. The CLI prints the ID and budget charge on stderr before sending. Network failures and HTTP 502/503/504 retry twice with the same body.

**Uncertain results (exit 5).** Payment may have occurred. Never choose a new ID. Follow the printed retry or status command:

- Without an answer, rerun unchanged with the printed `--request-id`. Changed details, including a changed charge, leave the original unresolved. Check `status`.
- After acceptance, an unreadable result prints both client and server IDs. Run `allowit status --wait 60s -- POLICY ID` with either ID, or retry with the client ID. If neither ID resolves, the exec may still be in flight. Rerun that identical exec.

**Replays.** Stored results carry `replayed: true`. Explicit-ID retries retain the stored state and exit code. Derived-ID repeats return `state: replayed`, exit 6 and `replayedState`. Neither submits anything new.

**Input and output.** Duplicate request flags exit 2. Multiline server text prints as one quoted value. `--context` requires one JSON object: maximum 16 KB, depth 8 and 128 values. Repeated keys and top-level `allowitExecution` are forbidden. The server applies the same limits.

**Protocol checks.** The CLI checks `/skill`, canonical routes, networks and response states. Inconsistent responses remain uncertain. `status` can recover without a usable policy description, subject to authentication, routing and state checks. It never resends `judge` or `transactions`. See [HTTP API contract](docs/http-api.md) for exact validation and recovery rules.

## Owner policy lifecycle

`allowit policy` calls the pinned `allowit-native` Rust SDK library. The SDK generates policy parameters, signs locally, keeps its durable journal and talks to the network. These commands need no `ALLOWIT_TOKEN` and do not read `ALLOWIT_URL`. The CLI has no Node runtime or subprocess adapter.

```sh
allowit policy generate "Spend up to 5 test tokens per day"   # prints the generated Rust source
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
| `status`, `revoke`, `close` | None. |
| `deploy`, `fund`, `withdraw` | One positive decimal `AMOUNT` (e.g. `5`, `0.25`). `deploy` binds this initial funding in the browser signing intent. |
| `execute` | `RECIPIENT` (a Solana token account address, checked offline) and a positive decimal `AMOUNT`. |
| `tune`, `tune-action` | One non-negative daily or per-action limit `VALUE`. |

Decimals are plain digits with an optional fraction: no sign, exponent, separator, leading zero or bare `.`, at most 40 characters. The SDK checks precision and limits. Every command accepts `--json`, which asks the SDK for a machine-readable result on stdout; any other flag is refused. Invalid arguments exit 2 before anything runs.

**Network.** Testnet by default. `ALLOWIT_NETWORK=solana:devnet` selects Devnet explicitly; configure its RPC as well. Mainnet is refused. Generate never signs. Execute needs `ALLOWIT_OWNER` (public key), the executor key, and the imported scoped server capability; the authority key remains server-side. Status needs no secret signing key. Owner keys stay on the owner device.

**Native lifecycle exits.** 0 settled/new generation or status, 5 uncertain, 6 replay of an earlier settled operation, 20 policy denial or finalized failure, 3 configuration. `ALLOWIT_REQUEST_ID` identifies a new intended operation; keep it unchanged for retries.

An expired unsigned server approval exits 3 with its original request ID and never requests an executor signature. The scoped executor endpoint returns that same stored approval on a retry; it cannot refresh it. Retain the original ID and approval, then have the owner authorize an explicit replacement before selecting a fresh ID. A settled `close` retry verifies and replays the saved receipt (exit 6) after the vault accounts disappear. A new close ID still requires a live vault, and a recreated vault uses its current instance instead of the old close receipt.

**Local configuration.** `ALLOWIT_POLICY_DIR` defaults to `.allowit`; `ALLOWIT_POLICY_FILE` may select another policy file. `ALLOWIT_NETWORK`, `ALLOWIT_RPC_URL`, `ALLOWIT_MINT`, `ALLOWIT_EXECUTOR`, `ALLOWIT_AUTHORITY`, and `ALLOWIT_DEPLOYMENT_FILE` configure the native profile. Import persists a public context and refuses conflicting configuration. `ALLOWIT_OWNER_KEYPAIR` is used for local owner operations other than deployment. `ALLOWIT_EXECUTOR_KEYPAIR` is used for execution. `ALLOWIT_OWNER` supplies the public owner for browser deployment and execution/status. Deployment never loads an owner private key. Keys are private local files. `ALLOWIT_REQUEST_ID` is required for execution and is the durable operation ID. `ALLOWIT_EXECUTION_ACTION` defaults to `transfer`; `ALLOWIT_EXECUTION_MERCHANT` and one of `ALLOWIT_EXECUTION_CONTEXT_JSON` or `ALLOWIT_EXECUTION_CONTEXT_FILE` supply the exact policy input. Context is sent to the trusted backend, so do not put credentials in it. Only an explicitly additional fund/withdraw uses both a fresh ID and `ALLOWIT_ADDITIONAL_OWNER_OPERATION=1` after an expired uncertain operation.

**SDK source pin.** The CLI has one runtime dependency, `allowit-client`, from the pinned SDK submodule.
The facade links Tempo and Solana vendor crates at exact Git revisions. Vendors depend on shared core functions.
The Tempo implementation lives in `allowit-contracts-tempo/rust`; PaySH lives in `allowit-contracts-solana/crates/solana-vendor`.
`vendor/native-sdk.json` binds the resolved first-party graph, source files, features and licenses.

The published Tempo vendor is verified at its exact canonical Git revision. The SDK's `tempo-rust` compatibility
package reexports that vendor. Current schema 2 attests the resolved facade, vendors and core package graph.
The `ALLOWIT_TEMPO_REVIEW_MANIFEST` mode applies only to the historical schema 1 fixture and earlier SDK base.
It cannot produce current release provenance or license packages.

```sh
python3 scripts/sync-native-sdk.py verify              # run by make test/parity/build/dist, CI, provenance and license packaging
python3 scripts/sync-native-sdk.py update FULL_COMMIT  # check out an exact SDK commit, record and stage it
python3 scripts/sync-native-sdk.py pin                 # record and stage the checked-out submodule commit
```

`verify` checks the canonical SDK gitlink and immutable first-party Cargo graph. The CLI's only runtime dependency
is the SDK facade. The graph includes the facade, shared client core, policy core, native Solana library,
Stellar library, Tempo vendor and Solana vendor. Each package resolves to its recorded canonical repository,
exact revision, source inventory, enabled features and license text. First-party build scripts, `links`,
Cargo path overrides, discovery changes and source substitutions fail verification.

Checked-out files must match immutable Git blobs. The verifier rejects hidden source changes, local Git filters,
index flags and replacement refs. Cargo discovery inputs between the CLI root and SDK remain bound.
`pin` records the checked-out clean SDK revision and stages the gitlink and graph metadata together.
License packaging includes the unchanged first-party and registry notices.

Binary provenance additionally requires a clean parent status and binds the CLI root's Cargo inputs to committed `HEAD`, including ignored files and changes hidden by index flags. Generated `target/` and `dist/` stay ignored. These checks cover Cargo discovery from the SDK crate through the CLI root. Directories above the CLI checkout, `CARGO_HOME`, environment variables and the Rust toolchain are trusted build context; they are neither checked nor recorded.

**Hosted execution authorization.** A backend-exported executor bundle contains `audit: {origin, token}`. Import saves this policy-scoped capability in the private local journal. The CLI sends only the high-level action, merchant, context, recipient and amount to `POST /api/native/execute`; the backend evaluates the owner-bound policy and returns an authority-only signature over its exact prepared transaction. The CLI reconstructs and checks the approval commitment, signer set, instructions and message, adds only the executor signature, persists the complete proof, then requires a durable `POST /api/native/report` acknowledgment before chain broadcast. Identical retries reconcile the saved proof without obtaining another approval or allocating another payment. Missing, redirected or inconsistent responses block broadcast or produce exit 5. `policy status` retries reporting without signing or broadcasting. The token is never printed; the executor bundle and journal contain this private capability and must not be shared publicly. Denial, unresolved owner input, or a required provider failure produces no execution signature. Owner operations remain independent of the provider and authority.

## Tempo payments and API calls

Use `allowit tempo` with an owner-exported executor bundle for native vault payments and paid API requests. See [Tempo usage](docs/tempo.md) for configuration, commands and recovery.

## PaySH agent calls

`allowit paysh` serves operations recorded under an existing PaySH policy and its scoped capability. Do not deploy a separate PaySH policy or export a new capability for it. The backend journal keeps each original operation; recovery uses the same `POLICY`, `OPERATION_ID` and, for `call`, the identical `SERVICE_ID` and input. The agent sets `ALLOWIT_URL` and `ALLOWIT_PAYSH_TOKEN`; no signing key is read.

```sh
allowit paysh services
allowit paysh call POLICY OPERATION_ID SERVICE_ID '{"location":{"latitude":43.6532,"longitude":-79.3832},"universalAqi":true}'
allowit paysh status POLICY OPERATION_ID
```

`call` sends `POST /api/paysh/call` with `{policyId, operationId, serviceId, input}` and the capability as bearer; `status` sends `POST /api/paysh/status` with `{policyId, operationId}`; `services` sends `GET /api/paysh/catalog` without credentials and lists either the public catalog's `providers` or a cooperating backend's `{profile: "cooperating-v1", services}`; a cooperating price is shown as test-token units only on `solana:testnet`, never as USD or USDC, and a malformed list exits 3. Each request is sent once with no redirect. `ALLOWIT_URL` must be an HTTPS origin, or HTTP on loopback. `INPUT_JSON` is limited to 4096 bytes and replies to 1 MiB. Payment and delivery are printed separately; `--json` adds `state` and `exitCode` to the server reply.

Exits: 0 only when the API response was delivered; 12 pending (payment or delivery not complete, including `awaiting_input`, where the owner must answer in Allowit Requests, and `owner_approved`, a signed Yes for this original request only that establishes no payment; keep the same `OPERATION_ID`); 20 failed, denied or expired, with no delivery (`expired` means the answer-and-start deadline passed; it is not an owner denial); 5 unknown (network or server failure, redirect, unreadable or mismatched reply, HTTP 409, a `status` that finds no operation, operation status `unknown`/`settlement_unknown`, a failed, denied or expired operation with any receipt other than a swap, or an expired operation with a signature that has no receipt: the operation remains unresolved and payment may have been sent, neither failed nor delivered); 2 usage; 3 configuration or auth. After exit 5, never use a new `OPERATION_ID` for the same call: run the printed `allowit paysh status` command or rerun the identical call. The capability is redacted from all output.

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

The configured token is redacted in full from all output, whatever its length. Its secret part must be 16–128 URL-safe characters.

## API used

HTTP action commands use `GET /api/harness/{owner}/{policy}/skill` and `POST` routes for `judge`, `transactions` and `status`, with the policy-scoped bearer token. The frontend proxies this public API to the Rust backend in `allowit-hq/allowit-engine/crates/server/` (the engine's root `server/` is its deployment wrapper). The CLI does not link backend or engine crates.

The HTTP commands report server states and preserve owner approval. Native `policy execute` uses the executor's local key plus the trusted server authority signature and cannot sign owner operations. Owner withdrawal and closure never depend on the executor, authority, or semantic provider.

The [integration checks](integration/README.md) retain pinned Go gateways and their Rust SDK runtimes as compatibility fixtures. They do not represent a production deployment. Run `make integration APP_REPO=/path/to/AllowIt-app` alongside `make test` when both fixture commits are available locally.

## License and binary notices

First-party code is licensed under [MIT](LICENSE). Dependency licenses remain their own; [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES/README.md) contains the exact dependency notices and runtime attribution for current and historical workflow binaries. Keep this companion directory with downloaded binaries. New workflow artifacts include it with `LICENSE`, the checksum and provenance manifest. The SDK's own notices are copied unchanged from the verified submodule into `THIRD_PARTY_LICENSES/AllowIt-sdk/` at packaging time.

Skill format: [Agent Skills specification](https://agentskills.io/specification) and [best practices](https://agentskills.io/skill-creation/best-practices).

## Stellar execution

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

This mode activates when `ALLOWIT_TOKEN` starts with `allowit-stellar-v1.`. Scalar request flags and curl requests are not part of this Stellar transfer profile.

## Local agent wallet preparation

```sh
allowit wallet generate --network solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1 --output /private/path/agent.json
allowit wallet show --network solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1 /private/path/agent.json
```

The parent directory is private (0700). New secret files are 0600 and never replace existing keys.
Solana uses its native JSON keypair, Tempo uses hex and Stellar uses a StrKey seed. Output contains public metadata only.
Use that metadata for `setup`; remote account key generation, secret import and secret export are refused.
Server validation and the server's independent authority do not require the agent's private key.

`--network` accepts x402 CAIP-2 identifiers and must match the wallet or deployment.
An ambiguous address cannot select a network. Tempo generic execution accepts only its bound token-transfer operation.

Solana Devnet `policy deploy` requires the public owner and configured public wallet roles, plus `ALLOWIT_REQUEST_ID`.
It prints a browser link and the intent fingerprint, then exits 10. Compare that fingerprint in the browser before signing.
The browser requires the exact source, network, amount, deployment, mint, executor and authority.
The backend's configured executor public key must match the CLI agent key. A mismatch fails before signing.
A signing link does not establish a finalized deployment. Other rail lifecycle restrictions remain explicit.

For an authoritatively expired unsigned browser preparation, choose a new `ALLOWIT_REQUEST_ID` and set
`ALLOWIT_RETRY_PREPARATION_OF` to the original preparation ID. The browser checks explicit replacement permission.
Signed uncertain transactions retain their original proof and are never replaced through this option.
