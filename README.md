# allowit

`allowit` is a native Rust CLI for AllowIt policies. HTTP commands send agent requests through the AllowIt service. Native policy commands use the pinned Rust SDK for generation, signing, receipt validation and recovery. The CLI cannot bypass the policy, owner approval or server request schema.

## Build from source

Use Rust 1.98 or later; CI pins Rust 1.98.0. Go is needed only for reference and integration tests.

Native `policy` commands require a local POSIX filesystem for private, durable journals.
On Windows, use Linux/WSL and keep state in the Linux filesystem, not `/mnt/c` or `/mnt/d`.
The CLI refuses unsupported platforms before loading keys or creating policy state.
Keep existing journals for recovery. Do not regenerate or resubmit an uncertain operation.

```sh
git clone --recurse-submodules https://github.com/AllowIt-hq/allowit-cli.git
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

### Stellar contract-backed x402

`allowit stellar` is a native Rust buyer for Stellar x402 v2. It uses the pinned
AllowIt vault and policy contract identities, Circle USDC, and explicit detached
approval from a trusted operator. It does not use a managed wallet or a backend
Stellar endpoint. Use `allowit stellar help` for the configuration schema and
environment variables. Keys and private recovery journals require Linux/WSL
storage, with files at 0600 and directories at 0700.

```sh
allowit stellar import stellar-config.json
allowit stellar prepare 'https://agent402.tools/ENDPOINT?QUERY' --id purchase-001 --max-amount 0.01 --json
# Run only on the trusted operator's machine/key boundary:
ALLOWIT_STELLAR_AUTHORITY_KEY_FILE=/private/authority.hex allowit stellar authorize purchase-001 > approval.json
# The agent receives only the detached approval and executor key access:
ALLOWIT_STELLAR_EXECUTOR_KEY_FILE=/private/executor.hex allowit stellar call 'https://agent402.tools/ENDPOINT?QUERY' --id purchase-001 --max-amount 0.01 --approval approval.json --json
allowit stellar resume purchase-001 --json
# If the HTTP response lost its receipt, reconcile a known original chain hash:
allowit stellar resume purchase-001 --transaction ORIGINAL_HASH --json
```

The URL above is a placeholder; select a real paid Agent402 endpoint. `prepare`
validates the live network, deployed code hashes, vault state, exact quote,
amount conversion and Soroban authorization before saving the plan. `authorize`
prints a signature for that exact prepared operation and sends no payment. This
explicit operator attestation does not implement server semantic policy
evaluation. The agent must never have the authority key.

`call` saves the complete signed credential and a durable attempted marker
before its single paid HTTP request. Repeating the same ID preserves the URL,
maximum, quote and nonce. `resume` and `status` load no key and never send another
credential. Payment requires an independently verified exact Stellar receipt;
HTTP delivery is reported separately. A lost result stays uncertain until an
original transaction hash can be reconciled. `resume --transaction HASH` requires
a chain proof matching the exact saved credential and transfer. It does not
create a merchant response, sign or resend. Preserve the original journal instead
of creating a replacement purchase. All processes
using an executor must share its state directory. Another signed unresolved
request blocks new purchases.

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
allowit policy deploy 25                    # create, configure, fund and activate atomically
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
| `deploy`, `fund`, `withdraw` | One positive decimal `AMOUNT` (e.g. `5`, `0.25`). `deploy` includes this initial funding in the one setup transaction. |
| `execute` | `RECIPIENT` (a Solana token account address, checked offline) and a positive decimal `AMOUNT`. |
| `tune`, `tune-action` | One non-negative daily or per-action limit `VALUE`. |

Decimals are plain digits with an optional fraction: no sign, exponent, separator, leading zero or bare `.`, at most 40 characters. The SDK checks precision and limits. Every command accepts `--json`, which asks the SDK for a machine-readable result on stdout; any other flag is refused. Invalid arguments exit 2 before anything runs.

**Network.** Testnet by default. `ALLOWIT_NETWORK=solana:devnet` selects Devnet explicitly; configure its RPC as well. Mainnet is refused. Generate never signs. Execute needs `ALLOWIT_OWNER` (public key), the executor key, and the imported scoped server capability; the authority key remains server-side. Status needs no secret signing key. Owner keys stay on the owner device.

**Native lifecycle exits.** 0 settled/new generation or status, 5 uncertain, 6 replay of an earlier settled operation, 20 policy denial or finalized failure, 3 configuration. `ALLOWIT_REQUEST_ID` identifies a new intended operation; keep it unchanged for retries.

An expired unsigned server approval exits 3 with its original request ID and never requests an executor signature. The scoped executor endpoint returns that same stored approval on a retry; it cannot refresh it. Retain the original ID and approval, then have the owner authorize an explicit replacement before selecting a fresh ID. A settled `close` retry verifies and replays the saved receipt (exit 6) after the vault accounts disappear. A new close ID still requires a live vault, and a recreated vault uses its current instance instead of the old close receipt.

**Local configuration.** `ALLOWIT_POLICY_DIR` defaults to `.allowit`; `ALLOWIT_POLICY_FILE` may select another policy file. `ALLOWIT_NETWORK`, `ALLOWIT_RPC_URL`, `ALLOWIT_MINT`, `ALLOWIT_EXECUTOR`, `ALLOWIT_AUTHORITY`, and `ALLOWIT_DEPLOYMENT_FILE` configure the native profile. Import persists a public context and refuses conflicting configuration. `ALLOWIT_OWNER_KEYPAIR` is used for owner operations, `ALLOWIT_EXECUTOR_KEYPAIR` for execution, and `ALLOWIT_OWNER` supplies the public owner for execution/status. Keys are private local files. `ALLOWIT_REQUEST_ID` is required for execution and is the durable operation ID. `ALLOWIT_EXECUTION_ACTION` defaults to `transfer`; `ALLOWIT_EXECUTION_MERCHANT` and one of `ALLOWIT_EXECUTION_CONTEXT_JSON` or `ALLOWIT_EXECUTION_CONTEXT_FILE` supply the exact policy input. Context is sent to the trusted backend, so do not put credentials in it. Only an explicitly additional fund/withdraw uses both a fresh ID and `ALLOWIT_ADDITIONAL_OWNER_OPERATION=1` after an expired uncertain operation.

**SDK source pin.** One Git submodule, `repos/AllowIt-hq--allowit-sdk` from `https://github.com/AllowIt-hq/allowit-sdk.git`, supplies four Cargo path dependencies: `allowit-native` (`native-rust/`), its `allowit-paysh-interface` (`crates/paysh-interface/`), the root `allowit-sdk` policy crate as `allowit-policy-sdk` with `default-features = false, features = ["std", "typed-workflow"]` for the canonical typed workflow types and host evaluator, without the compiler, and `allowit-tempo` (`tempo-rust/`) with no enabled features. The parent gitlink pins the exact SDK commit. `vendor/native-sdk.json` records that commit, the submodule path and URL, SHA-256 hashes of the consumed files of each crate (the policy crate's `Cargo.toml` and `src/` and the Tempo crate's complete input inventory), the native crate's unconsumed tooling, and the SDK root license files. The repository keeps no copies of SDK source or license text.

The published Tempo SDK is verified from the same exact Git submodule commit as the native and policy libraries. Its complete crate inputs and enabled features are bound into release provenance. A separate local `ALLOWIT_TEMPO_REVIEW_MANIFEST` mode can review a new, uncommitted Tempo crate on the earlier supported SDK base; it binds that crate and the parent Cargo inputs to explicit SHA256 values. This local mode cannot replace a published Tempo crate or produce release provenance and license packages.

```sh
python3 scripts/sync-native-sdk.py verify              # run by make test/parity/build/dist, CI, provenance and license packaging
python3 scripts/sync-native-sdk.py update FULL_COMMIT  # check out an exact SDK commit, record and stage it
python3 scripts/sync-native-sdk.py pin                 # record and stage the checked-out submodule commit
```

`verify` requires the following:

- `.gitmodules` names only the canonical URL, the index holds a mode `160000` gitlink at the recorded commit, and the submodule is initialized and clean, including untracked and ignored files, with its `HEAD` at that commit.
- The three direct Cargo dependency lines match those above exactly, including the policy SDK's feature selection. Each consumed crate's tracked and checked-out file sets match the pinned Git tree and recorded hashes. The policy and Tempo crates may not have a build script; the Tempo crate's inventory also excludes nested Cargo configuration and symlinks.
- The SDK root's Cargo discovery inputs (`Cargo.toml`, `Cargo.lock` and everything under `.cargo/`) are regular files, not symlinks, and their file sets and bytes match the pinned commit's tree and blobs. They are checked but not separately recorded in the metadata.
- CLI-owned directories between the CLI root and SDK (currently `repos/`) are real directories, and their Cargo discovery inputs match the CLI's committed `HEAD`; today `HEAD` has none, so none may exist, even ignored. `verify` leaves the CLI root's own Cargo inputs available for ordinary development.
- Recorded crate and SDK license hashes match immutable Git blobs, and checked-out bytes match those same blobs. Files reached by `#[path]` or `include_str!` outside the hashed sets are bound by the clean submodule at the pinned commit.
- `cargo metadata --locked` resolves the four crates to the submodule's manifests and `src/lib.rs`, with no build script or `links`, and enables exactly the pinned features. A `paths` override in any Cargo configuration fails. Binary provenance repeats this check.

Hashes read CRLF as LF in text files, so a clean Windows `core.autocrlf` checkout verifies. Any other change fails, including one hidden by a local Git filter, `assume-unchanged`/`skip-worktree` or a replace ref. Inherited `GIT_*` variables are ignored. License packaging copies checked-out notices unchanged. `update` and `pin` hash commit blobs, refuse checkout drift, and stage the gitlink and metadata for review without committing.

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

Exits: 0 only when the API response was delivered; 12 pending (payment or delivery not complete, including `awaiting_input`, where the owner must answer in AllowIt Requests, and `owner_approved`, a signed Yes for this original request only that establishes no payment; keep the same `OPERATION_ID`); 20 failed, denied or expired, with no delivery (`expired` means the answer-and-start deadline passed; it is not an owner denial); 5 unknown (network or server failure, redirect, unreadable or mismatched reply, HTTP 409, a `status` that finds no operation, operation status `unknown`/`settlement_unknown`, a failed, denied or expired operation with any receipt other than a swap, or an expired operation with a signature that has no receipt: the operation remains unresolved and payment may have been sent, neither failed nor delivered); 2 usage; 3 configuration or auth. After exit 5, never use a new `OPERATION_ID` for the same call: run the printed `allowit paysh status` command or rerun the identical call. The capability is redacted from all output.

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

HTTP action commands use `GET /api/harness/{owner}/{policy}/skill` and `POST` routes for `judge`, `transactions` and `status`, with the policy-scoped bearer token. The frontend proxies this public API to the Rust backend in `AllowIt-hq/allowit-engine/crates/server/` (the engine's root `server/` is its deployment wrapper). The CLI does not link backend or engine crates.

The HTTP commands report server states and preserve owner approval. Native `policy execute` uses the executor's local key plus the trusted server authority signature and cannot sign owner operations. Owner withdrawal and closure never depend on the executor, authority, or semantic provider.

The [integration checks](integration/README.md) retain pinned Go gateways and their Rust SDK runtimes as compatibility fixtures. They do not represent a production deployment. Run `make integration APP_REPO=/path/to/AllowIt-app` alongside `make test` when both fixture commits are available locally.

## License and binary notices

First-party code is licensed under [MIT](LICENSE). Dependency licenses remain their own; [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES/README.md) contains the exact dependency notices and runtime attribution for current and historical workflow binaries. Keep this companion directory with downloaded binaries. New workflow artifacts include it with `LICENSE`, the checksum and provenance manifest. The SDK's own notices are copied unchanged from the verified submodule into `THIRD_PARTY_LICENSES/AllowIt-sdk/` at packaging time.

Skill format: [Agent Skills specification](https://agentskills.io/specification) and [best practices](https://agentskills.io/skill-creation/best-practices).
