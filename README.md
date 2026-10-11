# allowit

`allowit` is a native Rust CLI for AllowIt policies. Its HTTP commands send agent requests through the AllowIt service; its native policy commands use the pinned Rust SDK locally for generation, signing, receipt validation and recovery. The CLI cannot bypass the policy, owner approval or server request schema.

Tempo uses the separately versioned `allowit tempo` command set. Import the owner's exported executor bundle with `allowit tempo import EXECUTOR_JSON`, set `ALLOWIT_REQUEST_ID`, then request a plan with `allowit tempo execute RECIPIENT AMOUNT`. The CLI verifies the exact request, contract call and authority signature before returning the plan (exit 10); the designated executor signs through its own Tempo wallet. Report its hash with `allowit tempo submit REQUEST_ID TRANSACTION_HASH`, or recover with `allowit tempo status REQUEST_ID`. Only a verified receipt settles a payment. `allowit tempo help` documents configuration, owner-input waiting (exit 11), settled replay (exit 6) and uncertain outcomes. These commands read the policy-scoped capability, never an owner, executor or service private key.

The published Tempo SDK is verified from the same exact Git submodule commit as the native and policy libraries. Its complete crate inputs and enabled features are bound into release provenance. A separate local `ALLOWIT_TEMPO_REVIEW_MANIFEST` mode can review a new, uncommitted Tempo crate on the earlier supported SDK base; it binds that crate and the parent Cargo inputs to explicit SHA256 values. This local mode cannot replace a published Tempo crate or produce release provenance and license packages.

All commands call Rust modules directly. The binary needs no Node runtime. The Go implementation under `reference/go/` is a differential test oracle; the default command and distribution build use Rust. Its historical Go module path remains unchanged.

Main contains the untagged `0.3.0-dev` implementation. No native Rust GitHub Release has been published. The existing `v0.1.0` and `v0.1.1` tags identify earlier Go releases.

## Build from source

Use Rust 1.88 or later; CI pins Rust 1.98.0. Go is needed only for reference and integration tests.

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

**Local configuration.** `ALLOWIT_POLICY_DIR` defaults to `.allowit`; `ALLOWIT_POLICY_FILE` may select another policy file. `ALLOWIT_NETWORK`, `ALLOWIT_RPC_URL`, `ALLOWIT_MINT`, `ALLOWIT_EXECUTOR`, `ALLOWIT_AUTHORITY`, and `ALLOWIT_DEPLOYMENT_FILE` configure the native profile. Import persists a public context and refuses conflicting configuration. `ALLOWIT_OWNER_KEYPAIR` is used for owner operations, `ALLOWIT_EXECUTOR_KEYPAIR` for execution, and `ALLOWIT_OWNER` supplies the public owner for execution/status. Keys are private local files. `ALLOWIT_REQUEST_ID` is required for execution and is the durable operation ID. `ALLOWIT_EXECUTION_ACTION` defaults to `transfer`; `ALLOWIT_EXECUTION_MERCHANT` and one of `ALLOWIT_EXECUTION_CONTEXT_JSON` or `ALLOWIT_EXECUTION_CONTEXT_FILE` supply the exact policy input. Context is sent to the trusted backend, so do not put credentials in it. Only an explicitly additional fund/withdraw uses both a fresh ID and `ALLOWIT_ADDITIONAL_OWNER_OPERATION=1` after an expired uncertain operation.

**SDK source pin.** One Git submodule, `repos/AllowIt-hq--allowit-sdk` from `https://github.com/AllowIt-hq/allowit-sdk.git`, supplies four Cargo path dependencies: `allowit-native` (`native-rust/`), its `allowit-paysh-interface` (`crates/paysh-interface/`), the root `allowit-sdk` policy crate as `allowit-policy-sdk` with `default-features = false, features = ["std", "typed-workflow"]` for the canonical typed workflow types and host evaluator, without the compiler, and `allowit-tempo` (`tempo-rust/`) with no enabled features. The parent gitlink pins the exact SDK commit. `vendor/native-sdk.json` records that commit, the submodule path and URL, SHA-256 hashes of the consumed files of each crate (the policy crate's `Cargo.toml` and `src/` and the Tempo crate's complete input inventory), the native crate's unconsumed tooling, and the SDK root license files. The repository keeps no copies of SDK source or license text.

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
