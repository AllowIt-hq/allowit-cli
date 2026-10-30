<div align="center">

# allowit

*The command line your AI agent uses to spend within the policy you set.*

[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.98-orange?style=flat-square&logo=rust)](Cargo.toml)

**Go on. On your terms.**

[What it is](#what-it-is) • [Install](#install) • [First run](#first-run) • [Core commands](#core-commands) • [Wallets and policies](#wallets-and-policies) • [How it talks to the backend](#how-it-talks-to-the-backend) • [Documentation](#documentation)

</div>

Allowit lets your AI agents spend and invest, within a policy you set. `allowit` is the small native binary that an agent runs to do that: it asks the Allowit service whether an action is allowed, submits it, and reports back with a clear state and exit code. The policy, the owner's approval and the service's request schema always have the final say. The CLI cannot talk its way around any of them.

```sh
allowit eval  my-policy --request-id pay-001-eval --action transfer --rail solana --op transferUSDC --addr SOLANA_ADDRESS --amount 1
allowit exec  my-policy --request-id pay-001-exec --action transfer --rail solana --op transferUSDC --addr SOLANA_ADDRESS --amount 1
allowit status my-policy pay-001-exec --wait 60s
```

## What it is

An agent that can pay for things needs a careful tool between itself and the money. `allowit` is that tool.

- **One static binary.** Written in Rust, no Node or Python runtime needed. The CLI is a thin adapter over the pinned [Allowit SDK](https://github.com/AllowIt-hq/allowit-sdk) client facade, which owns command orchestration, receipt validation and recovery.
- **Policy first.** `eval` asks "may I?" and spends nothing. `exec` submits the request. `status` recovers whatever happened. Every answer comes with a stable state and exit code your agent can branch on.
- **Secrets stay put.** Tokens are read from the environment only, never from flags or URLs. They are scrubbed from everything the CLI prints. Agent keys are generated locally with private file modes and never leave the machine.
- **Safe by default on the wire.** HTTPS origins only (plain HTTP just for localhost), no redirects, a 60 s timeout, and bounded request and response sizes.
- **Built for retries.** Every operation carries a request ID. Retry with the same ID and you get the stored result back, never a second payment.
- **Owner lifecycle too.** `allowit policy` generates, deploys, funds, tunes and closes a policy vault through the native Rust SDK, with owner keys staying on the owner's device.

## Install

You need Rust 1.98 or later (CI pins 1.98.0) and Python 3 for the pinned-SDK check. Go is needed only for the reference and integration tests.

```sh
git clone --recurse-submodules https://github.com/allowit-hq/allowit-cli.git
cd allowit-cli
python3 scripts/sync-native-sdk.py verify
cargo build --locked --release
./target/release/allowit version
```

Copy `target/release/allowit` anywhere on your `PATH`. The lockfile pins the complete dependency graph, so `--locked` builds are reproducible.

If you already have a clone, or you switch to a revision that pins another SDK commit, refresh the submodule first:

```sh
git submodule update --init --recursive
```

> [!NOTE]
> Native `policy` commands keep private, durable journals on disk and need a local POSIX filesystem. On Windows, use WSL and keep state in the Linux filesystem rather than `/mnt/c`.

## First run

Allowit gives each policy a harness token for its agent. Put the service origin and that token in the environment:

```sh
export ALLOWIT_URL='https://app.allowit.xyz'    # exact service origin (this is also the default)
export ALLOWIT_TOKEN='owner.policy.secret'      # the policy's harness token
# optional: export ALLOWIT_CA_FILE=/path/extra-roots.pem
```

Then look at what the policy lets you do:

```sh
allowit show my-policy            # policy, network, budget, rails, checks, original request
allowit show my-policy --json     # the same as a machine contract, credentials removed
```

A few rules keep this safe:

- `ALLOWIT_URL` must be `https://host[:port]` with no path, query, fragment or credentials. Plain `http` is accepted only for `localhost` and loopback addresses.
- The `POLICY` argument must match the token's policy, or the CLI stops before sending anything.
- Redirects are never followed, so the `Authorization` header cannot leave the origin.
- Requests time out after 60 s. Requests are capped at 64 KB and responses at 2 MB.

Run `allowit help` at any time for the full command summary.

## Core commands

| Command | What it does | Spends? |
|---|---|---|
| `allowit show POLICY [--json] [--source]` | Describe the policy and the execution profile the service supports. | No |
| `allowit eval POLICY [request flags]` | Ask whether the policy permits a request. Calls `/judge`. | No |
| `allowit exec POLICY [request flags]` | Submit the request. Calls `/transactions`. | Yes, if allowed |
| `allowit status POLICY REQUEST_ID [--wait 60s] [--json]` | Read the stored result of an earlier request. | No |
| `allowit version` | Print the CLI version. | No |

### Request flags

`eval` and `exec` take the same flags. `--action` is required; everything else describes the transfer.

```sh
allowit eval my-policy --request-id dataset-001-eval \
  --action research --rail stellar --op transferXLM --addr G... --amount 5 \
  --context '{"decision":"Buy dataset","evidence":{"source":"https://...","observed_at":"2026-09-28T12:00:00Z"}}'
```

| Flag | Meaning |
|---|---|
| `--action NAME` | **Required.** The action the policy evaluates, sent exactly as given, for example `transfer` or `research`. |
| `--rail solana\|stellar --op transferSOL\|transferXLM\|transferUSDC` | The transfer on a rail. Always given together. `--op` is transport only and is never sent as the action. |
| `--addr ADDRESS` | Recipient: Solana base58 or Stellar G/M/C strkey. Checked offline, then again by the server. |
| `--amount DECIMAL` | Exact decimal quantity of the transferred asset. Without `--rail` and `--op`, the USDC amount. |
| `--merchant NAME` | Optional merchant. |
| `--context JSON\|@file\|-` | Runtime context object, forwarded as the exact JSON value. At most 16 KB, depth 8 and 128 values. |
| `--request-id ID` | Explicit client request ID, 8 to 100 characters. Strongly recommended. |
| `--budget DECIMAL` | Assert the computed USDC charge before sending. |
| `--wait DURATION` | How long to wait for a pending evaluation. Default `60s` for `eval`/`exec`, `0s` for `status`. |
| `--json` | Machine-readable output. |

For an ID that begins with `-`, put `--` before `POLICY` (and before `REQUEST_ID` for `status`).

### Request IDs and retries

Give each intended operation its own `--request-id`, with separate IDs for `eval` and `exec`. Retrying with the same ID and the same details returns the stored result; changed details are rejected. Network failures and HTTP 502/503/504 are retried twice with the same body.

When the CLI exits **5 (uncertain)**, payment may have happened. Never pick a new ID. Rerun the identical command, or check it with `allowit status`, which accepts either the server `requestId` or your `--request-id`.

### Exit codes

| Exit | State | Meaning |
|---|---|---|
| 0 | `passed`, `recorded`, `settled` | Allowed, mock-recorded, or confirmed on chain. |
| 2 | usage | Invalid flags or input. Nothing was sent. |
| 3 | config/auth | Bad configuration, policy mismatch, untrusted TLS or an unsupported policy description. Nothing was sent. |
| 4 | rejected | The server rejected the request (400/429) before accepting it. |
| 5 | uncertain | Network or server failure, an unreadable result, or an ID reused with other details. Retry only as printed. |
| 6 | `replayed` | A derived request ID matched an identical earlier request. Nothing new was submitted. |
| 10 | `owner_signature`, `ready` | Passed, but the owner must sign or the network must confirm. |
| 11 | `awaiting_input` | The owner must answer the printed question in Allowit. |
| 12 | `pending` | Still evaluating after `--wait`. |
| 20 | `denied` | The policy refused. The reason is printed. |

The full validation and recovery rules are in [Commands](docs/commands.md) and the [HTTP API contract](docs/http-api.md).

## Wallets and policies

### Local agent wallets

Agents hold their own keys. `allowit wallet` creates and inspects them without ever printing a secret:

```sh
allowit wallet generate --network solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1 --output /private/path/agent.json
allowit wallet show --network solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1 /private/path/agent.json
```

The parent directory must be private (`0700`). New key files are `0600` and never overwrite an existing key. Solana uses its native JSON keypair, Tempo a hex key and Stellar a StrKey seed. Output contains public metadata only, which is what `setup` registers with the server. Remote key generation, secret import and secret export are refused. `--network` takes an x402 CAIP-2 identifier.

### Owner policy lifecycle

`allowit policy` drives a policy vault through the pinned native Rust SDK. It needs no `ALLOWIT_TOKEN` and does not read `ALLOWIT_URL`.

```sh
allowit policy generate "Spend up to 5 test tokens per day"   # prints the generated Rust policy source
allowit policy deploy 25           # prints the owner browser signing link
allowit policy fund 25             # prints the transaction's explorer link
allowit policy execute RECIPIENT_TOKEN_ACCOUNT 1.5
allowit policy status
allowit policy tune 0.5            # daily limit
allowit policy tune-action 0.25    # per-action limit
allowit policy withdraw 10
allowit policy revoke
allowit policy close
allowit policy help
```

Testnet is the default; `ALLOWIT_NETWORK=solana:devnet` selects Devnet and mainnet is refused. `generate` never signs. Deployment opens a browser handoff so the owner signs on their own device; the CLI never loads an owner key for it. Every command accepts `--json`. See [Policies](docs/policy.md) for configuration, Stellar execution and hosted execution authorization.

### More rails and services

- **Tempo** vault payments and paid API calls: `allowit tempo`, documented in [Tempo usage](docs/tempo.md).
- **PaySH** operations on Solana: `allowit paysh`, documented in [PaySH](docs/paysh.md).
- **Account and service commands** (`call`, `curl`, `mcp`, `claude`, `codex`, `whoami`, `skills`, `catalog` and friends): [Service commands](docs/services.md).

## How it talks to the backend

Every action command speaks to the Allowit service over a small, policy-scoped HTTP API:

```
GET  /api/harness/{owner}/{policy}/skill          describe the policy
POST /api/harness/{owner}/{policy}/judge          eval: check permission, spend nothing
POST /api/harness/{owner}/{policy}/transactions   exec: bind the request ID, evaluate, reserve, create an owner review
POST /api/harness/{owner}/{policy}/status         status: return the existing request
```

The bearer token is the policy's harness token. The CLI reads `/skill` first and checks that the published owner, policy ID, routes, network and execution profile all agree with the token before it sends anything that could spend. The frontend at [app.allowit.xyz](https://app.allowit.xyz) proxies this public API to the Rust backend, the Allowit engine. The CLI does not link engine crates; it only speaks HTTP.

Owner approval lives on the server side of that line. The CLI reports server states and preserves them. Native `policy execute` combines the executor's local key with the trusted server authority signature, and cannot sign owner operations. Owner withdrawal and closure never depend on the executor or the authority.

When `ALLOWIT_TOKEN` starts with `allowit-stellar-v1.`, the CLI switches to the Stellar execution profile: it decodes the token, signs requests locally and submits a typed request file with `allowit exec POLICY --request-file request.json`. Details are in [Policies](docs/policy.md#stellar-execution).

## Project structure

```
src/                 Thin executable adapter; the SDK client facade owns the commands
repos/AllowIt-hq--allowit-sdk/   Pinned Allowit SDK Git submodule (the only runtime dependency)
docs/                Command, policy, HTTP API, Tempo, PaySH, service and build reference
tests/               Rust integration tests (native, network, Stellar, PaySH, parity, vendor)
reference/go/        Earlier Go implementation, kept as a differential test oracle
integration/         Gateway compatibility checks against pinned backend fixtures
scripts/             SDK pin verification, license packaging and provenance tooling
vendor/              Recorded first-party dependency graph for the SDK pin
THIRD_PARTY_LICENSES/   Dependency notices shipped with every binary
```

## Development

```sh
make test                                   # Rust tests, lints and Go reference regressions
make parity                                 # original harness cases against the Rust binary
make integration APP_REPO=/path/to/AllowIt-app
make dist                                   # static Linux/musl distribution with checksum and licenses
```

`make dist` needs the `x86_64-unknown-linux-musl` target and a musl linker. Build, distribution, binary provenance and the SDK source pin are described in [Build and distribution](docs/build.md).

## Allowit

`allowit-cli` is one piece of the Allowit system:

- [allowit-sdk](https://github.com/AllowIt-hq/allowit-sdk): the restricted Rust policy language, compiler, evaluator and the client facade this CLI wraps.
- [allowit-contracts-solana](https://github.com/AllowIt-hq/allowit-contracts-solana), [allowit-contracts-stellar](https://github.com/AllowIt-hq/allowit-contracts-stellar) and [allowit-contracts-tempo](https://github.com/AllowIt-hq/allowit-contracts-tempo): the on-chain policy vaults.
- The Allowit engine and the app at [app.allowit.xyz](https://app.allowit.xyz): where owners write policies, approve requests and issue tokens.

Learn more at [allowit.xyz](https://allowit.xyz).

## Documentation

- [Commands](docs/commands.md): request flags, budget charges, replays, uncertain results and exit codes in full.
- [Policies](docs/policy.md): owner lifecycle configuration, Stellar execution, wallets and hosted execution authorization.
- [HTTP API contract](docs/http-api.md): exactly what the CLI validates in every response.
- [Tempo usage](docs/tempo.md) and [PaySH](docs/paysh.md).
- [Service commands](docs/services.md).
- [Build and distribution](docs/build.md): toolchains, workflows, provenance, the SDK source pin and licenses.
- [Gateway compatibility checks](integration/README.md).

## Contributing

Issues and pull requests are welcome. Run `make test` before opening a pull request, keep `cargo fmt` and `clippy` clean, and keep the SDK pin verified with `python3 scripts/sync-native-sdk.py verify`. Plans, reviews and run evidence live in the project knowledge repository, not here.

## License

First-party code is licensed under [MIT](LICENSE). Dependency licenses remain their own; [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES/README.md) carries the exact notices for every binary built from this repository. Keep that directory with any binary you redistribute.
