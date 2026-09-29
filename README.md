# allowit

`allowit` sends an agent's actions through an AllowIt policy. It is a thin, strict client for one policy's harness API; the policy itself (restricted Rust, evaluated by the shared SDK WASM on the AllowIt server) decides. The CLI cannot bypass the policy, the owner-input gate or the server's request schema.

Go, standard library only.

## Install

`github.com/ackrate/allowit-cli` is private; installing needs authorized GitHub access. There is no public download.

```sh
GOPRIVATE=github.com/ackrate/* go install github.com/ackrate/allowit-cli/cmd/allowit@VERSION   # release tag or commit
allowit version
```

Or build from a checkout:

```sh
make test                 # vet + race tests
make dist                 # dist/allowit-linux-amd64 (+ .sha256), static, reproducible
go build -o allowit ./cmd/allowit   # host binary
```

`make dist` builds with `CGO_ENABLED=0 -trimpath -ldflags="-s -w -buildid="`, so the same Go toolchain produces a byte-identical binary. CI uploads it as the `allowit-linux-amd64` artifact.

The hosted AllowIt agent VM has the CLI preinstalled: the app builds it from vendored source at deploy time and copies it into the sandbox. No GitHub credentials exist there.

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

`eval` calls `/judge`: it checks permission and never spends or reserves budget. `exec` calls `/transactions`.

| Flag | Meaning |
|---|---|
| `--rail solana\|stellar`, `--op transferSOL\|transferXLM\|transferUSDC` | Transfer on a rail. Local dev: Solana SOL/USDC, Stellar XLM/USDC (mock plan). Wallet networks: `--rail solana --op transferUSDC` only. |
| `--addr` | Recipient (Solana base58 or Stellar G/M/C strkey), checked offline and again by the server. |
| `--amount` | Asset quantity as an exact decimal (USDC amount without `--op`). |
| `--action`, `--merchant` | Policy action label (default: the op) and optional merchant. |
| `--context JSON\|@file\|-` | Runtime context object. Forwarded as the exact JSON value; numbers are never converted. |
| `--memo`, `--data TEXT\|@file` | Local dev plan memo and payload bytes (base64-encoded by the CLI). |
| `--before`, `--after JSON\|@file` | Local dev contract calls: `[{"type":"contract_call","contract":"...","method":"...","args":{},"maxCostUSDC":"0"}]`. |
| `--request-id` | Explicit client request ID (8–100 chars). |
| `--budget` | Assert the computed USDC charge. |
| `--json` | Machine-readable output. |

**Budget charge.** For Local dev plans the CLI computes the USDC charge the server requires, exactly (`math/big`): `ceil_to_0.000001(quantity × rate) + Σ maxCostUSDC`, with the fixed test rates published by the server's `/skill` response (SOL 100, XLM 0.1, USDC 1).

**Request IDs.** Give every intended operation its own `--request-id`, and use different IDs for `eval` and `exec` (e.g. `dataset-001-eval`, `dataset-001-exec`). To retry the same request, rerun it unchanged with the same ID: the server returns the stored result instead of applying it again, and rejects the ID if any detail changed. Without `--request-id` the ID is a hash of the owner, policy, revision, source hash, command and exact request, so an accidental retry is safe but a deliberate identical second purchase collapses into the first. Network failures and 502/503/504 are retried twice with the same body. If the outcome is still unknown the CLI exits 5 and prints the ID — rerun the identical command.

**Context.** `--context` must be a single JSON object of at most 16 KB, depth 8 and 128 values, with no repeated keys and no top-level `allowitExecution` (AllowIt supplies that field). The server enforces the same limits.

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
| 3 | config/auth | Bad configuration, policy mismatch, untrusted TLS, redirect, HTTP 401/403. |
| 4 | rejected | Server rejected the request (400/404/409/429); its message is printed. |
| 5 | uncertain | Network or server failure; rerun the identical command. |

`status` uses the server's `kind`: a ready `judgment` is `passed`, a ready `transaction` is `owner_signature`. All fields the server returns (reason, prompt, `decisionCode`, `workflowNodeId`, revision, source hash, receipt steps) are printed.

The configured token is redacted in full from all output, whatever its length. Its secret part must be 16–128 URL-safe characters.

## API used

`GET /api/harness/{owner}/{policy}/skill`, `POST …/judge`, `POST …/transactions`, `POST …/status`, with `Authorization: Bearer owner.policy.secret`. See `AllowIt-app/server/app/policy_requests.go` for validation.

Skill format: [Agent Skills specification](https://agentskills.io/specification) and [best practices](https://agentskills.io/skill-creation/best-practices).
