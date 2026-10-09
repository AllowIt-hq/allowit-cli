# Gateway compatibility checks

Run from the CLI repository:

```sh
go run ./integration --app-repo /path/to/AllowIt-app
```

The clone must contain both exact commits in `backends.json`; the second is currently a local reviewed runtime commit. The Go runner does not fetch or change that checkout. It builds the Rust CLI with the locked Cargo dependencies and the initialized `repos/AllowIt-hq--allowit-sdk` submodule, archives each gateway's tracked Go sources into a temporary directory, verifies the pinned SDK WASM hash and overlays the integration tests there. Optional `--backend customer-workspace` runs only Igor's PR6 snapshot. Rust, Go and Git are required; Go modules must be cached or downloadable. Archive extraction, artifact hashing and test-event verification use the Go standard library.

These checks exercise the actual Go HTTP routes and Rust WASM policy evaluator. The backend's synthetic wallet identities and chain adapter fixtures provide setup; there are no live payments, model calls, external executors or production credentials. Tests cover:

- `show`, `eval`, `exec`, `status` through the same origin and scoped bearer used by an agent;
- exact action/recipient/amount forwarding, non-spending evaluations, reservations, duplicate retries and changed-body conflicts;
- pending owner input and resumption by the owner, without CLI approval powers;
- recovery of an existing request when typed skill issuance refuses an old compiler binding;
- the actual generated CLI skill for a policy ID beginning with `-`, including its trailing flags;
- Igor's real structured-policy save/compile path, a draft refusing agent access, strict review threshold, hard cap and unsupported action denial.

## Later app-server integration

| Agent command | Current frontend-server route | Responsibility retained by the server |
| --- | --- | --- |
| `show POLICY` | `GET /api/harness/{owner}/{policy}/skill` | Check capability; describe the policy and actual supported execution profile. |
| `eval POLICY ...` | `POST .../judge` | Evaluate an exact action with the Rust SDK; do not reserve or spend. |
| `exec POLICY ...` | `POST .../transactions` | Bind action and client request ID; evaluate, reserve and create an owner review request. |
| `status POLICY REQUEST_ID` | `POST .../status` | Return the existing server request; do not create or approve an action. |

The customer editor uses `--action transfer` for a plain USDC transfer. `--op transferUSDC` selects the transport/asset; an explicit action remains the policy's action identifier. Other configured action names do not imply an installed execution adapter.

The customer UI still needs explicit allocation activation, capability handoff and an owner review/transaction path. Its chat is text-only. Wallet fixtures in these tests do not complete those UI features. The standalone engine's `/v1` API requires trusted service credentials and signed owner bindings; never send an agent harness token directly to it. A future gateway adapter must also preserve the non-reserving `eval` contract (engine `judge` currently reserves), request identity, revisions, owner continuations and settlement evidence.

The newer gateway includes `kind`, `revision` and `sourceHash` in results. Igor's snapshot omits them: a `status` response of `ready` remains incomplete because the CLI cannot distinguish a judgment from a transaction. Unknown network metadata cannot establish mock versus on-chain completion. These conservative limits are intentional until the server contract is upgraded. Neither backend snapshot implements paid API delivery in this interface.
