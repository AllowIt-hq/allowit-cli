# HTTP API contract

See [CLI usage](../README.md#use) for commands and retry rules.

## Policy description

Commands read `GET …/skill` before sending to `judge` or `transactions`.

- Published `owner` and `policyId` must match `ALLOWIT_TOKEN`.
- Published `endpoints.judge`, `.transactions`, `.status` and `.skill` must match `ALLOWIT_URL/api/harness/{owner}/{policy}/{action}`. Relative URLs resolve against the skill URL. Changes to origin, scheme, port, path, query or fragment exit 3. Requests and bearer tokens use only canonical routes, never published endpoints.
- Required `network` accepts `local:dev` for mocks, or `solana:devnet`, `solana:testnet` and `solana:mainnet` for owner-signed USDC. Other networks fail validation.
- Published `executionMode`, `capabilities.mode`, `capabilities.execution`, `contract.profile` and `contract.capabilities.execution` must match the network. Accepted values are `local`/`owner_signed`, `local_dev`/`solana_owner_signed` for profiles, and `mock`/`owner_signed` for contract execution. Unknown values, contract versions other than 1, or mismatched `sourceHash` exit 3.
- Rails, rates and plan support use `contract.capabilities`, falling back to legacy `capabilities`. Without published rails, wallet policies allow `--rail solana --op transferUSDC`, and Local dev allows plain USDC only. Typed `executionPlans`, `memoData` or `contractCalls` set to false reject corresponding flags.

Omitted `title`, `policyId`, `owner`, `endpoints`, `capabilities` and `contract` remain valid.
`show` falls back from `title` to `name`.
Without a reported policy ID, it prints the token's policy ID marked as not reported by AllowIt.

## Response validation

Accepted decision/status pairs:

| Decision | Status | Required field |
|---|---|---|
| `pass` | `ready`, `submitted` | — |
| `pass` | `recorded` | `localRecorded: true` |
| `pass` | `settled` | `executed: true` |
| `pending` | `evaluating` | — |
| `awaiting_input` | `awaiting_input` | — |
| `fail` | `denied` | — |

Present `executed` and `localRecorded` must agree with status.
Present `kind` must be `judgment` or `transaction` and match the command.
Without `kind`, `status` never treats `ready` as complete.

Everything else is uncertain, including:

- Missing or conflicting decision/status fields, such as `pass`/`evaluating`, `pending`/`denied`, or `ready` with `executed: true`.
- On-chain states on Local dev, mock recordings on wallet networks, or spending for `eval`/`judgment`.
- `/status` results for another request or without `requestId`.
- Non-200 2xx responses or redirects from `judge`, `transactions` or `status`.

## Status recovery without a policy description

`status` continues after non-authentication `/skill` failures, including HTTP 409 assembly refusal, other HTTP errors, network failure, and unreadable or unsupported descriptions.
It reports the unavailable description on stderr and reads the canonical `…/status` route.
HTTP 401/403, redirects, or descriptions naming another owner, policy or route stop recovery with exit 3.

Without network information, `pending`, `awaiting_input`, `denied` and ready judgments (`passed`) retain their normal meaning.
`recorded`, `submitted`, `settled`, ready transactions, and ready results without `kind` exit 5 with empty stdout, including after `--wait`.
These results cannot establish whether execution was a mock or wallet transfer.
`status` never resends `judge` or `transactions`.
