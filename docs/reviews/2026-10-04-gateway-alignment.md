# Agent CLI gateway alignment review

Candidate: `0.2.0-dev`, branch `v2-dev`, base `cd5516b8c975210b61904087ec5f93363f79534e`.

The implementation preserves the four agent commands and the app gateway routes. Frontend, app-server production code, SDK, engine, contracts and deployments are outside this change.

Author: Claude Code session `8518e5fd-8e3b-4031-9902-78789e29f581`, actual model `claude-opus-5-5`. Codex added real-gateway integration and identifier parsing fixes.

Independent reviewer: Claude Code session `3b30cc93-9496-4c73-9bff-e242ba56549d`, actual model `claude-opus-5-5` on both review passes. Verified from returned modelUsage, not just the requested model flag.

Initial review found one material incompatibility: strict end-of-options parsing rejected the existing generated skill's trailing flags for dash-prefixed policy IDs. The parser now protects the required identifier slots then resumes flags. A regression executes the actual generated skill command from the pinned typed-runtime server. Also addressed: missing status request identity and ensuring the integration runner detects skipped/missing tests.

Final reviewer verdict: "the finding is closed, and I have no remaining material findings on the current diff from cd5516b."

The reviewer inspected the code and traced the parser but could not independently rerun builds because its permission prompts blocked them. The following checks were executed successfully by Codex:

- `make test`: Go vet and race tests.
- `make dist`: static Linux amd64 distribution; host build reports `allowit 0.2.0-dev`.
- Gateway integration: three named customer-workspace cases and four named typed-runtime cases; actual Go HTTP gateways and pinned Rust WASM evaluators, with artifact hashes checked. The current invocation is `make integration APP_REPO=/path/to/AllowIt-app`.
- `git diff --check`.

Backend commits and the repeatable procedure are in [the integration guide](../../integration/README.md). Wallet sessions and chain adapters in those tests are synthetic fixtures. This review and validation do not establish live wallet settlement, payment delivery, a deployed app integration or an npm release.

## Go runner follow-up

The owner requested Go throughout and authorized merging PR1. The integration runner is now Go using only its standard library; the earlier script was removed. It retains exact commit checks, SDK WASM hashing, temporary source archives and the seven named-case assertions. Archive extraction rejects traversal and links while accepting Git's PAX commit metadata.

Independent Claude Code reviewer `07da008c-a25a-4044-80c4-3c746049ff97` used actual model `claude-opus-5-5`, verified from modelUsage on both passes. Initial review flagged PAX metadata handling; this was fixed and covered by a regression. Final verdict: "The PAX header finding is closed, and I found no other material issues."

The reviewer inspected the current files; Codex executed `make test`, `make integration` (all seven cases), `make dist` and `git diff --check`, all successfully. CLI behavior, frontend and app server are unchanged by this follow-up.
