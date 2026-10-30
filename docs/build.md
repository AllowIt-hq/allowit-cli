# Build and distribution

How the `allowit` binary is built, checked and packaged. The [README](../README.md#install) has the short install path.

## Toolchain

Use Rust 1.98 or later; CI pins Rust 1.98.0. Python 3 runs the SDK pin and packaging scripts. Go is needed only for the reference and integration tests.

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

All commands call Rust modules directly. The binary needs no Node runtime. The Go implementation under `reference/go/` is a differential test oracle; the default command and distribution build use Rust. Its historical Go module path remains unchanged. The `v0.1.0` and `v0.1.1` tags identify the earlier Go releases; `main` carries the `0.3.0-dev` Rust implementation.

## Validation and distribution

```sh
make test                             # Rust tests + Go reference regressions
make parity                           # original harness cases against Rust
make integration APP_REPO=/path/to/AllowIt-app
make dist                             # static Linux/musl distribution
```

`make test` runs the SDK pin verifier, license packaging checks, provenance and vendor-graph tests, `cargo fmt --check`, `cargo clippy` with warnings denied, the Rust test suites of the CLI and the pinned SDK crates, and the Go reference and integration tests.

`make dist` requires the `x86_64-unknown-linux-musl` target and a suitable musl linker (`.cargo/config.toml` selects `musl-gcc`). CI installs both and uploads `dist/allowit-linux-amd64` with its SHA-256. The lockfile pins the complete dependency graph.

The **Native binaries** workflow builds Linux x64 (static musl), macOS Apple Silicon and macOS Intel, with checksums and a source-free smoke test whose PATH has no Node installation. It uploads workflow artifacts rather than publishing a GitHub Release. Distribution checks must pass for the exact release revision before a release is accepted.

The CLI is independent of the optional hosted-agent runtime. A host can install the same binary used by an external agent; this repository contains no sandbox launcher, supervisor or model proxy.

## Binary provenance

Each **Native binaries** artifact includes `allowit-PLATFORM.provenance.json` (schema version 1, kind `rust-native`). It records the binary target and SHA-256, exact CLI commit and source tree, the SDK submodule path, canonical URL, pinned commit and consumed file hashes, and native contract release identity. It is written only after the shared SDK verifier passes and the CLI root's Cargo inputs match the committed source (see [SDK source pin](#sdk-source-pin)). Consumers should select a trusted workflow run, verify the binary checksum against this manifest, and compare the release identity with their backend before executing a downloaded skill. The manifest describes the workflow build; it is not a signature or a standalone attestation from an arbitrary download.

Binary provenance additionally requires a clean parent status and binds the CLI root's Cargo inputs to committed `HEAD`, including ignored files and changes hidden by index flags. Generated `target/` and `dist/` stay ignored. These checks cover Cargo discovery from the SDK crate through the CLI root. Directories above the CLI checkout, `CARGO_HOME`, environment variables and the Rust toolchain are trusted build context; they are neither checked nor recorded.

## SDK source pin

The CLI has one runtime dependency, `allowit-client`, from the pinned SDK submodule. The facade links Tempo and Solana vendor crates at exact Git revisions. Vendors depend on shared core functions. The Tempo implementation lives in `allowit-contracts-tempo/rust`; PaySH lives in `allowit-contracts-solana/crates/solana-vendor`. `vendor/native-sdk.json` binds the resolved first-party graph, source files, features and licenses.

The published Tempo vendor is verified at its exact canonical Git revision. The SDK's `tempo-rust` compatibility package reexports that vendor. Current schema 2 attests the resolved facade, vendors and core package graph. The `ALLOWIT_TEMPO_REVIEW_MANIFEST` mode applies only to the historical schema 1 fixture and earlier SDK base. It cannot produce current release provenance or license packages.

```sh
python3 scripts/sync-native-sdk.py verify              # run by make test/parity/build/dist, CI, provenance and license packaging
python3 scripts/sync-native-sdk.py update FULL_COMMIT  # check out an exact SDK commit, record and stage it
python3 scripts/sync-native-sdk.py pin                 # record and stage the checked-out submodule commit
```

`verify` checks the canonical SDK gitlink and immutable first-party Cargo graph. The graph includes the facade, shared client core, policy core, native Solana library, Stellar library, Tempo vendor and Solana vendor. Each package resolves to its recorded canonical repository, exact revision, source inventory, enabled features and license text. First-party build scripts, `links`, Cargo path overrides, discovery changes and source substitutions fail verification.

Checked-out files must match immutable Git blobs. The verifier rejects hidden source changes, local Git filters, index flags and replacement refs. Cargo discovery inputs between the CLI root and SDK remain bound. `pin` records the checked-out clean SDK revision and stages the gitlink and graph metadata together. License packaging includes the unchanged first-party and registry notices.

## License and binary notices

First-party code is licensed under [MIT](../LICENSE). Dependency licenses remain their own; [THIRD_PARTY_LICENSES](../THIRD_PARTY_LICENSES/README.md) contains the exact dependency notices and runtime attribution for current and historical workflow binaries. Keep this companion directory with downloaded binaries. New workflow artifacts include it with `LICENSE`, the checksum and provenance manifest. The SDK's own notices are copied unchanged from the verified submodule into `THIRD_PARTY_LICENSES/AllowIt-sdk/` at packaging time.

Skill format: [Agent Skills specification](https://agentskills.io/specification) and [best practices](https://agentskills.io/skill-creation/best-practices).
