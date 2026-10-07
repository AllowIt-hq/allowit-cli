# Binary license notices

This directory is companion documentation for all `allowit` binaries built by this repository, including the earlier Go `v0.1.0` and `v0.1.1` builds and the Rust Linux and macOS Actions artifacts. Preserve it together with the repository `LICENSE` when redistributing a binary. Older artifact archives may lack these files; obtain this companion directory with those downloads. No binary archive is changed by adding this documentation.

`registry-index.json` covers the union of registry packages in every historical tracked `Cargo.lock`, including platform-specific packages that are not linked into every binary. Each original crate archive was checked against its lockfile checksum. Its unmodified license, copyright and NOTICE files are retained under `crates/NAME/VERSION/`; `r-efi` publishes its license text in `AUTHORS`. Package SPDX expressions and original archive URLs are recorded in the index. An optional license in an expression remains an option, rather than an additional obligation created by this collection.

`toolchains/` preserves Go's BSD license and vendored standard-library notices, plus Rust's standard-library copyright attribution and referenced license texts, plus the complete musl 1.2.5 copyright and component notices for Rust's self-contained static Linux target. OpenSSL and other bundled C notices are included in the original dependency package files. The root MIT license applies to first-party AllowIt code; it does not replace third-party licenses.

Future artifact builds validate every current registry dependency against this collection and bundle this directory with the binary. If a lockfile introduces a new version, refresh its notices before publishing the artifact.
