GO ?= go
CARGO ?= cargo
RUST_TARGET ?= x86_64-unknown-linux-musl
# Canonical SDK crate from the pinned Git submodule. Its target output stays in
# this checkout so SDK checks never leave files inside the submodule.
SDK_CRATE := repos/AllowIt-hq--allowit-sdk/native-rust
TEMPO_CRATE := repos/AllowIt-hq--allowit-sdk/tempo-rust

.PHONY: test parity integration build dist clean

test:
	python3 scripts/sync-native-sdk.py verify
	python3 scripts/package-licenses.py
	python3 scripts/test-package-licenses.py
	python3 scripts/test-binary-provenance.py
	python3 scripts/test-tempo-sdk-review.py
	$(CARGO) fmt --check
	$(CARGO) clippy --locked --all-targets -- -D warnings
	$(CARGO) test --locked
	CARGO_TARGET_DIR="$(CURDIR)/target" $(CARGO) test --manifest-path $(SDK_CRATE)/Cargo.toml --locked
	CARGO_TARGET_DIR="$(CURDIR)/target" $(CARGO) clippy --manifest-path $(SDK_CRATE)/Cargo.toml --locked --all-targets -- -D warnings
	CARGO_TARGET_DIR="$(CURDIR)/target" $(CARGO) test --manifest-path $(TEMPO_CRATE)/Cargo.toml --locked
	CARGO_TARGET_DIR="$(CURDIR)/target" $(CARGO) clippy --manifest-path $(TEMPO_CRATE)/Cargo.toml --locked --all-targets -- -D warnings
	python3 scripts/sync-native-sdk.py verify
	cd reference/go && $(GO) vet ./... && $(GO) test -race -count=1 ./...
	$(GO) test -race -count=1 ./integration

# Original harness state/security/recovery cases, with only the process entry
# changed to the Rust binary. The Go reference remains a test oracle.
parity:
	python3 scripts/sync-native-sdk.py verify
	$(CARGO) build --locked
	cd reference/go && ALLOWIT_PARITY_BINARY="$(CURDIR)/target/debug/allowit" $(GO) test -race -count=1 -timeout 10m ./internal/cli

integration:
	$(GO) run ./integration --app-repo "$(APP_REPO)"

build:
	python3 scripts/sync-native-sdk.py verify
	$(CARGO) build --locked --release

dist:
	python3 scripts/sync-native-sdk.py verify
	$(CARGO) build --locked --release --target $(RUST_TARGET)
	mkdir -p dist
	python3 scripts/package-licenses.py --dist dist
	cp target/$(RUST_TARGET)/release/allowit dist/allowit-linux-amd64
	cd dist && (command -v sha256sum >/dev/null && sha256sum allowit-linux-amd64 || shasum -a 256 allowit-linux-amd64) > allowit-linux-amd64.sha256

clean:
	$(CARGO) clean
	rm -rf dist
