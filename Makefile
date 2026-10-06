GO ?= go
CARGO ?= cargo
RUST_TARGET ?= x86_64-unknown-linux-musl

.PHONY: test parity integration build dist clean

test:
	$(CARGO) fmt --check
	$(CARGO) clippy --locked --all-targets -- -D warnings
	$(CARGO) test --locked
	cd reference/go && $(GO) vet ./... && $(GO) test -race -count=1 ./...
	$(GO) test -race -count=1 ./integration

# Original harness state/security/recovery cases, with only the process entry
# changed to the Rust binary. The Go reference remains a test oracle.
parity:
	$(CARGO) build --locked
	cd reference/go && ALLOWIT_PARITY_BINARY="$(CURDIR)/target/debug/allowit" $(GO) test -race -count=1 -timeout 10m ./internal/cli

integration:
	$(GO) run ./integration --app-repo "$(APP_REPO)"

build:
	$(CARGO) build --locked --release

dist:
	$(CARGO) build --locked --release --target $(RUST_TARGET)
	mkdir -p dist
	cp target/$(RUST_TARGET)/release/allowit dist/allowit-linux-amd64
	cd dist && (command -v sha256sum >/dev/null && sha256sum allowit-linux-amd64 || shasum -a 256 allowit-linux-amd64) > allowit-linux-amd64.sha256

clean:
	$(CARGO) clean
	rm -rf dist
