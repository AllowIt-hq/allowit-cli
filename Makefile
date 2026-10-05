GO ?= go
LDFLAGS := -s -w -buildid=

.PHONY: test integration dist clean

test:
	$(GO) vet ./...
	$(GO) test -race -count=1 ./...

# Requires a local app clone with the exact commits in integration/backends.json.
integration:
	python3 integration/check.py --app-repo "$(APP_REPO)"

# Static, reproducible Linux binary for the AllowIt agent sandbox.
dist:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o dist/allowit-linux-amd64 ./cmd/allowit
	cd dist && (command -v sha256sum >/dev/null && sha256sum allowit-linux-amd64 || shasum -a 256 allowit-linux-amd64) > allowit-linux-amd64.sha256

clean:
	rm -rf dist
