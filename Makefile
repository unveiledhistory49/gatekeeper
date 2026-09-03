GO ?= go
BIN ?= bin/gatekeeper

.PHONY: build test vet fmt vuln e2e migrate serve lock

build:
	$(GO) build -o $(BIN) ./cmd/gatekeeper

test:
	$(GO) test ./... -count=1

vet:
	$(GO) vet ./...

fmt:
	@test -z "$$(gofmt -l .)" || (echo "unformatted: $$(gofmt -l .)"; exit 1)

vuln:
	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

e2e:
	./scripts/e2e.sh

migrate:
	$(GO) run ./cmd/gatekeeper migrate

serve:
	$(GO) run ./cmd/gatekeeper serve

# go.sum is committed; `go mod tidy` refreshes the go.mod/go.sum lockfiles.
lock:
	$(GO) mod tidy
