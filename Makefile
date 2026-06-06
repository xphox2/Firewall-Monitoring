# Firewall-Mon developer Makefile (AUDIT-004).
#
# Targets mirror the CI gates in `.github/workflows/ci.yml` so you can run
# the same checks locally before pushing. `make qa` is the one to run before
# every commit (matches the project's QA gate; see CONTRIBUTING.md).

GO         ?= go
GOFMT      ?= gofmt
VERSION    ?= $(shell grep -E 'const ServerVersion' cmd/api/main.go | sed -E 's/.*"([^"]+)".*/\1/')
BIN_DIR    ?= bin

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' Makefile | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

.PHONY: qa
qa: tidy-check fmt-check vet build test ## Run the full QA gate (same as CI)
	@echo "QA OK (v$(VERSION))"

.PHONY: test
test: ## Run tests
	$(GO) test -count=1 -timeout=5m ./...

.PHONY: test-race
test-race: ## Run tests with the race detector (requires CGO)
	CGO_ENABLED=1 $(GO) test -race -count=1 -timeout=5m ./...

# AUDIT-102: -trimpath strips local filesystem paths and -buildvcs=false
# keeps VCS state out of the binary, so builds are reproducible across hosts.
GOFLAGS_REPRO ?= -trimpath -buildvcs=false

.PHONY: build
build: ## Build all binaries into ./bin (reproducible)
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS_REPRO) -o $(BIN_DIR)/ ./cmd/...

.PHONY: vet
vet: ## go vet
	$(GO) vet ./...

.PHONY: fmt
fmt: ## Apply gofmt to the whole tree
	$(GOFMT) -w .

.PHONY: fmt-check
fmt-check: ## Fail if any file needs gofmt
	@unformatted=$$($(GOFMT) -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "Files need gofmt:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

.PHONY: tidy
tidy: ## go mod tidy
	$(GO) mod tidy

.PHONY: tidy-check
tidy-check: ## Fail if go.mod / go.sum aren't tidy
	@$(GO) mod tidy
	@if ! git diff --quiet -- go.mod go.sum; then \
		echo "go.mod / go.sum out of sync; run 'make tidy' and commit"; \
		git --no-pager diff -- go.mod go.sum; \
		exit 1; \
	fi

.PHONY: vuln
vuln: ## Run govulncheck (requires github.com/golang/vuln)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)

.PHONY: docker
docker: ## Build the Docker image with the current version tag
	docker build --build-arg VERSION=$(VERSION) -t firewall-mon:$(VERSION) -t firewall-mon:latest .

.PHONY: version
version: ## Print the current ServerVersion
	@echo $(VERSION)
