# Firewall-Mon developer Makefile (AUDIT-004).
#
# Targets mirror the CI gates in `.github/workflows/ci.yml` so you can run
# the same checks locally before pushing. `make qa` is the one to run before
# every commit (matches the project's QA gate; see CONTRIBUTING.md).

GO         ?= go
GOFMT      ?= gofmt
VERSION    ?= $(shell grep -E 'const ServerVersion' cmd/api/main.go | sed -E 's/.*"([^"]+)".*/\1/')
BIN_DIR    ?= bin

# AUDIT-104: native (non-Docker) install paths. Override PREFIX for a
# different prefix (e.g. /opt/firewall-mon) and DESTDIR for staged installs
# (packaging). These let users on FreeBSD/Synology/RHEL/k8s-without-Docker
# install the binaries without the container.
PREFIX     ?= /usr/local
DESTDIR    ?=
SHAREDIR    = $(DESTDIR)$(PREFIX)/share/firewall-mon
BINDIR      = $(DESTDIR)$(PREFIX)/bin
DIST_DIR   ?= dist

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

.PHONY: test-integration
test-integration: ## Run the Postgres integration suite (AUDIT-118; needs TEST_PG_DSN)
	# Build-tagged (//go:build integration) suite that needs a real PostgreSQL.
	# Set TEST_PG_DSN, e.g.:
	#   postgres://firewall_mon:firewall_mon@localhost:5432/firewall_mon_test?sslmode=disable
	# With Docker you can spin one up:
	#   docker run --rm -d --name fwmon-it-pg -p 5432:5432 \
	#     -e POSTGRES_USER=firewall_mon -e POSTGRES_PASSWORD=firewall_mon \
	#     -e POSTGRES_DB=firewall_mon_test postgres:16
	# Without TEST_PG_DSN the suite compiles and skips. Deliberately NOT part of
	# `qa` so the default contributor gate stays database-free.
	$(GO) test -tags=integration -count=1 -timeout=5m ./internal/database/...

# AUDIT-102: -trimpath strips local filesystem paths and -buildvcs=false
# keeps VCS state out of the binary, so builds are reproducible across hosts.
GOFLAGS_REPRO ?= -trimpath -buildvcs=false

.PHONY: build
build: ## Build all binaries into ./bin (reproducible, canonical fwmon-* names)
	@mkdir -p $(BIN_DIR)
	# AUDIT-104: emit the canonical `fwmon-*` names the rest of the project
	# uses (Dockerfile, deploy.sh, the systemd units). `go build -o bin/
	# ./cmd/...` would name them after their directories (api/poller/
	# trap-receiver/probe), which `make install` and the tarball can't then
	# find and which wouldn't match the systemd ExecStart paths.
	$(GO) build $(GOFLAGS_REPRO) -o $(BIN_DIR)/fwmon-api    ./cmd/api
	$(GO) build $(GOFLAGS_REPRO) -o $(BIN_DIR)/fwmon-poller ./cmd/poller
	$(GO) build $(GOFLAGS_REPRO) -o $(BIN_DIR)/fwmon-trap   ./cmd/trap-receiver
	$(GO) build $(GOFLAGS_REPRO) -o $(BIN_DIR)/fwmon-probe  ./cmd/probe

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

.PHONY: install
install: build ## Install binaries + web assets natively (PREFIX, DESTDIR)
	install -d $(BINDIR) $(SHAREDIR)
	install -m 0755 $(BIN_DIR)/fwmon-api    $(BINDIR)/fwmon-api
	install -m 0755 $(BIN_DIR)/fwmon-poller $(BINDIR)/fwmon-poller
	install -m 0755 $(BIN_DIR)/fwmon-trap   $(BINDIR)/fwmon-trap
	install -m 0755 $(BIN_DIR)/fwmon-probe  $(BINDIR)/fwmon-probe
	cp -r web $(SHAREDIR)/web
	install -m 0644 config.env.example $(SHAREDIR)/config.env.example
	@echo "Installed to $(DESTDIR)$(PREFIX). Copy $(SHAREDIR)/config.env.example to /etc/firewall-mon/config.env and edit it."

.PHONY: uninstall
uninstall: ## Remove a native install (PREFIX, DESTDIR)
	rm -f $(BINDIR)/fwmon-api $(BINDIR)/fwmon-poller $(BINDIR)/fwmon-trap $(BINDIR)/fwmon-probe
	rm -rf $(SHAREDIR)

.PHONY: tarball
tarball: build ## Package binaries + assets into dist/firewall-mon-$(VERSION).tar.gz
	@mkdir -p $(DIST_DIR)
	@rm -rf $(DIST_DIR)/firewall-mon-$(VERSION)
	@mkdir -p $(DIST_DIR)/firewall-mon-$(VERSION)
	cp -r $(BIN_DIR) $(DIST_DIR)/firewall-mon-$(VERSION)/bin
	cp -r web $(DIST_DIR)/firewall-mon-$(VERSION)/web
	cp config.env.example deploy.sh entrypoint.sh README.md LICENSE $(DIST_DIR)/firewall-mon-$(VERSION)/
	tar -czf $(DIST_DIR)/firewall-mon-$(VERSION).tar.gz -C $(DIST_DIR) firewall-mon-$(VERSION)
	@rm -rf $(DIST_DIR)/firewall-mon-$(VERSION)
	@echo "Wrote $(DIST_DIR)/firewall-mon-$(VERSION).tar.gz"

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) $(DIST_DIR)

.PHONY: docker
docker: ## Build the Docker image with the current version tag
	docker build --build-arg VERSION=$(VERSION) -t firewall-mon:$(VERSION) -t firewall-mon:latest .

.PHONY: version
version: ## Print the current ServerVersion
	@echo $(VERSION)
