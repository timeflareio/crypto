# timeflare crypto — Makefile
#
# Two implementations of one set of primitives live here: pure Go in go/
# (consumed by the chain and the guardian, no cgo) and Rust in rust/ (compiled
# to WASM for the TypeScript SDK), with the corpus that holds them together in
# vectors/. They are NOT allowed to drift, and nothing in this repo prevents
# drift by construction — what prevents it is that both suites assert the same
# corpus, so `make test` fails on the side that changed. Keep it that way.
#
# This repository is self-contained: it defines primitives that other components
# depend on, and depends on none of them. Nothing here reaches for the chain, and
# nothing here enforces or checks chain protocol rules. `make test` and
# `make verify` are offline and hermetic.
#
# go.mod stays at the repository root deliberately, even though the sources sit
# in go/: that keeps one plain vX.Y.Z tag line serving both the Go module and
# the WASM asset, and keeps `go test ./...` working from here. The import path
# is github.com/timeflareio/crypto/go.

.DEFAULT_GOAL := help

GOLANGCI_LINT_VERSION ?= v2.12.2
LINT_TIMEOUT          ?= 5m
TEST_TIMEOUT          ?= 10m
COVERAGE_FILE         ?= coverage.out
COVERAGE_HTML_FILE    ?= coverage.html

# The corpus files this repository owns and publishes. Consumers (TypeScript
# SDK, mobile client) pin a release and assert these to prove they interoperate
# with the primitives defined here.
VECTORS_FILES := detection_hint encryption hmac low_order_keys rebate_commitment

# wasm-pack output directory (published as a release asset, never committed)
WASM_OUT_DIR ?= pkg

##@ Testing

.PHONY: test
test: go-test rust-test ## Run both suites (Go + Rust) against the shared vectors

.PHONY: go-test
go-test: ## Run the Go test suite
	@echo "--> Go tests"
	@go test -mod=readonly -race -timeout $(TEST_TIMEOUT) ./...
	@echo "✅ Go tests passed"

.PHONY: go-test-cover
go-test-cover: ## Run the Go suite and write an HTML coverage report
	@go test -mod=readonly -race -timeout $(TEST_TIMEOUT) \
		-coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	@go tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML_FILE)
	@rm -f $(COVERAGE_FILE)
	@echo "✅ Coverage written to $(COVERAGE_HTML_FILE)"

.PHONY: rust-test
rust-test: ## Run the Rust test suite
	@echo "--> Rust tests"
	@cd rust && cargo test
	@echo "✅ Rust tests passed"

##@ Code quality

# rust-format-check and rust-lint are deliberately NOT in `verify` yet. The
# crate arrived from the monorepo carrying pre-existing debt — its CI ran
# `cargo test` and `cargo audit` only, never rustfmt or clippy — so gating on
# them today would fail on ~880 lines of reformatting and 6 clippy findings
# that have nothing to do with this repository's own work. Both targets exist
# and both should join `verify` once the crate is clean; that is
# docs/planning/PENDING_RUST_HYGIENE_PLAN.md.
.PHONY: verify
verify: go-format-check go-imports-check go-vet go-lint-check ## Verify all standards (read-only)
	@echo "✅ All checks passed"
	@echo "ℹ  Rust format/lint not yet gated — docs/planning/PENDING_RUST_HYGIENE_PLAN.md"

.PHONY: clean-code
clean-code: go-format go-imports go-lint ## Fix everything fixable (formats, lints with --fix)
	@echo "✅ Code cleaned"

.PHONY: go-format
go-format:
	@gofmt -w -s .

.PHONY: go-format-check
go-format-check:
	@files=$$(gofmt -l -s .); \
	if [ -n "$$files" ]; then \
		echo "❌ Unformatted files:"; echo "$$files"; \
		echo "Run 'make go-format' to fix"; exit 1; fi
	@echo "✅ Formatting OK"

.PHONY: go-imports
go-imports:
	@command -v goimports >/dev/null 2>&1 || go install golang.org/x/tools/cmd/goimports@latest
	@goimports -w .

.PHONY: go-imports-check
go-imports-check:
	@command -v goimports >/dev/null 2>&1 || go install golang.org/x/tools/cmd/goimports@latest
	@files=$$(goimports -l .); \
	if [ -n "$$files" ]; then \
		echo "❌ Unorganised imports:"; echo "$$files"; \
		echo "Run 'make go-imports' to fix"; exit 1; fi
	@echo "✅ Import organisation OK"

.PHONY: go-vet
go-vet:
	@go vet ./...
	@echo "✅ go vet OK"

.PHONY: go-lint
go-lint:
	@command -v golangci-lint >/dev/null 2>&1 || go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@golangci-lint run ./... --fix --timeout $(LINT_TIMEOUT)

.PHONY: go-lint-check
go-lint-check:
	@command -v golangci-lint >/dev/null 2>&1 || go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@golangci-lint run ./... --timeout $(LINT_TIMEOUT)
	@echo "✅ golangci-lint OK"

.PHONY: go-govulncheck
go-govulncheck: ## Scan Go dependencies for vulnerabilities (advisory, not in verify)
	@command -v govulncheck >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@latest
	@govulncheck ./...

.PHONY: rust-format
rust-format:
	@cd rust && cargo fmt

.PHONY: rust-format-check
rust-format-check:
	@cd rust && cargo fmt --check
	@echo "✅ cargo fmt OK"

.PHONY: rust-lint
rust-lint:
	@cd rust && cargo clippy --all-targets -- -D warnings
	@echo "✅ clippy OK"

.PHONY: rust-audit
rust-audit: ## Audit Rust dependencies (advisory, not in verify)
	@command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit
	@cd rust && cargo audit

##@ Vectors

# vectors/ is OWNED here. It pins the primitives this repository defines, and it
# is the artefact downstream implementations (TypeScript SDK, mobile client)
# assert to prove they interoperate. Vectors are append-only: adding cases is
# ordinary work, changing an existing expected value is a breaking primitive
# change (see README.md "Versioning").
#
# There is no sync or verify step, and deliberately so: this repository is the
# source of these vectors, not a consumer of someone else's copy.

.PHONY: vectors-package
vectors-package: ## Package the owned corpus with a SHA-256 manifest (used by release.yml)
	@set -e; \
	out="$${OUT_DIR:-dist}"; \
	ver="$${VERSION:-dev}"; \
	mkdir -p "$$out"; \
	tar -czf "$$out/timeflare-crypto-vectors-$$ver.tar.gz" \
		$(foreach v,$(VECTORS_FILES),-C "$(CURDIR)" vectors/$(v).json); \
	( cd vectors && shasum -a 256 $(foreach v,$(VECTORS_FILES),$(v).json) ) \
		> "$$out/timeflare-crypto-vectors-$$ver.sha256"; \
	echo "✅ corpus packaged in $$out/"

##@ Build

.PHONY: wasm
wasm: $(WASM_OUT_DIR)/timeflare_crypto.js ## Build the WASM bundle from the Rust crate

$(WASM_OUT_DIR)/timeflare_crypto.js: $(shell find rust/src -name '*.rs') rust/Cargo.toml rust/rust-toolchain.toml
	@command -v wasm-pack >/dev/null 2>&1 || { \
		echo "❌ wasm-pack not found. Install with: cargo install wasm-pack"; exit 1; }
	@echo "🦀 Building WASM crypto (rust -> $(WASM_OUT_DIR))"
	@cd rust && wasm-pack build --target web --out-dir ../$(WASM_OUT_DIR)
	@echo "✅ WASM built in $(WASM_OUT_DIR)/"

##@ Misc

.PHONY: clean
clean: ## Remove build and test artefacts
	@rm -rf $(WASM_OUT_DIR) dist rust/target $(COVERAGE_FILE) $(COVERAGE_HTML_FILE)
	@go clean -cache -testcache 2>/dev/null || true
	@echo "✅ Cleaned"

.PHONY: doctor
doctor: ## Check the local toolchain
	@ok=0; \
	for t in go cargo rustc wasm-pack; do \
		if command -v $$t >/dev/null 2>&1; then printf "  ✅ %-12s %s\n" "$$t" "$$(command -v $$t)"; \
		else printf "  ❌ %-12s MISSING\n" "$$t"; ok=1; fi; \
	done; \
	exit $$ok

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage: make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
	@echo ""
