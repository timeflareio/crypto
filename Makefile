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

# The corpus files that travel to consumers, shipped inside the WASM package.
#
# These two are the ones an implementation outside this repository asserts:
# low_order_keys against the SDK's TypeScript guard, which rejects a small-order
# guardian key before reaching the WASM boundary, and rebate_commitment against
# the mobile app's TypeScript commitment arithmetic. The rest of the corpus pins
# this repository's own Go and Rust suites against each other, so it has no
# consumer to reach.
VECTORS_TRAVELLING := low_order_keys rebate_commitment

# wasm-pack output directory (published as a release asset, never committed)
WASM_OUT_DIR ?= pkg

# npm package identity for the WASM bundle. Named for the organisation and the
# repository it comes from, so a consumer's dependency key matches the artefact.
WASM_PACKAGE_NAME ?= @timeflareio/crypto

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

# vectors/ is OWNED here. It pins the primitives this repository defines, and
# `make test` asserts every file from both the Go and the Rust suite. Vectors are
# append-only: adding cases is ordinary work, changing an existing expected value
# is a breaking primitive change (see README.md "Versioning").
#
# There is no sync or verify step, and deliberately so: this repository is the
# source of these vectors, not a consumer of someone else's copy.
#
# The two files an outside implementation asserts travel inside the WASM package
# (VECTORS_TRAVELLING, staged by wasm-package). The rest hold this repository's
# own two implementations together and have no consumer to reach, so they are not
# published separately.

##@ Build

.PHONY: wasm
wasm: $(WASM_OUT_DIR)/timeflare_crypto.js ## Build the WASM bundle from the Rust crate

$(WASM_OUT_DIR)/timeflare_crypto.js: $(shell find rust/src -name '*.rs') rust/Cargo.toml rust/rust-toolchain.toml
	@command -v wasm-pack >/dev/null 2>&1 || { \
		echo "❌ wasm-pack not found. Install with: cargo install wasm-pack"; exit 1; }
	@echo "🦀 Building WASM crypto (rust -> $(WASM_OUT_DIR))"
	@cd rust && wasm-pack build --target web --out-dir ../$(WASM_OUT_DIR)
	@echo "✅ WASM built in $(WASM_OUT_DIR)/"

.PHONY: wasm-package
wasm-package: wasm ## Stage the WASM bundle for consumption (used by release.yml)
	@set -e; \
	dir="$(WASM_OUT_DIR)"; \
	ver="$${VERSION:-0.0.0-dev}"; ver="$${ver#v}"; \
	[ -f "$$dir/package.json" ] || { \
		echo "❌ $$dir/package.json is absent — wasm-pack did not produce a package"; \
		exit 1; }; \
	mkdir -p "$$dir/vectors"; \
	for v in $(VECTORS_TRAVELLING); do \
		cp "vectors/$$v.json" "$$dir/vectors/$$v.json"; \
	done; \
	tmp="$$(mktemp)"; \
	sed -e 's|"name": *"[^"]*"|"name": "$(WASM_PACKAGE_NAME)"|' \
	    -e 's|"version": *"[^"]*"|"version": "'"$$ver"'"|' \
	    "$$dir/package.json" > "$$tmp"; \
	mv "$$tmp" "$$dir/package.json"; \
	grep -q '"name": "$(WASM_PACKAGE_NAME)"' "$$dir/package.json" || { \
		echo "❌ the package name was not rewritten — check wasm-pack's output format"; \
		exit 1; }; \
	grep -q "\"version\": \"$$ver\"" "$$dir/package.json" || { \
		echo "❌ the package version was not rewritten to $$ver"; exit 1; }; \
	echo "✅ $(WASM_PACKAGE_NAME)@$$ver staged in $$dir/ with $(VECTORS_TRAVELLING)"

##@ Misc

.PHONY: clean
clean: ## Remove build and test artefacts
# Scope is what this checkout produces, and nothing else. The Go build cache
# ($GOCACHE, which also holds cached test results) and cargo's registry cache
# are machine-global and shared with every sibling repository, so evicting them
# from here would leave an unrelated repository facing a cold rebuild; Go trims
# its own cache anyway. To force the suites to re-run rather than replay a
# cached result, pass -count=1 to `go test`.
	@rm -rf $(WASM_OUT_DIR) dist rust/target $(COVERAGE_FILE) $(COVERAGE_HTML_FILE)
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
