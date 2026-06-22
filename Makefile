# ShipSafe development tasks. Run `make help` to list them.
.PHONY: help build test fmt lint check bump

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

build: ## Build the release binary
	cargo build --release

test: ## Run the test suite
	cargo test

fmt: ## Format the code
	cargo fmt

lint: ## Run clippy with warnings denied
	cargo clippy --all-targets -- -D warnings

check: fmt lint test ## Format, lint and test (run before opening a PR)

bump: ## Bump the crate version in Cargo.toml + Cargo.lock (usage: make bump VERSION=0.2.2)
	@test -n "$(VERSION)" || { echo "usage: make bump VERSION=0.2.2" >&2; exit 2; }
	scripts/bump-version.sh $(VERSION)
