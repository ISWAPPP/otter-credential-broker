.PHONY: all fmt fmt-check lint test test-pg check deny audit build release docker run-dev

all: check

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets -- -D warnings

## Tests need PostgreSQL: set OCB_TEST_DATABASE_URL, or use `make test-pg`.
test:
	cargo test --workspace

## Tests against a throwaway PostgreSQL cluster (needs initdb/pg_ctl on PATH).
test-pg:
	./scripts/test-with-postgres.sh

## Local quality gate (same as CI minus deny/audit)
check: fmt-check lint test-pg

deny:
	cargo deny check

audit:
	cargo audit

build:
	cargo build --workspace

release:
	cargo build --release --locked -p otter-credential-broker

docker:
	docker build -t otter-credential-broker:dev .

## Local dev server with throw-away secrets in ./secrets (gitignored).
## Needs PostgreSQL at the URL in config/dev.toml.
run-dev: build
	mkdir -p secrets
	test -f secrets/kek || ./target/debug/otter-credential-broker keygen > secrets/kek
	test -f secrets/token-key || ./target/debug/otter-credential-broker keygen > secrets/token-key
	test -f secrets/admin-tokens || echo "dev $$(./target/debug/otter-credential-broker gen-token)" > secrets/admin-tokens
	./target/debug/otter-credential-broker serve --config config/dev.toml
