BUILD_ENV := rust
PYTHON ?= $(if $(wildcard .venv/bin/python),$(CURDIR)/.venv/bin/python,python3)

.PHONY: lint fix test

lint:
	@cargo fmt
	@cargo clippy --all-targets --all-features

fix:
	@cargo clippy --fix --workspace --tests

test:
	@cargo test --workspace --all-features -- --nocapture
	@npm test
	@$(PYTHON) -m pytest python/agent-protocols/tests
