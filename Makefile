BUILD_ENV := rust
PYTHON ?= $(if $(wildcard .venv/bin/python),$(CURDIR)/.venv/bin/python,python3)

.PHONY: lint fix test test-mail-interop

lint:
	@cargo fmt
	@cargo clippy --all-targets --all-features

fix:
	@cargo clippy --fix --workspace --tests

test:
	@cargo test --workspace --all-features -- --nocapture
	@pnpm test
	@$(PYTHON) -m pytest python/agent-protocols/tests
	@$(PYTHON) docs/protocols/agent-mail/verify_vectors.py
	@$(PYTHON) tests/mail_interop.py

test-mail-interop:
	@$(PYTHON) tests/mail_interop.py
