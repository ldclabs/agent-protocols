BUILD_ENV := rust
PYTHON ?= $(if $(wildcard .venv/bin/python),$(CURDIR)/.venv/bin/python,python3)

.PHONY: lint fix test test-mail-interop mail-vectors version

lint:
	@cargo fmt
	@cargo clippy --all-targets --all-features

fix:
	@cargo clippy --fix --workspace --tests

test:
	@cargo test --workspace --all-features -- --nocapture
	@pnpm test
	@$(PYTHON) -m pytest python/agent-protocols/tests
	@$(PYTHON) tests/mail_interop.py

test-mail-interop:
	@$(PYTHON) tests/mail_interop.py

# Regenerate docs/protocols/agent-mail/1.0.vectors.json after a Mail wire change.
mail-vectors:
	@$(PYTHON) tests/gen_mail_vectors.py

# Set the SDK version in all three manifests and the landing page note: make version VERSION=X.Y.Z
version:
	@$(PYTHON) scripts/set_version.py $(VERSION)
