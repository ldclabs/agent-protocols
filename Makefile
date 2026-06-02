BUILD_ENV := rust

.PHONY: lint fix test

lint:
	@cargo fmt
	@cargo clippy --all-targets --all-features

fix:
	@cargo clippy --fix --workspace --tests

test:
	@cargo test --workspace --all-features -- --nocapture
	@npm test
	@cd python/agent-protocols && python3 -m pytest
