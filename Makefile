# Verification harness. Two tiers:
#
#   verify-fast  runs in seconds so an agent can loop on it after every edit.
#   verify-full  adds the slow, network-touching, and mutation checks.
#
# `verify` is an alias for the fast tier so `make verify` is always cheap.
# Do not weaken any target here to make it pass; fix the code instead.

.PHONY: verify verify-fast verify-full fmt

verify-fast:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo test

verify-full: verify-fast
	cargo audit
	cargo deny check
	cargo mutants --file src/diff.rs

verify: verify-fast

fmt:
	cargo fmt
