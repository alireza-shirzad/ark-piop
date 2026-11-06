# Run all tests (with and without honest-prover feature), then once more
# under LogUp-GKR, which tests on a default configuration do not reach
test:
    cargo test --features test-utils
    cargo test --features test-utils,honest-prover
    ARK_PIOP_LOOKUP_PROTOCOL=gkr cargo test --features test-utils

# Check formatting
fmt:
    cargo fmt --check

# Run clippy lints
clippy:
    cargo clippy --features test-utils -- -D warnings
    cargo clippy --features test-utils,honest-prover -- -D warnings

# Run microbenchmarks (writes comparison report against last run to target/criterion/)
bench:
    cargo bench --features test-utils

# Run all CI checks (fmt + clippy + tests)
ci: fmt clippy test
