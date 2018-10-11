#!/bin/sh

set -xe

export RUST_BACKTRACE=1

# Enables additional cpu-specific optimizations.
export RUSTFLAGS="-D warnings -C target-cpu=native"

cargo clippy --tests --examples --benches -- --deny clippy
cargo clippy --all-features --tests --examples --benches -- --deny clippy
cargo fmt -- --check
cargo test --release
cargo test --all-features --release
cargo doc
cargo deadlinks --dir target/doc/threshold_crypto/
