# Choose your required Rust version
FROM rust:1.82-slim

# Install system dependencies (including protoc)
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install the LLVM tools preview required for coverage
RUN rustup component add llvm-tools-preview

# Install cargo-nextest and cargo-llvm-cov binaries using pre-compiled installers
# (Much faster than running `cargo install` inside the Dockerfile)
RUN curl -LsSf https://github.com/nextest-rs/nextest/releases/latest/download/nextest-binstall-installer.sh | sh

RUN cargo binstall -y cargo-nextest cargo-llvm-cov

# Ensure protoc is globally accessible (usually /usr/bin/protoc via apt)
ENV PROTOC=/usr/bin/protoc
