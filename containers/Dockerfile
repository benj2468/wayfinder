# Choose your required Rust version
FROM rust:1.96-slim AS builder

# Install system dependencies (including protoc)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        protobuf-compiler \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY . /app

WORKDIR /app

# Ensure protoc is globally accessible (usually /usr/bin/protoc via apt)
ENV PROTOC=/usr/bin/protoc

RUN cargo build --release -p wayfinder-tap

FROM gcr.io/distroless/cc-debian12

COPY --from=builder /app/target/release/wayfinder-tap /wayfinder-tap

ENTRYPOINT ["/wayfinder-tap"]
