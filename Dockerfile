# Use cargo-chef to plan the build
FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

# Create a recipe for caching dependencies
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Build dependencies - this is the caching layer!
FROM chef AS builder
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is cached unless Cargo.lock changes
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY . .
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*
RUN cargo build --release

# Ubuntu base image
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y curl && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /app/target/release/sova-bitcoin-sync /usr/local/bin/

# Run the binary
ENTRYPOINT ["/usr/local/bin/sova-bitcoin-sync"]