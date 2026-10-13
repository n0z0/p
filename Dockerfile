# Multi-stage Dockerfile untuk build statis lintas platform (Linux & Windows)
FROM rust:1.80-slim-bookworm AS builder

# Install build essentials & mingw-w64 untuk kompilasi silang ke Windows
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    mingw-w64 \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

# Tambah target Windows GNU & Linux Musl
RUN rustup target add x86_64-pc-windows-gnu
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /app
COPY . .

# Build binary p untuk Windows (.exe)
RUN cargo build --release --target x86_64-pc-windows-gnu

# Build binary p statis murni untuk Linux
RUN cargo build --release --target x86_64-unknown-linux-musl

# Output stage
FROM scratch AS artifacts
COPY --from=builder /app/target/x86_64-pc-windows-gnu/release/p.exe /windows/p.exe
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/p /linux/p
