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

# Build binary Agent & Controller untuk Windows (.exe)
RUN cargo build --release --target x86_64-pc-windows-gnu

# Build binary statis murni untuk Linux
RUN cargo build --release --target x86_64-unknown-linux-musl

# Output stage
FROM scratch AS artifacts
COPY --from=builder /app/target/x86_64-pc-windows-gnu/release/agent.exe /windows/agent.exe
COPY --from=builder /app/target/x86_64-pc-windows-gnu/release/controller.exe /windows/controller.exe
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/agent /linux/agent
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/controller /linux/controller
