# syntax=docker/dockerfile:1.7

# --- builder ------------------------------------------------------------------
FROM rust:1.94-bookworm AS builder
WORKDIR /app

# Cache deps
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src target/release/deps/bastion*

COPY . .
RUN cargo build --release

# --- runtime ------------------------------------------------------------------
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV DATABASE_PATH=/data/bastion.db
ENV PORT=5180

COPY --from=builder /app/target/release/bastion /usr/local/bin/bastion

RUN mkdir -p /data
EXPOSE 5180

CMD ["/usr/local/bin/bastion"]
