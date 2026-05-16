# syntax=docker/dockerfile:1.7

# --- builder ------------------------------------------------------------------
FROM rust:1.94-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY static ./static

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo build --release && \
    cp target/release/bastion /bastion

# --- runtime ------------------------------------------------------------------
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV DATABASE_PATH=/data/bastion.db
ENV PORT=5180

COPY --from=builder /bastion /usr/local/bin/bastion

RUN mkdir -p /data
EXPOSE 5180

CMD ["/usr/local/bin/bastion"]
