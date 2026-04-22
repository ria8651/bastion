# syntax=docker/dockerfile:1.7

# --- builder ------------------------------------------------------------------
FROM node:22-bookworm-slim AS builder
WORKDIR /app

# Build tools for better-sqlite3's native addon.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# --- runtime ------------------------------------------------------------------
FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
ENV DATABASE_PATH=/data/bastion.db
ENV PORT=5180

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Full node_modules (including drizzle-kit) comes across so we can
# `drizzle-kit push` at container start. No migrations yet — when the schema
# stops churning, swap for a proper migration run.
COPY --from=builder /app/build ./build
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./
COPY --from=builder /app/drizzle.config.ts ./
COPY --from=builder /app/src/lib/server/db/schema.ts ./src/lib/server/db/schema.ts

RUN mkdir -p /data

EXPOSE 5180

# Sync schema then start the SvelteKit node server.
CMD ["sh", "-c", "npx drizzle-kit push --force && node build"]
