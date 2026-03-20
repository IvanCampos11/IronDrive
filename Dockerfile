# syntax=docker/dockerfile:1.7

FROM rust:1.86-bookworm AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        pkg-config \
        libsqlite3-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY templates ./templates
COPY static ./static
COPY Rocket.toml ./Rocket.toml

RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime

ENV APP_HOME=/app \
    RUST_LOG=info \
    IRONDRIVE_DATA_DIR=/var/lib/irondrive/data \
    IRONDRIVE_DB_DIR=/var/lib/irondrive/db

WORKDIR ${APP_HOME}

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        tzdata \
        libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system irondrive \
    && useradd --system --gid irondrive --home-dir /var/lib/irondrive --create-home irondrive \
    && mkdir -p /var/lib/irondrive/data /var/lib/irondrive/db

COPY --from=builder /app/target/release/irondrive /usr/local/bin/irondrive
COPY --from=builder /app/Rocket.toml ${APP_HOME}/Rocket.toml
COPY --from=builder /app/templates ${APP_HOME}/templates
COPY --from=builder /app/static ${APP_HOME}/static
COPY --from=builder /app/migrations ${APP_HOME}/migrations

RUN chown -R irondrive:irondrive /var/lib/irondrive ${APP_HOME}

USER irondrive

EXPOSE 8000
VOLUME ["/var/lib/irondrive/data", "/var/lib/irondrive/db"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 \
  CMD curl -fsS http://127.0.0.1:8000/health > /dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/irondrive"]
