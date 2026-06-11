# --- Build stage -----------------------------------------------------------
FROM rust:1-slim AS builder
WORKDIR /app

# Cache the dependency graph: build a dummy main against the real manifests
# so source edits don't invalidate the dependency layer.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY . .
RUN touch src/main.rs && cargo build --release && strip target/release/shipsafe

# --- Runtime stage ----------------------------------------------------------
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="ShipSafe" \
      org.opencontainers.image.description="AI-Powered Pre-Deploy Security Gate" \
      org.opencontainers.image.source="https://github.com/baneido/shipsafe" \
      org.opencontainers.image.licenses="MIT"

ARG TRIVY_VERSION=0.58.1
ARG GITLEAKS_VERSION=8.30.1

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip ca-certificates curl git \
    && pip3 install --no-cache-dir --break-system-packages semgrep \
    && curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
       | tar -xz -C /usr/local/bin trivy \
    && curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
       | tar -xz -C /usr/local/bin gitleaks \
    && apt-get purge -y --auto-remove curl \
    && rm -rf /var/lib/apt/lists/* /root/.cache

COPY --from=builder /app/target/release/shipsafe /usr/local/bin/shipsafe

RUN useradd --create-home --uid 10001 shipsafe \
    && mkdir -p /scan && chown shipsafe /scan
USER shipsafe
WORKDIR /scan

ENTRYPOINT ["shipsafe"]
CMD ["scan"]
