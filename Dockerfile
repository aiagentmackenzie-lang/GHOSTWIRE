# syntax=docker/dockerfile:1
# GHOSTWIRE single-image deploy (decision Q1: on-prem / client box).
# Stage 1 builds the Python wheel, stage 2 builds the dashboard, stage 3 is the
# runtime: Node (server + tsx) + Python (engine) + dashboard static, non-root.

# ── Stage 1: Python wheel ───────────────────────────────────────────────────
FROM python:3.12-slim AS wheel
WORKDIR /build
COPY pyproject.toml README.md ./
COPY engine/ engine/
RUN pip install --no-cache-dir wheel \
 && pip wheel . --no-deps -w /wheels

# ── Stage 2: dashboard static build ─────────────────────────────────────────
FROM node:22-slim AS dash
WORKDIR /dash
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci
COPY dashboard/ ./
RUN npm run build

# ── Stage 3: runtime (Node + Python) ─────────────────────────────────────────
FROM node:22-slim AS final
# Python runtime + pip (scapy/dpkt/ja4plus are pure Python, no native build).
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install the engine wheel (pulls scapy/dpkt/ja4plus/rich/click from PyPI).
COPY --from=wheel /wheels/ghostwire-*.whl /tmp/
RUN pip3 install --no-cache-dir --break-system-packages /tmp/ghostwire-*.whl \
 && rm /tmp/ghostwire-*.whl

# Server deps (includes tsx, used to run server/index.ts).
COPY package.json package-lock.json ./
RUN npm ci
COPY server/ server/

# Built dashboard assets, served by the server at / (Phase 5).
COPY --from=dash /dash/dist /app/dashboard/dist

# Non-root user + writable data dir (job DB / audit log / mounted samples).
RUN useradd -r -u 1001 ghostwire \
 && mkdir -p /data/samples \
 && chown -R ghostwire:ghostwire /app /data
USER ghostwire

ENV GHOSTWIRE_PYTHON_BIN=python3 \
    GHOSTWIRE_ALLOWED_DIRS=/data/samples \
    GHOSTWIRE_DATA_DIR=/data \
    GHOSTWIRE_DASHBOARD_DIR=/app/dashboard/dist \
    NODE_PATH=/app/node_modules \
    PORT=3001 \
    GHOSTWIRE_HOST=0.0.0.0
# NOTE: binding 0.0.0.0 requires GHOSTWIRE_API_KEY (fail-closed) - operators MUST
# set it (see docker-compose / .env). The image refuses to start open+exposed.

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3001/health').then(r=>{process.exit(r.ok?0:1)}).catch(()=>process.exit(1))"

CMD ["npx", "tsx", "server/index.ts"]