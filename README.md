# GHOSTWIRE — Network Forensics Engine

> *"The wire remembers everything."*

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Status](https://img.shields.io/badge/Status-Beta-blue?style=flat)

GHOSTWIRE is a developer-built network forensics engine that combines C2 beacon detection, JA4+ fingerprinting, and session reconstruction into one focused hunting tool. Not an enterprise SIEM — a weapon for analysts.

## Features

- **PCAP/PCAPNG Ingestion** — Streaming parse (dpkt fast-path, scapy fallback) with IPv4 + IPv6; memory-bounded session accumulation so a large SPAN capture does not OOM the process
- **Protocol Decoding** — HTTP, DNS, TLS (SNI extraction), SSH, ICMP tunnel detection
- **TCP Session Reconstruction** — 5-tuple grouping, sequence-number-ordered reassembly with retransmit dedup and a per-direction head cap, state tracking (SYN/FIN/RST). A ClientHello split across TCP segments is stitched back together before fingerprinting (so real captures fingerprint, not just single-segment fixtures).
- **JA4+ Fingerprinting** — TLS (JA4/JA4S), HTTP (JA4H), SSH (JA4SSH) client fingerprinting via the official `ja4plus` library, with a spec-compliant JA3 fallback when `ja4plus` is unavailable
- **C2 Beacon Detection** — Statistical jitter analysis, volume asymmetry, connection regularity, Shannon entropy scoring
- **DNS Threat Detection** — DGA detection, DNS tunneling, suspicious query patterns
- **C2 Tool Matching** — Indicator database for Cobalt Strike, Metasploit, Sliver, Havoc, Brute Ratel, Covenant (exact User-Agent matches against documented defaults; JA4 prefix matches as research-tier hints). No fabricated JA3 hashes are shipped.
- **Composite Threat Scoring** — Weighted scoring across all detection signals, with a strong-beacon floor so a textbook beacon is never drowned to LOW
- **Hunt Mode** — Six built-in hunt queries (beacons, Cobalt Strike, DNS tunneling, data exfil, lateral movement, encrypted C2)
- **STIX 2.1 Export** — Industry-standard IOC sharing with MITRE ATT&CK relationships
- **MITRE ATT&CK Mapping** — Detections mapped to enterprise tactics/techniques
- **Report Generator** — Markdown, text, and STIX report output
- **Rich CLI Output** — Dark-themed terminal dashboard with tables and highlights
- **React Dashboard + API** — Optional Fastify API server and Vite/React dashboard for browser-based hunting

## Production readiness (v0.2.0)

GHOSTWIRE ships the operational baseline a real tool needs, not just a demo:

- **CI on every push** — ruff + mypy (strict, with `typings/` stubs so the dpkt/scapy/ja4plus boundary is not blind) + pytest (Python 3.10-3.13 matrix) + server typecheck + server tests + dashboard tests (`.github/workflows/ci.yml`).
- **Server safety** — body/request/handler timeouts, 500 MiB PCAP pre-check (413), subprocess timeout -> SIGTERM -> SIGKILL -> 504, per-IP rate limiting, loopback-by-default + fail-closed non-loopback binding.
- **Durable job store** — `better-sqlite3` backed; `/api/analyze` returns a `jobId` immediately and runs async, so concurrent analyses no longer clobber each other; `/api/jobs` + `/api/jobs/:id` to poll.
- **Audit log** — append-only JSON-lines, one line per analysis, written outside the engine's write path; rotates at 100 MiB keeping the last 10.
- **Streaming + memory-bounded** — `iter_packet_records` yields packets one at a time; per-session payload is head-capped (64 KiB) with a total-bytes counter so volume scoring survives capping; session fan-out capped at 50k.
- **C2 IOC feeds** — `engine/feeds/` lets operators extend the runtime C2 database from cited external feed files (`ghostwire refresh-feeds`). No invented hashes; CIRCL/MISP hash feeds require a license check before bundling.
- **Detection honesty** — a benign-traffic corpus asserts zero false positives (`beacons_detected == 0`, `c2_matches == 0`, `dns_threats == 0`); known-positive corpora assert beacons/DNS/C2-UA are detected. See `tests/corpus/README.md`.
- **Deployment** — multi-stage Dockerfile (non-root, healthcheck), `docker compose up` single-host deploy, GHCR publish on tag (OIDC, multi-arch). PyPI is intentionally deferred.

See `PRODUCTION_PLAN.md` (local-only) for the full path and `tests/corpus/README.md` for the detection-accuracy policy.

## Quick Start

### CLI

```bash
# Install
git clone https://github.com/aiagentmackenzie-lang/GHOSTWIRE.git
cd GHOSTWIRE
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Analyze a PCAP
ghostwire analyze capture.pcap

# JSON output for automation
ghostwire analyze capture.pcap --output json

# Adjust sensitivity
ghostwire analyze capture.pcap --min-score 0.1 --min-packets 5

# Use specific parser
ghostwire analyze capture.pcap --parser scapy

# Hunt mode
ghostwire hunt capture.pcap --all
ghostwire hunt capture.pcap --query cobalt_strike

# Generate a report
ghostwire report capture.pcap --format markdown -o report.md
ghostwire report capture.pcap --format stix -o report.stix.json
```

### Docker (single-image deploy)

```bash
cp .env.example .env          # set GHOSTWIRE_API_KEY (required for non-loopback)
docker compose up --build     # dashboard + API at http://localhost:3001
# drop captures into ./samples/ and POST /api/analyze { "filePath": "/data/samples/x.pcap" }
```

The image binds `0.0.0.0` and refuses to start without `GHOSTWIRE_API_KEY`
(fail-closed). Captures are read from `/data/samples` (mount `./samples:ro`);
the SQLite job store + audit log persist in a named volume.

### Dashboard + API server (optional)

```bash
# Install server/dashboard deps
npm install

# Launch both the API server (loopback :3001) and the dashboard (:5173)
./start.sh
```

Then open `http://localhost:5173`. The API server binds `127.0.0.1` by default
and reads PCAPs only from `samples/` unless `GHOSTWIRE_ALLOWED_DIRS` is set. To
expose it on the network, set **both** `GHOSTWIRE_HOST=0.0.0.0` **and**
`GHOSTWIRE_API_KEY=<secret>` — the server refuses to start non-loopback without
a key (fail-closed).

| Env var | Default | Purpose |
|--------|---------|---------|
| `GHOSTWIRE_HOST` | `127.0.0.1` | Bind address. Non-loopback requires `GHOSTWIRE_API_KEY`. |
| `GHOSTWIRE_API_KEY` | unset | If set, requires `Authorization: Bearer <key>` (and `?token=` for WebSocket). Unset = open, loopback-only. |
| `GHOSTWIRE_ALLOWED_DIRS` | `<project>/samples` | Colon-separated PCAP directory allowlist. |
| `GHOSTWIRE_MAX_PCAP_BYTES` | `524288000` | Max PCAP size; oversize -> 413 (no subprocess spawned). |
| `GHOSTWIRE_ANALYSIS_TIMEOUT_MS` | `240000` | Subprocess timeout -> SIGTERM -> SIGKILL -> 504. |
| `GHOSTWIRE_RATE_MAX` / `GHOSTWIRE_RATE_WINDOW` | `20` / `1 minute` | Per-IP rate limit on `/api/analyze`. |
| `GHOSTWIRE_DATA_DIR` | `<project>/data` | SQLite job store + audit log location. |
| `GHOSTWIRE_FEEDS_DIR` | `engine/feeds` | C2 IOC feed directory (Phase 4.2). |
| `GHOSTWIRE_PYTHON_BIN` | `.venv/bin/python3` | Interpreter the server shells out to. |
| `PORT` | `3001` | API server port. |

See `.env.example` for the full list.

## How It Works

```
PCAP File → Parser → Protocol Decoder → Session Reconstructor
                                          ↓
                               JA4+ Fingerprinting ←→ C2 Database
                                          ↓
                               C2 Beacon Detector
                               DNS Threat Detector
                                          ↓
                               Composite Threat Scorer
                                          ↓
                               CLI Dashboard / JSON / STIX / Report
```

### C2 Beacon Detection Algorithm

1. **Jitter Analysis** — Inter-arrival time (IAT) jitter ratio (sample std/mean). Beacons have consistent intervals → jitter < 0.1 → jitter_score 0.95.
2. **Volume Asymmetry** — C2 traffic is typically asymmetric (small request, variable response).
3. **Connection Regularity** — Long-duration low-rate sessions sustained over time.
4. **Entropy Scoring** — Encrypted C2 channels show high Shannon entropy (>7.5).

The composite scorer weights these 40/20/25/15 (jitter/volume/regularity/entropy). When the beacon detector itself is HIGH/CRITICAL, the beacon score becomes the floor for the overall score — so a textbook beacon isn't drowned to LOW when C2/DNS signals are absent.

### JA4+ Fingerprinting

Uses the official `ja4plus` library for TLS/TCP/HTTP/SSH fingerprinting:
- **JA4** — TLS client fingerprint (successor to JA3), via `ja4plus.generate_ja4`
- **JA4S** — TLS server fingerprint, via `ja4plus.generate_ja4s`
- **JA4H** — HTTP client fingerprint, via `ja4plus.generate_ja4h`
- **JA4SSH** — SSH client fingerprint, via `ja4plus.generate_ja4ssh`

When `ja4plus` is unavailable, JA4H/JA4SSH fall back to clearly-marked `local_` hashes and JA3 falls back to a spec-compliant 5-field hash (TLSVersion, Ciphers, Extensions, EllipticCurves, ECPointFormats). Matches against known C2 tool indicators for Cobalt Strike, Sliver, Metasploit, and more.

> **Note on JA4X (X.509 certificate fingerprinting):** `ja4plus` ships a `generate_ja4x` API; GHOSTWIRE does not yet wire it. It is on the roadmap, not in the current build.

## Architecture

| Module | Purpose |
|--------|---------|
| `engine/parser/` | PCAP loading (dpkt/scapy), protocol decoding, session reconstruction |
| `engine/fingerprint/` | JA4+/JA3/JA4H/JA4SSH fingerprinting, C2 tool matching |
| `engine/detection/` | Beacon detection, DNS threats, composite scoring, hunt queries |
| `engine/export/` | STIX 2.1 export, MITRE ATT&CK mapping, report generator |
| `engine/cli.py` | CLI interface (click + rich) |
| `server/` | Optional Fastify API server + WebSocket (TypeScript) |
| `dashboard/` | Optional Vite + React hunting dashboard |
| `tests/` | Self-contained suite (scapy-generated PCAP fixtures — runs on a fresh clone) |

## Testing

```bash
pip install -e ".[dev]"
ruff check engine/ tests/
mypy engine
python -m pytest -q
```

The test suite synthesizes its own PCAPs (beacon, TLS-with-SNI, DNS-tunnel, CS-UA HTTP) in `tests/conftest.py` via scapy, so it runs on a fresh clone with no binary fixtures committed.

## Why GHOSTWIRE?

| Feature | RITA | Malcolm | Arkime | GHOSTWIRE |
|---------|------|---------|--------|-----------|
| C2 beacon detection | ✅ | ❌ | ❌ | ✅ |
| JA4+ fingerprinting | ❌ | ❌ | ❌ | ✅ |
| Single developer built | ❌ | ❌ | ❌ | ✅ |
| No infrastructure needed | ❌ | ❌ | ❌ | ✅ |
| PCAP-level analysis | ❌* | ✅ | ✅ | ✅ |
| DNS threat detection | ❌ | ❌ | ❌ | ✅ |

*RITA analyzes Zeek/Zeek logs (not raw PCAP directly), which is the real differentiator.

## Roadmap

- [x] Phase 1: PCAP parser + protocol decoder + JA4+ fingerprinting + C2 matching
- [x] Phase 2: C2 beacon detector + DNS threats + composite scoring
- [x] Phase 3: React dashboard (timeline, beacon chart, network graph, session view, protocol breakdown, fingerprint table) + Fastify API
- [x] Phase 4: STIX 2.1 export + MITRE ATT&CK mapping + report generator + hunt mode
- [x] Sequence-number-based TCP reassembly (out-of-order / retransmit handling) — v0.2.0
- [x] IPv6 parse + private-range detection — v0.2.0
- [x] Streaming, memory-bounded analysis (no OOM on large captures) — v0.2.0
- [x] SQLite job store + rotating audit log + async API — v0.2.0
- [x] CI (ruff/mypy/pytest matrix + server + dashboard), Dockerfile, GHCR — v0.2.0
- [x] C2 IOC feed loader + `refresh-feeds` CLI — v0.2.0
- [x] DNS compression-pointer handling + strict DNS validation (reject non-DNS UDP, fail-closed on garbage qtypes/labels) — v0.2.0
- [x] NetBIOS Name Service (NBNS/UDP 137) suppression — fixed 32-char A-P encoded names no longer flag as DNS tunneling — v0.2.0
- [ ] JA4X (X.509 certificate fingerprinting)
- [ ] Runtime C2 feed fetch (currently bundled / local-dir only)
- [ ] Multi-worker rate limiting (Redis; per-process today)

## License

MIT

---

*Designed by Raphael Main + Agent Mackenzie. Built for analysts who hunt.*