# GHOSTWIRE — Network Forensics Engine

> *"The wire remembers everything."*

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Status](https://img.shields.io/badge/Status-Beta-blue?style=flat)

GHOSTWIRE is a developer-built network forensics engine that combines C2 beacon detection, JA4+ fingerprinting, and session reconstruction into one focused hunting tool. Not an enterprise SIEM — a fast, self-contained workbench for analysts.

## Features

- **PCAP/PCAPNG Ingestion** — Streaming parse (dpkt fast-path, scapy fallback) with IPv4 + IPv6; memory-bounded session accumulation so a large SPAN capture does not OOM the process
- **Protocol Decoding** — HTTP, DNS, TLS (SNI extraction), SSH, ICMP tunnel detection
- **TCP Session Reconstruction** — 5-tuple grouping, sequence-number-ordered reassembly with retransmit dedup and a per-direction head cap, state tracking (SYN/FIN/RST). A ClientHello split across TCP segments is stitched back together before fingerprinting (so real captures fingerprint, not just single-segment fixtures).
- **JA4+ Fingerprinting** — TLS (JA4/JA4S), HTTP (JA4H), SSH (JA4SSH) client fingerprinting via the official `ja4plus` library, plus a spec-compliant JA3 computed from the parsed ClientHello (revision recorded with every result)
- **C2 Beacon Detection** — Statistical jitter analysis, volume asymmetry, connection regularity, Shannon entropy scoring
- **DNS Threat Detection** — DGA detection, DNS tunneling, suspicious query patterns
- **C2 Tool Matching** — Indicator database for Cobalt Strike, Metasploit, Sliver, Havoc, Brute Ratel, Covenant (exact User-Agent matches against documented defaults; JA4 prefix matches as research-tier hints). No fabricated JA3 hashes are shipped.
- **Composite Threat Scoring** — Weighted scoring across all detection signals, with a strong-beacon floor so a textbook beacon is never drowned to LOW
- **Hunt Mode** — Six built-in hunt queries (beacons, Cobalt Strike, DNS tunneling, data exfil, lateral movement, encrypted C2)
- **Detection Mindset** — Every signal is designed for threat hunting and incident response, not automated blocking or disruption
- **STIX 2.1 Export** — Industry-standard IOC sharing with MITRE ATT&CK relationships
- **MITRE ATT&CK Mapping** — Detections mapped to enterprise tactics/techniques
- **Report Generator** — Markdown, text, and STIX report output
- **Rich CLI Output** — Dark-themed terminal dashboard with tables and highlights
- **React Dashboard + API** — Optional Fastify API server and Vite/React dashboard for browser-based hunting

## Production readiness (v0.3.0)

GHOSTWIRE ships the operational baseline a real tool needs, not just a demo:

- **CI on every push** — ruff + mypy (strict, with `typings/` stubs so the dpkt/scapy/ja4plus boundary is not blind) + pytest (Python 3.10-3.13 matrix) + server typecheck + server tests + dashboard tests (`.github/workflows/ci-pipeline.yml`).
- **Server safety** — body/request/handler timeouts, 500 MiB PCAP pre-check (413), subprocess timeout -> SIGTERM -> SIGKILL -> 504, per-IP rate limiting, loopback-by-default + fail-closed non-loopback binding.
- **Durable job store** — `better-sqlite3` backed; `/api/analyze` returns a `jobId` immediately and runs async, so concurrent analyses no longer clobber each other; `/api/jobs` + `/api/jobs/:id` to poll.
- **Audit log** — append-only JSON-lines, one line per analysis, written outside the engine's write path; rotates at 100 MiB keeping the last 10.
- **Streaming + memory-bounded (bounded, not a whole-process guarantee)** — `iter_packet_records` yields packets one at a time, so the capture is not held in memory. Per-direction stored payload is head-capped at **16 KiB** (`GHOSTWIRE_MAX_PAYLOAD_BYTES`) with a total-bytes counter so volume scoring survives capping; session fan-out is capped at **20,000** (`GHOSTWIRE_MAX_SESSIONS`). Inter-arrival lists and dropped-session counts still grow with traffic, and the report command retains packets for display — treat "bounded" as applying to the capture payload, not as a measured RSS ceiling. The audit's 64 KiB / 50k figures were the README's, not the code's; they now match the code.
- **C2 IOC feeds** — `engine/feeds/` lets operators extend the runtime C2 database from cited external feed files (`ghostwire refresh-feeds`). No invented hashes; CIRCL/MISP hash feeds require a license check before bundling.
- **Detection honesty** — a benign-traffic corpus asserts zero findings on *synthetic* browsing traffic (`beacons_detected == 0`, `c2_matches == 0`, `dns_threats == 0`); known-positive corpora assert beacons/DNS/C2-UA are detected. These are regression controls on fixtures, **not a measured false-positive rate**: field precision/recall on held-out traffic is unmeasured (Wave 3 work). See `tests/corpus/README.md`.
- **Evidence contract** — one versioned result (`schema_version` 1.0) answers which capture/frames, which field, which rule, and what was unavailable; `complete` / `partial` / `unsupported_decode` / `empty` coverage states are surfaced in every view. Older saved jobs open through a compatibility adapter that marks missing detail instead of guessing.
- **Runtime** — Python 3.10+; **Node >= 22** for the server/dashboard (`engines` + `.nvmrc`; CI and Docker use 22, verified on 22 and 26). `better-sqlite3` 13 ships N-API prebuilds, so one install works across those versions.
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

**Auth boundary (v0.2.1):** the dashboard shell at `/` and all static assets are
served **without** auth; only `/api/*` and `/ws` require the key. Open
`http://localhost:3001` in a browser and enter `GHOSTWIRE_API_KEY` in the
prompt — the key is stored in the browser (`localStorage`) and sent as
`Authorization: Bearer` on API calls. It is never baked into the JS bundle
(baking the build-time `VITE_API_TOKEN` would ship the secret to anyone who
loads `/`, defeating API auth — fixed in v0.2.1).

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
| `GHOSTWIRE_API_KEY` | unset | If set, the **API** (`/api/*`) and WebSocket require `Authorization: Bearer <key>` (or `?token=` for `/ws`). The dashboard HTML shell and static assets are served **without** auth — browsers cannot send a Bearer header on plain navigation, so the operator enters the key in the dashboard UI (stored in browser `localStorage`, never baked into the JS bundle). Unset = open, loopback-only. |
| `GHOSTWIRE_ALLOWED_DIRS` | `<project>/samples` | Colon-separated PCAP directory allowlist. |
| `GHOSTWIRE_MAX_PCAP_BYTES` | `524288000` | Max PCAP size; oversize -> 413 (no subprocess spawned). |
| `GHOSTWIRE_ANALYSIS_TIMEOUT_MS` | `240000` | Subprocess timeout -> SIGTERM -> SIGKILL -> 504. |
| `GHOSTWIRE_RATE_MAX` / `GHOSTWIRE_RATE_WINDOW` | `20` / `1 minute` | Per-IP rate limit on `/api/analyze`. |
| `GHOSTWIRE_DATA_DIR` | `<project>/data` | SQLite job store + audit log location. |
| `GHOSTWIRE_FEEDS_DIR` | `engine/feeds` | C2 IOC feed directory (Phase 4.2). |
| `GHOSTWIRE_MAX_PAYLOAD_BYTES` | `16384` | Per-direction stored-payload head cap (bytes). Volume counters still count every transmitted byte. |
| `GHOSTWIRE_MAX_SESSIONS` | `20000` | Hard cap on reconstructed conversations; the number dropped is reported in `coverage`. |
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

JA3 is always computed from the parsed ClientHello as
`MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)` with `-`
inside each list and `,` between the five fields (the published algorithm).
The producing revision is recorded in every result as
`run.versions.ja3_algorithm`; values written by 0.2.x used comma delimiters
everywhere and are labelled `ghostwire-ja3-comma-v0.2`. Do not compare a
historical digest with a current one.

The conformance check is not the project's own fixture (one cipher, one
extension cannot reveal a delimiter bug). It replays the TCP payloads of
Wireshark's `test/captures/tls13-rfc8446.pcap`, pinned by commit
`62874e37` and SHA-256 in `tests/fixtures/wireshark_tls13_rfc8446.json`, and
asserts the published reference digests
`25bd5fc6fcc031c1c87f93613e0252ce` (frame 1) and
`7ed44a80eb19c620609c3b5cbc2eafd0` (frame 7). The check is offline; refresh
the fixture with `python tests/fixtures/fetch_wireshark_tls13.py`.

Matches against known C2 tool indicators for Cobalt Strike, Sliver,
Metasploit, and more. A rule match is a match on an observed field — it is
reported as an inference, not as confirmation that a host is compromised.

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

## Evidence, coverage and result schema (0.3.0)

Every analysis writes one versioned result (`schema_version: "1.0"`) that
answers four questions. `analyze --output json`, the API job result, the
reports and the dashboard all read this one object.

- **Which capture and frames?** `run.capture` holds the SHA-256, declared link
  type, the parser that actually produced the records (including a dpkt→scapy
  fallback), frames read/decoded, and the observed time bounds.
  `observations[].frame` is a one-based frame number.
- **Which field?** `observations[].field` (`dns.query_name`,
  `http.header.user-agent`, `tls.client_hello.ja3`, ...) with `value` exactly as
  observed and `normalized_value` when a rule compared a normalised form.
  Stream-derived observations also carry the sequence ranges, gaps and the
  evidence for the client/server role.
- **Which rule?** `findings[].rule` (id, revision, source file) plus
  `findings[].reasons[]`, each naming the observation and the score it
  contributed on a named scale.
- **What was unavailable?** `coverage.status` is one of `complete`, `partial`,
  `unsupported_decode` or `empty`, with reasons. `unsupported_decode` means
  frames were read and none decoded — a zero finding count there is *not* an
  all-clear. `partial` means frames or stream bytes were lost.

Three outcomes that used to look identical are now distinct: a complete
analysis with no rule match, a result filtered by the session threshold (the
findings are still listed; `selection.explanation` says so), and a partial or
unsupported decode.

**Counting units.** `packets_total` counts frames; `protocol_counts` is frames
per decoded protocol (one denominator); `sessions_total` counts reconstructed
5-tuples; a *finding* is one rule interpretation of one observed subject; a
*conversation row* is a scored session and is the only thing `--min-score`
filters. DNS findings are standalone — a DNS query has no TCP session, so it is
reported with its own frame reference and is never attributed to a TCP session
because of a shared address or timestamp.

**Export policy (STIX 2.1).** An indicator is raised only for the subject a rule
matched: the DNS name, or the HTTP request header value (patterned on
`network-traffic:extensions.'http-request-ext'`). Every indicator carries
`x_ghostwire_provenance` (capture digest, frames, rule, reasons). Addresses are
exported as SCOs inside `observed-data` — conversation context, not indicators;
an indicator decision needs its own basis. Findings with no standard STIX
patterning target (TLS/SSH fingerprints) are exported as
`x-ghostwire-finding` with an explicit `export_disposition` rather than forced
into an invalid pattern. `validate_bundle` checks format; `import_bundle`
checks meaning.

## Testing

```bash
pip install -e ".[dev]"
ruff check engine/ tests/
mypy engine
python -m pytest -q

# server + dashboard (Node 22 is required for better-sqlite3 prebuilds)
npm install && npm test
cd dashboard && npm run test && npm run build
```

The test suite synthesizes its own PCAPs (beacon, TLS-with-SNI, DNS-tunnel, CS-UA HTTP, split/truncated/reversed ClientHellos, duplicate segments, a server-first excerpt) in `tests/conftest.py` via scapy, so it runs on a fresh clone with no binary capture committed. The one external reference is reduced to the TCP payload bytes of Wireshark's TLS 1.3 capture, with attribution and a refresh script (see above).

`server/e2e.test.ts` runs a real capture through the real Python engine and the Fastify job store, then compares the API result with the CLI. It skips (with a reason) when `.venv` is absent, so a Node-only checkout still runs `npm test`.

## Why GHOSTWIRE?

The table records **documented capabilities as of 2026-11**, from each project's
public documentation. It is not a benchmark: no capture was run through the
other tools for this repository, and capability presence says nothing about
accuracy, scale or operational maturity. Every ✅ for GHOSTWIRE is covered by a
test in this repo; every ❌ for another tool is "not documented as a built-in",
not "cannot be built".

| Capability | RITA | Malcolm | Arkime | GHOSTWIRE |
|---------|------|---------|--------|-----------|
| Built-in C2 beacon scoring | ✅ | ❌ | ❌ | ✅ |
| JA4/JA4H/JA4SSH fingerprinting | ❌ | ❌ | ❌ | ✅ |
| Reads raw PCAP directly | ❌ (Zeek logs) | ✅ | ✅ | ✅ |
| Built-in DNS tunneling heuristic | ❌ | ❌ | ❌ | ✅ |
| Single-process, no infrastructure | ❌ | ❌ | ❌ | ✅ |

What this table does **not** establish: detection accuracy, false-positive
rate, throughput, or fitness for a production SOC. GHOSTWIRE is a beta
workbench; its accuracy on held-out traffic has not been measured.

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
- [x] Dashboard auth boundary inversion + operator-entered API key (no secret baked into the JS bundle; `/api/*` and `/ws` gated, dashboard shell public) — v0.2.1
- [x] Wave 1 evidence contract: observations, findings, coverage states, selection counters, saved-job compatibility, reanalysis — v0.3.0
- [x] JA3 conformance against Wireshark's TLS 1.3 reference capture; historical digests labelled by algorithm revision — v0.3.0
- [ ] JA4X (X.509 certificate fingerprinting)
- [ ] Runtime C2 feed fetch (currently bundled / local-dir only)
- [ ] Multi-worker rate limiting (Redis; per-process today)

## License

MIT

---

*Designed by Raphael Main + Agent Mackenzie. Built for analysts who hunt — defensively.*