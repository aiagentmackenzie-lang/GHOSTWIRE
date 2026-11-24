# Changelog

All notable changes to GHOSTWIRE. Versions are semver; the result `schema_version`
is versioned separately (see `engine/evidence.py`).

## [0.3.0] — 2026-11-23 — Wave 1: trustworthy findings

The engine now carries evidence from the frame to the analyst: which capture and
frames support a finding, which field was observed, which rule interpreted it,
and what the analysis could not examine. Every interface (CLI, JSON, reports,
STIX, API, saved jobs, dashboard) reads the same versioned result.

### Added
- **Result schema `1.0`** (`engine/evidence.py`, `engine/analysis.py`):
  `run`, `coverage`, `observations`, `findings`, `conversations`, `selection`.
  0.2.x top-level JSON fields are retained.
- **Observations** with one-based frame references, capture timestamp, transport,
  typed endpoints in the observed direction, field name, the value exactly as
  observed, a separate normalised value, and — for stream-derived fields —
  sequence ranges, gaps and the evidence for the client/server role.
- **Coverage states** `complete` / `partial` / `unsupported_decode` / `empty`
  with reasons, declared link type, the parser that actually produced the
  records (including dpkt→scapy fallback), frames read/decoded, dropped
  sessions, stream gaps and head-capped directions.
- **Findings** with a stable content-hash id, rule id + revision + source,
  match method, named score scale, per-reason contributions, conversation link
  and basis, and provenance.
- **Selection counters** (`findings_total/returned`, `sessions_total/scored/
  eligible/returned`), filter and truncation metadata, and an explanation, so an
  empty session table can be told apart from an empty capture.
- **Saved-job compatibility** (`server/legacy.ts`): `current` / `legacy` /
  `unsupported` / `absent`. Unversioned 0.2.x summaries keep recorded counts,
  scores, labels and IOC text and mark missing structure as unavailable; an
  unknown schema is returned with its original payload preserved.
- `GET /api/jobs/:id/result` and `POST /api/jobs/:id/reanalyze` (new job row with
  `parentJobId`; the original result is never rewritten).
- SQLite migration adds `schema_version`, `engine_version`, `capture_sha256`,
  `request_json`, `parent_job_id` in place.
- **Raw-IP and link-type-aware framing** (Ethernet, raw IPv4/IPv6, BSD loopback,
  Linux cooked); unsupported framings are reported instead of yielding silent
  empty packets.
- **JA3 conformance against an independent reference** (Wireshark
  `tls13-rfc8446.pcap`, pinned commit + sha256), reproducible offline.
- `legacy_comma_ja3()` and `run.versions.ja3_algorithm` so historical digests
  remain identifiable by their producing revision.
- Dashboard: findings inspector (frame, field, value, ranges, gaps, reasons),
  measured timestamps, saved-job loader, compatibility banner, persistent demo
  marker.

### Fixed
- **DNS attribution.** A DNS query no longer raises a TCP session score. On the
  audit's combined fixture the HTTP session was 0.565 because capture-wide DNS
  was added to it; it is 0.315, and the DNS finding is reported separately with
  its own frame and reasons.
- **HTTP attribution.** A matched User-Agent is attached to the 5-tuple that
  supplied the header, never to another session sharing the client address. The
  structured `c2_matches` array is no longer empty while the prose names a match.
- **JA3 serialisation.** Elements inside each JA3 field are joined with `-` and
  the five fields with `,` (the published algorithm). Reference digests:
  frame 1 `25bd5fc6fcc031c1c87f93613e0252ce` (was `9787a0eb…`), frame 7
  `7ed44a80eb19c620609c3b5cbc2eafd0` (was `8c5f06f9…`).
- **Reassembly continuity.** Bytes captured before and after a hole are no
  longer concatenated; the stored payload is the contiguous prefix and the
  missing bytes are reported (audit fixture: 19 missing bytes, two ranges).
- **Duplicate segments** no longer corrupt the stream: first transmission of a
  sequence byte wins (107 captured / 77 distinct bytes, not 107 concatenated).
- **Timing.** Duration comes from observed time bounds, not file order
  (reversed capture: +1 ms and an ordering anomaly, not −1 ms); epoch zero is a
  valid timestamp (IPv6 span 1440.5 s on both streaming and eager paths).
- **Roles.** A capture that begins on the server side reports the observed
  ServerHello with `client_side: "dst"` instead of inventing a client handshake.
- Version mismatch (engine reported 0.2.0 while the package declared 0.2.1).
- Hard-coded `analysis_time: 0` in reports replaced with measured elapsed time.
- Protocol breakdown denominators (a one-packet DNS capture reports DNS 100 %,
  not 50 %/50 %); dashboard beacon bars no longer use random numbers; the
  timeline uses real timestamps; the graph uses observed direction.
- Feed confidence is preserved on load, and feeds are loaded for JA3/HTTP/SSH
  lookups (previously only after a JA4 lookup).

### Changed (breaking)
- **STIX export**: indicators are raised only for the matched subject (DNS name,
  or the HTTP `User-Agent` via `network-traffic:extensions.'http-request-ext'`)
  with `x_ghostwire_provenance`. Peer addresses are `observed-data` SCOs, **not
  indicators** (0.2.x labelled both peers `c2_communication`). Findings without
  a standard STIX patterning target are exported as `x-ghostwire-finding` with
  an explicit `export_disposition`.
- **API defaults** are now `minScore 0.25` / `minPackets 10` (were `0.1` / `5`),
  matching the CLI. `/health` advertises them.
- `TCPSession.start_time`/`end_time` are the observed min/max timestamps.
- `client_payload`/`server_payload` are the contiguous prefix only; the full
  range list is available as `src_to_dst`/`dst_to_src` reassembly metadata.
- A session's DNS contribution to `score_session()` is only used when a DNS
  observation genuinely belongs to that conversation; the pipeline passes none.

### Build
- `better-sqlite3` `^11.10.0` → `^13.2.0` (N-API prebuilds, one install works on
  Node 22 and 26). `engines: node >=22` and `.nvmrc` added — the previous
  pin could not build on Node 26.

### Verification
244 Python tests (was 189), 27 server tests, 17 dashboard tests; ruff, mypy and
`tsc` clean; dashboard builds. Real-engine end-to-end compares API results with
the CLI, reports and STIX import, and the built dashboard was driven in a
headless browser.

## [0.2.1] — 2026-06-23
- Dashboard auth boundary inverted: `/api/*` and `/ws` are gated, the dashboard
  shell is public; the operator enters the API key in the browser.
- Strict DNS validation and compression-pointer handling; NetBIOS (NBNS)
  suppression.

## [0.2.0] — 2026-06-22
- Production pass: streaming/memory-bounded analysis, sequence-ordered TCP
  reassembly, IPv6, SQLite job store, async API, audit log, IO feeds, CI,
  Dockerfile.
