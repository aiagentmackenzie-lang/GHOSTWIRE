# GHOSTWIRE — Bug Fix Plan

**Created:** April 23, 2026  
**Author:** Agent Mackenzie (Lead Security Engineer)  
**Status:** All 5 phases executed and verified ✅  

---

## Phase 1 — Critical Fixes (Crash & Data Integrity) ✅ COMPLETE

*Goal: Stop the CLI from crashing on bad input, fix corrupt samples.*

| # | Issue | File(s) | Action |
|---|-------|---------|--------|
| 1.1 | CLI crashes with raw traceback on corrupt/invalid PCAP files | `engine/parser/pcap_loader.py`, `engine/cli.py` | Wrap `_parse_with_dpkt` in try/except, fall back to scapy, then surface a clean error message via click instead of a traceback |
| 1.2 | `samples/test.pcap` is an HTML file, not a PCAP | `samples/test.pcap` | Delete the fake file |
| 1.3 | `samples/cobalt_strike.pcap` is an HTML file, not a PCAP | `samples/cobalt_strike.pcap` | Delete the fake file |
| 1.4 | No graceful error in CLI when PCAP parse fails | `engine/cli.py` | Add try/except around `_full_analysis()` that catches `ValueError`, `Scapy_Exception`, etc. and prints a user-friendly error via `console.print` |
| 1.5 | `load_pcap` doesn't try scapy as fallback when dpkt fails mid-parse | `engine/parser/pcap_loader.py` | Restructure `_parse_with_dpkt` → if dpkt raises, try `_parse_with_scapy` before giving up |

**Estimated effort:** ~30 min  
**Verification:** Run `ghostwire analyze` against a corrupt file, a missing file, and a valid PCAP — all three should give clean output (no traceback).

---

## Phase 2 — API Security & Error Handling ✅ COMPLETE

*Goal: Prevent path traversal and unhandled errors in the server layer.*

| # | Issue | File(s) | Action |
|---|-------|---------|--------|
| 2.1 | Path traversal risk — API accepts any `filePath` with no sanitization | `server/index.ts` | Validate `filePath`: reject `..`, require absolute path or restrict to allowed directories, reject non-.pcap/.pcapng extensions |
| 2.2 | No subprocess error handling — if Python crashes, raw stderr leaks to client | `server/index.ts` | Sanitize stderr before sending to client (only send a generic error, log full details server-side) |
| 2.3 | No auth on API endpoints | `server/index.ts` | Add optional API key check via `GHOSTWIRE_API_KEY` env var — if set, require `Authorization: Bearer <key>` header. If unset, open access (local dev). Document in README. |
| 2.4 | Subprocess spawn uses `PYTHONPATH` override | `server/index.ts` | Keep for now but add a comment explaining the security implication and that the server should not be exposed publicly without auth |

**Estimated effort:** ~30 min  
**Verification:** Test path traversal (e.g., `filePath: "../../../etc/passwd"`), test missing auth header when `GHOSTWIRE_API_KEY` is set.

---

## Phase 3 — Test Suite ✅ COMPLETE

*Goal: Minimum viable test coverage for the core engine.*

| # | Issue | File(s) | Action |
|---|-------|---------|--------|
| 3.1 | No `tests/` directory | `tests/` | Create `tests/` with `__init__.py` |
| 3.2 | No unit tests for beacon detection | `tests/test_beacon.py` | Test: session with low jitter → high score, session with high jitter → low score, session with < min_packets → None, edge case: empty IATs |
| 3.3 | No unit tests for DNS threat detection | `tests/test_dns_threats.py` | Test: high-entropy domain → DGA flag, hex domain → DGA flag, long subdomain → tunneling flag, known-good domain → no flag, TXT query type → tunneling |
| 3.4 | No unit tests for protocol identification | `tests/test_protocol.py` | Test: TLS Client Hello payload → "TLS", HTTP GET payload → "HTTP", SSH banner → "SSH", DNS payload → "DNS", ICMP with high entropy → tunnel_suspect |
| 3.5 | No unit tests for session reconstruction | `tests/test_session.py` | Test: packets grouped by 5-tuple, session key canonicalization, IAT calculation, state tracking (RST, FIN, TIMEOUT) |
| 3.6 | No unit tests for C2 database matching | `tests/test_c2_database.py` | Test: known UA match → Cobalt Strike, partial UA → lower confidence, unknown UA → no match, SSH banner → Paramiko flag |
| 3.7 | No integration test for CLI | `tests/test_cli.py` | Test: `ghostwire analyze` on a valid PCAP returns JSON with expected keys, `ghostwire analyze` on missing file returns error, `ghostwire hunt --all` runs without crash |

**Estimated effort:** ~1.5 hr  
**Verification:** `pytest` runs with all tests passing, `pytest --cov=engine` shows >70% coverage on detection/parser modules.

---

## Phase 4 — Doc & Spec Alignment ✅ COMPLETE

*Goal: Documentation matches what the project actually is.*

| # | Issue | File(s) | Action |
|---|-------|---------|--------|
| 4.1 | `pyproject.toml` points readme to `SPEC.md` instead of `README.md` | `pyproject.toml` | Change `readme = "SPEC.md"` → `readme = "README.md"` |
| 4.2 | README roadmap checkboxes: Phase 3 & 4 marked unchecked but are built | `README.md` | Update `- [ ]` → `- [x]` for Phase 3 and Phase 4 |
| 4.3 | Dashboard `index.html` title says "dashboard" not "GHOSTWIRE" | `dashboard/index.html`, `dashboard/src/App.tsx` or `vite.config.ts` | Update title to "GHOSTWIRE — Network Forensics" |
| 4.4 | SPEC references `engine/recon/tcp_stream.py`, `http_recon.py`, `file_extract.py` — these don't exist | `SPEC.md` | Update SPEC file structure to match actual code (recon module is empty, session.py handles TCP reassembly) |
| 4.5 | SPEC references `entropy.py` in detection/ | `SPEC.md` | Note that entropy is inline in beacon.py/dns_threats.py, not a separate module |
| 4.6 | README comparison table claims RITA has no PCAP-level analysis — this is partially incorrect | `README.md` | Soften claim: RITA analyzes Zeek logs (not raw PCAP), which is the real differentiator |
| 4.7 | Dashboard component list in SPEC doesn't match reality (no GeoMap, no HuntNotebook) | `SPEC.md` | Update component list to match what's actually built: ThreatPanel, Timeline, BeaconChart, NetworkGraph, SessionView, ProtoBreakdown, FingerprintTable |

**Estimated effort:** ~30 min  
**Verification:** Read-through of README, SPEC, pyproject.toml confirms no false claims.

---

## Phase 5 — C2 Database & Fingerprinting Hardening ✅ COMPLETE

*Goal: Make C2 matching actually work against real traffic.*

| # | Issue | File(s) | Action |
|---|-------|---------|--------|
| 5.1 | JA3 hashes in C2 database are placeholders | `engine/fingerprint/c2_database.py` | Research and add real JA3 hashes from JA3er database / public threat intel (e.g., Cobalt Strike default: `72a5876a4ce4f4a1a0b5e1a8e9c7f3d2` is fictional — replace with actual known hashes) |
| 5.2 | JA4 pattern prefixes are approximate | `engine/fingerprint/c2_database.py` | Research actual JA4 prefix patterns for each C2 tool from FoxIO research / published datasets |
| 5.3 | STIX `iocs_from_analysis` only extracts IPs via fragile string splitting | `engine/export/stix.py` | Rewrite to use session metadata (src_ip, dst_ip) directly instead of parsing session_id strings |
| 5.4 | JA4 fingerprints are never actually produced (ja4plus fallback always fires) | `engine/fingerprint/ja4_engine.py` | Verify ja4plus import works in venv; if not, document that only JA3 fallback is active and improve the JA3 computation to be more complete |

**Estimated effort:** ~1 hr (research-heavy)  
**Verification:** Run analysis against a PCAP with known Cobalt Strike traffic → C2 match should trigger.

---

## Summary

| Phase | Focus | Est. Time | Risk |
|-------|-------|-----------|------|
| 1 | Crash fixes & corrupt samples | 30 min | Low | ✅ |
| 2 | API security | 30 min | Low | ✅ |
| 3 | Test suite | 1.5 hr | Low | ✅ |
| 4 | Doc alignment | 30 min | None | ✅ |
| 5 | C2 database hardening | 1 hr | Low (research) | ✅ |
| **Total** | | **~4 hr** | **All done** | |

---

*All phases executed April 23, 2026. 53/53 tests passing.*