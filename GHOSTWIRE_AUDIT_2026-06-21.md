# GHOSTWIRE — Production-Readiness Audit

**Date:** 2026-06-21
**Auditor:** Mackenzie, Lead Security Engineer (Pi)
**Reviewer target:** Claude Opus
**Method:** Code read + live verification (ran `pytest`, `ruff`, `analyze` on both sample PCAPs, constructed a real TLS ClientHello with SNI to test the headline feature)
**Prior audit:** `BUG_CATALOG.md` (May 15) — **gitignored**, not version-controlled. It caught 20 real bugs but missed the ship-blockers below and "documented" several things it never exercised.

---

## TL;DR — the headline

**GHOSTWIRE's flagship feature, JA4+ fingerprinting, does not work.** Not "partially" — it produces zero fingerprints on the project's own sample PCAP and empty strings on a correctly-built TLS ClientHello. The README's comparison table ("JA4+ fingerprinting: GHOSTWIRE ✅ / RITA ❌ / Malcolm ❌ / Arkime ❌") is the single biggest differentiator claimed, and it is vapor. Combined with a broken SNI extractor and a non-spec JA3 fallback, **C2 tool matching never fires in practice** (sample: `c2_matches: 0`). The tool currently functions as a jitter-only beacon detector that systematically scores a near-perfect beacon as "LOW."

Verification commands run:
- `python -m engine.cli analyze samples/c2_beacon_test.pcap --output json` → `tls_fingerprints: 0, c2_matches: 0`, one beacon scored `overall 0.30 / LOW`.
- Constructed a valid ClientHello with SNI extension → `decode_tls().sni == ''`, `fingerprint_tls().sni == ''`, `cipher_count == 256` (should be 1), `ext_count == 0` (should be 1), `ja4 == ''`.
- `python -m pytest -q` → 116 passed (local only; **CI would fail** — see F-04).
- `ruff check engine/` → clean (but no config; default rules only).
- `mypy` → **not installed**. No type gate exists.

Severity legend: 🔴 ship-blocker / lie · 🟠 real bug · 🟡 design smell / docs · 🟢 cosmetic.

---

## 🔴 CRITICAL — ship-blockers and untruths

### F-01 · JA4+ integration is broken — passes `bytes` to an API that expects a `dict`
**Files:** `engine/fingerprint/ja4_engine.py`, `ja4h_engine.py`, `ja4ssh_engine.py`
**Evidence:**
```python
# ja4_engine.py
result = ja4plus.generate_ja4(payload)   # payload is raw bytes
```
`ja4plus.generate_ja4` signature is `(tls_info)` and its first line is `tls_info.get('type') != 'client_hello'` — i.e. it expects a **dict**. Passing `bytes` raises `AttributeError`, which is swallowed by `except Exception`, and the code falls through to the JA3 path. **JA4, JA4S, JA4H, JA4SSH are always empty strings.** Same bug pattern in the HTTP and SSH engines (`generate_ja4h` / `generate_ja4ssh` also expect dicts/objects, not raw bytes).
**README claims:** "Uses the official `ja4plus` library for modern TLS/TCP/HTTP/SSH fingerprinting" — **vapor**.
**Impact:** The entire C2-matching-by-fingerprint path is dead. The comparison table's only "✅ where others are ❌" is a lie.
**Fix:** Use `ja4plus`'s parser/`JA4Fingerprinter` to build the `tls_info` dict from the ClientHello (ja4plus ships `utils` for this), or switch to a maintained binding. Either way, **add a test that asserts a non-empty `ja4` on a real ClientHello** — no such test exists today.

### F-02 · SNI extraction is off-by-one in both modules — and untested
**Files:** `engine/parser/protocol.py:decode_tls`, `engine/fingerprint/ja4_engine.py:fingerprint_tls`
**Root cause:** Both compute the ClientHello body offset as `6 + 4` (record header + handshake header). The record header is **5** bytes (`content_type(1) + version(2) + length(2)`), not 6. So every offset downstream is shifted by +1: session-id length is read from the wrong byte, cipher-suite length becomes garbage (e.g. `cs_len = 0x0200 = 512`), and the SNI extension loop never enters. Result: `sni == ''`, `cipher_count` and `ext_count` are nonsense.
**Telling inconsistency:** the JA3 fallback `_compute_ja3` in the *same file* uses `offset = 5 + 4` (correct). Someone copy-pasted and got it wrong in the SNI block.
**Why tests didn't catch it:** both `_build_tls_client_hello` (test_protocol.py) and `_make_tls_client_hello` (test_fingerprint.py) **omit the extensions block entirely**. The SNI/cipher_count/ext_count branches are dead-untested code that happens to be buggy.
**README claims:** "TLS (SNI extraction)" under Features. **Broken.** SNI is the single most important field for C2 hunting (which domain the beacon calls).
**Fix:** `5 + 4` not `6 + 4`; `5 + 4 + 2 + 32` not `6 + 4 + 2 + 32`. Then add a test that builds a ClientHello *with* an SNI extension and asserts `fp.sni == "evil.example.com"`.

### F-03 · README claims JA4X — it does not exist
**File:** `README.md` ("JA4+ Fingerprinting" → "JA4X — X.509 certificate fingerprint")
**Evidence:** `grep -rn "ja4x\|JA4X\|x509\|certificate" engine/` → no implementation. No `ja4x_engine.py`, no call to `ja4plus.generate_ja4x` (which does exist in the installed library). Pure vapor.
**Fix:** Delete the line, or implement it.

### F-04 · Integration tests depend on PCAPs that are `.gitignore`d — "116 passing" is local-only
**Files:** `.gitignore` (`*.pcap`, `*.pcapng`), `tests/test_cli.py`, `samples/*.pcap`
**Evidence:** `git ls-files | grep samples/` → **nothing tracked**. `test_cli.py` references `samples/c2_beacon_test.pcap` and `samples/test_mixed.pcap`, which exist only on this machine. A fresh `git clone` + `pip install -e .` + `pytest` → `FileNotFoundError` in `TestAnalyzeCommand`.
**BUG_CATALOG.md claims:** "Test Results: 116 passing, 0 failures" with no caveat. **Misleading** — this is not CI-verified; it's "passes on Raphael's laptop."
**Fix:** Either force-add small synthetic PCAPs (`git add -f samples/*.pcap` and drop `*.pcap` from `.gitignore` for the `samples/` dir), or generate fixtures in a conftest (`scapy` is already a dep — write a 20-line fixture builder). Until then, "production-grade" is not achievable.

---

## 🟠 HIGH — real bugs

### H-01 · `hunt` command never populates `protocol_result` metadata → `hunt_dns_tunneling` is dead in the CLI
**Files:** `engine/cli.py` (hunt command), `engine/detection/hunt.py:hunt_dns_tunneling`
**Evidence:** The `hunt` command's protocol loop only does `pkt.protocol_l7 = result.l7_protocol` — it does **not** store `pkt.metadata["protocol_result"]` (the `analyze` path does). `hunt_dns_tunneling` reads `pkt.metadata.get("protocol_result", {}).get("dns")` → always `None` → returns nothing.
**Why tests pass:** `test_hunt.py:test_txt_query_detected` manually sets `pkt.metadata = {"protocol_result": {"dns": ...}}`, bypassing the CLI path entirely. Classic "test passes, feature broken" pattern.
**Fix:** In the `hunt` command, store `pkt.metadata["protocol_result"] = asdict(result.dns)` etc., same as `_full_analysis`.

### H-02 · "Out-of-order handling" is not implemented — README lie
**File:** `engine/parser/session.py` (comment: *"Reassemble payloads (ordered by sequence — simplified; full reassembly would use seq numbers)"*)
**README claims:** "TCP Session Reconstruction — Stream reassembly, out-of-order handling, state tracking."
**Reality:** Payloads are concatenated in **timestamp order**, not sequence order. Out-of-order/retransmitted/duplicated segments are not handled. For a forensics tool that advertises stream reassembly, this silently produces corrupted streams on any non-trivial capture.
**Fix:** Implement seq-based reassembly (or at minimum: dedup by seq, drop retransmits), or downgrade the README to "payload concatenation (timestamp-ordered)".

### H-03 · JA3 fallback is not spec-compliant → C2 DB matching is structurally non-functional
**File:** `engine/fingerprint/ja4_engine.py:_compute_ja3`
**Bug:** JA3 = `MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)`. This code emits `f"{ver},{ciphers},{exts},,,"` — **EllipticCurves and ECPointFormats are always empty**. The resulting MD5 will never match any hash in JA3er / public datasets, because every real JA3 includes those fields.
**Compounded by:** `c2_database.py` JA3 hashes are mostly fabricated placeholders (credit: prior audit H-05 annotated them "(unverified)" and tiered confidence to 0.70 — but JA4 patterns got **no such treatment**, see M-09). So even if JA3 were spec-compliant, the DB is 80% placeholder.
**Net effect:** `match_ja3` and `match_ja4` together produce 0 matches on the sample. The C2-tool-matching feature is effectively decorative.
**Fix:** Either implement real JA3 (parse supported_groups 0x000a + ec_point_formats 0x000b extensions) or stop claiming JA3 support. And back every hash in `KNOWN_C2_PATTERNS` with a cited capture, or remove it.

### H-04 · Composite scoring makes HIGH/CRITICAL nearly unreachable — a perfect beacon scores "LOW"
**Files:** `engine/detection/scorer.py`, `engine/detection/beacon.py`
**Evidence (live):** `c2_beacon_test.pcap` → one session with `jitter 0.004` (textbook beacon), `beacon_score 0.75`, but `overall_score 0.30 → LOW`. Why: `overall = 0.40*beacon + 0.35*c2 + 0.25*dns`. With c2=0 (because F-01/H-03) and dns=0, even a max beacon caps at `0.40*0.95 = 0.38` < 0.40 (MEDIUM threshold). So **the tool's primary signal, on its own, can never clear "LOW."**
**README claims:** "jitter < 0.1 = 95% confidence." The README describes beacon confidence; the composite silently re-weights it down. A user trusting the README will miss real C2.
**Fix:** Either (a) make beacon-alone sufficient to reach HIGH when jitter is extreme (e.g. floor overall at `beacon_score` when jitter < 0.1), or (b) fix F-01 so C2 matches actually contribute. Today both inputs are broken, so the composite is doubly crippled.

### H-05 · `cli.py` hard-imports scapy — no graceful degradation
**File:** `engine/cli.py:from scapy.all import Scapy_Exception` (top-level)
**Bug:** `pcap_loader.py` carefully falls back when scapy is missing (`_USE_DPKT`, try/except on import). But `cli.py` imports `Scapy_Exception` at module top. If scapy is ever absent, **the entire CLI fails to import** with a `ModuleNotFoundError` before any command runs — defeating the dpkt fallback. `Scapy_Exception` is only referenced in two `except` clauses; it should be a lazy/try-except import.

### H-06 · Server fail-open defaults for a security product
**File:** `server/index.ts`
**Bugs:**
1. `app.listen({ host: '0.0.0.0' })` — binds all interfaces by default. Should be `127.0.0.1` unless explicitly overridden.
2. `API_KEY = process.env.GHOSTWIRE_API_KEY || null` — when unset, the API is **open**. The code comment warns "MUST NOT be exposed publicly without auth," but the default config exposes it publicly **and** open. Fail-open by default is the wrong posture for a security tool.
3. `ALLOWED_DIRS` defaults to `[]`. The prior "C-04 fixed" claim (path traversal) is **half-true**: when `GHOSTWIRE_ALLOWED_DIRS` is unset, `validateFilePath` only blocks `..` and checks extension/existence — **any absolute `.pcap` path on the system still reads**. The allowlist is opt-in, not default. The "fix" moved the hole behind an env var nobody sets.
**Fix:** Default `host` to `127.0.0.1`; default `ALLOWED_DIRS` to `[<project>/samples]`; refuse to start if `API_KEY` unset and `HOST` is non-loopback (fail-closed).

---

## 🟡 MEDIUM — design smells, docs, dead code

### M-01 · `iocs_from_analysis` "preferred structured fields" path is dead
**File:** `engine/export/stix.py`
The "prefer `src_ip`/`dst_ip` if present (added by enriched threat scores)" branch never fires — `ThreatScore.to_dict()` (scorer.py) does not include `src_ip`/`dst_ip`. The code always falls back to parsing the `session_id` string. The comment describes an enrichment that was never implemented. Remove the dead branch or implement the enrichment.

### M-02 · `BUG_CATALOG.md` is `.gitignore`d — audit trail not version-controlled
Commit `6a56551` "Add BUG_CATALOG.md to .gitignore, remove from tracking." For a review that Opus will scrutinize, hiding the prior audit in a local-only file is a transparency red flag. Either commit it (it's useful history) or fold its findings into the README/CHANGELOG. Right now a reviewer cloning the repo sees zero record of known issues.

### M-03 · Coverage "68%" is misleading — the important code is ~0–19%
`pytest --cov`: `cli.py` **0%** (258/258 uncovered — integration tests via subprocess don't count), `pcap_loader.py` **19%** (the parser, the riskiest module). The 68% is inflated by dataclass `__init__.py` files at 100%. BUG_CATALOG claims "Coverage: 68%" without this caveat.

### M-04 · No type gate; `mypy` not installed, no `[tool.mypy]` config
The skill's "proven gate" is ruff+mypy+pytest. Only ruff (default rules, no project config) + pytest run. `ruff` passing with no config is a low bar. Add `[tool.ruff]` ruleset, `[tool.mypy]` strict config, and install `mypy` in `dev` extras.

### M-05 · DNS compression pointers not handled in `decode_dns`
The label-walking loop treats any high byte as a label length; a `0xC0` compression pointer is read as "length 192" → reads past buffer or crashes. Acceptable for *queries* (rarely compressed), but the decoder is also applied to responses (`is_response` path). Document the limitation or handle 0xC0.

### M-06 · `detect_dga` `known_good` substring filter is over-broad
`if any(kg in domain.lower() for kg in known_good)` with `known_good = {... "aws", "apple" ...}`. `"aws"` matches `drawsomething.com`; `"apple"` matches `snapple.com`. Substring matching causes false negatives on DGA domains that happen to contain a vendor string. Use exact-label or suffix matching.

### M-07 · Duplicate MITRE name maps (two sources of truth)
`engine/export/stix.py:_mitre_name` and `engine/export/mitre_map.py:TECHNIQUE_MAP` maintain **separate** dicts of the same MITRE names. They will drift. Consolidate into one module.

### M-08 · Inconsistent entropy thresholds across modules
`decode_icmp` flags tunneling at entropy `> 7.0`; `beacon.detect_beacon` and `hunt_encrypted_c2` flag at `> 7.5`. No single constant. Drift risk.

### M-09 · JA4 patterns get no "unverified" tiering (H-05 fix was JA3-only)
Prior audit H-05 tiered **JA3** confidence (verified 0.95 / unverified 0.70). JA4 patterns like `"t13d1516h2_"` are also unverified approximations ("CS 4.x with TLS 1.3 (Java 11+ default)") but `match_ja4` gives **all of them 0.85** with no tiering. Inconsistent with the stated fix.

### M-10 · `match_http` partial-UA match is a false-positive generator
Brute Ratel's listed UA is `"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/108.0"` — a string that **also matches normal Chrome traffic**. The partial-match branch (`known_ua.lower() in ua_lower` → 0.60) will flag ordinary browsers. Either tighten patterns to C2-specific tokens or drop substring matching.

### M-11 · Dead npm dependencies (attack surface + install weight)
`package.json` lists `cors` (express middleware — only `@fastify/cors` is imported), `fastify-static` (never imported), `better-sqlite3` + `@types/better-sqlite3` (never imported). `grep` in `server/index.ts` confirms zero usage. Remove.

### M-12 · `engine/recon/` is an empty stub but Phase 4 is "complete"
`engine/recon/__init__.py` is `"""Recon package."""` — nothing else. BUG_CATALOG L-01 calls it "future Phase 4 recon modules," but the README roadmap marks Phase 4 complete and never mentions recon. Either build it or delete the package.

### M-13 · README Architecture table and "How It Works" omit half the system
No mention of `server/`, `dashboard/`, `engine/export/`, `engine/recon/`. Quick Start is CLI-only; the entire Phase 3 deliverable (React dashboard + API) is invisible to a reader. `start.sh` is undocumented.

### M-14 · Subprocess spawn: no server-side type validation before spawning Python
`server/index.ts` passes `minScore`, `minPackets`, `parser` from `request.body` straight into CLI args via `String(...)`. `parser` is validated by click's `Choice`; `minScore`/`minPackets` would crash the subprocess on bad types (caught, returns 500). Low risk (no shell, args list), but validate at the API layer before spawning — don't rely on the subprocess to be your validator.

---

## 🟢 LOW / cosmetic

- **L-01** `run_all_hunts` iterates `BUILTIN_QUERIES.items()` with an unused `meta` var.
- **L-02** `hunt_suspicious_beacons` and `hunt_encrypted_c2` recompute std/entropy inline instead of reusing `beacon.py`'s `_std` / `_shannon_entropy`. Duplicated logic.
- **L-03** `ghostwire.egg-info/requires.txt` still lists `numpy>=2.0`, `scipy>=1.14`, `maxminddb>=2.0` — stale build artifact (pyproject was fixed but egg-info not regenerated). Not tracked (gitignored), but will mislead anyone who reads it locally.
- **L-04** `package.json` pins `@types/node ^25.6.0` — Node 25 doesn't exist as LTS; use `^20` or `^22`.
- **L-05** `start.sh` `source .venv/bin/activate` with no existence check; backgrounded-process failures not caught by `set -e`.
- **L-06** Several `TECHNIQUE_MAP` entries (`T1071.004`, `T1095`, `T1041`, `T1048`, `T1001`, `T1568`, `T1568.002`) are unreachable from any emitter — `c2_database` never attaches them and DNS threats attach no MITRE. Dead reference data.
- **L-07** `decode_tls` has a `struct.unpack("!H", payload[offset+5:offset+7])[0]` whose result is discarded (dead expression) in the SNI block — moot once F-02 is fixed, but worth removing.
- **L-08** `hunt_cobalt_strike` does `payload_str = pkt.raw_payload[:512].decode(...)` then `if ua in payload_str` — substring UA match in HTTP hunt can false-positive (same class as M-10).

---

## What the prior audit got right (credit)

- C-02 Bessel's correction in `_std` — real fix, correct.
- C-04/M-08 server path-traversal + WebSocket auth — *partially* (see H-06 for the fail-open defaults it left).
- H-05 annotating unverified JA3 hashes + confidence tiering — good, but JA3 itself is broken (H-03) and JA4 was skipped (M-09).
- L-03/L-04/L-05 removing unused numpy/scipy/maxminddb from `pyproject.toml` — correct (egg-info still stale, L-03).
- Adding real unit tests for scorer/hunt/export/fingerprint — these are decent tests *of the units they cover*; the gap is they don't cover the broken paths (SNI, ja4plus integration, CLI metadata population).

## What the prior audit got wrong

- **"Documented as acceptable" was used to dispose of things that were never tested** (H-04 SNI duplication, H-03 multi-question DNS, M-05 lateral-movement false positives). H-04 in particular should have verified SNI actually parses — it doesn't (F-02).
- **T-05 "CLI coverage remains integration-only — documented"** — the integration tests don't even run in CI (F-04), so this "documentation" hides a ship-blocker.
- **"Coverage 68%"** stated without the cli.py 0% / pcap_loader 19% caveat (M-03).
- **Never ran the tool on its own sample PCAP** — if they had, `tls_fingerprints: 0` would have been impossible to miss (F-01).
- **BUG_CATALOG.md gitignored** (M-02) — the audit is local-only.

---

## Recommended fix order (ship-blockers first)

1. **F-04** — commit sample PCAPs or build fixtures. Without this, no CI, no "production."
2. **F-01** — fix ja4plus integration (build `tls_info` dict) + add a non-empty-JA4 test.
3. **F-02** — fix SNI/cipher/ext offset (`5+4`); add a ClientHello-with-SNI test.
4. **H-03** — implement spec-compliant JA3 (curves + EC point formats) or drop the claim.
5. **H-01** — populate `protocol_result` in the `hunt` command.
6. **H-04** — rebalance composite scoring so a strong beacon isn't capped at LOW.
7. **H-06** — fail-closed server defaults (loopback bind, required API_KEY, default allowlist).
8. **H-05** — lazy scapy import.
9. **F-03 + M-13** — README honesty pass: kill JA4X, fix "out-of-order handling," document dashboard/server, fix Architecture table.
10. **M-02** — commit `BUG_CATALOG.md` or this audit; stop hiding findings.
11. **M-04** — add ruff config + mypy config + install mypy; real quality gate.
12. Mediums and lows in a follow-up PR.

**Honest status:** Alpha, not production-ready. The core differentiator (JA4+) is unimplemented-by-integration, and the one thing that works (beacon jitter) is scored into irrelevance. Fix F-01 through H-04 and re-run the tool on `c2_beacon_test.pcap`; the target is `tls_fingerprints ≥ 1`, `c2_matches ≥ 1` on a known-bad sample, and a textbook beacon reaching at least HIGH. Until then, do not put this in front of a client.

— Mackenzie