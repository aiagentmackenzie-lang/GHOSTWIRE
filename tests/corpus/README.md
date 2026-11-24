# Detection-accuracy corpus

Synthetic PCAP fixtures (built in-memory by `tests/conftest.py` via scapy, so
the suite runs on a fresh clone with no binary samples committed) used by
`tests/test_detection_accuracy.py` to guard detection accuracy.

| Fixture | Builder | Expected outcome | Purpose |
|---|---|---|---|
| `benign_browsing.pcap` | `_build_benign_browsing_packets` | **0 beacons, 0 c2_matches, 0 dns_threats** | False-positive guard — the "no crying wolf" signal. ~30 sessions of normal browsing (short HTTPS connections + 3 longer bursty HTTP sessions with high-variance timing + 2 benign A-record DNS queries). |
| `beacon.pcap` | `_build_beacon_packets` | **≥1 beacon, confidence HIGH** | False-negative guard — steady 60s interval C2 beacon (jitter ≈ 0). |
| `dns.pcap` | `_build_dns_packets` | **≥1 dns_threat** | False-negative guard — long high-entropy subdomain TXT query (DNS tunneling). |
| `c2_http.pcap` | `_build_c2_http_packets` | **≥1 c2_match** | False-negative guard — exact Cobalt Strike default User-Agent. |

## How to interpret a failure

- **Benign corpus flags something** → a real false positive. Tune the
  detection threshold in `engine/detection/` (beacon jitter/regularity,
  dns entropy/label-length, c2 matching). **Do not** "fix" this by weakening
  the benign fixture (removing sessions, lowering packet counts) — that
  defeats the point of the guard.
- **Known-positive corpus misses** → a real false negative. Fix the detector
  or the fingerprint path before claiming any detection improvement.

## Notes

- The benign corpus is deterministic (`random.Random(20260622)`) so CI is
  reproducible.
- Longer benign HTTP sessions (15-18 packets) deliberately use bursty
  request/response pairs (<1s, filtered out of the beacon-IAT calc)
  separated by high-variance long pauses drawn from
  `[15,45,90,180,300,480,600]s`. The >1s IATs have std/mean ≈ 0.8, so
  `jitter_score` stays at 0.1 and the regularity gate (which requires
  `iat_jitter < 0.5`) does not fire — this exercises the real threshold,
  not a sub-`min_packets` shortcut.
## Evidence fixtures (Wave 1)

These fixtures exist for the *evidence* contract, not for detection accuracy.
Each one expresses a distinction the earlier suite could not make.

| Fixture | Builder | Expected outcome | Why it exists |
|---|---|---|---|
| `dns.pcap` | `_build_dns_packets` | **1 standalone DNS finding, 2 reasons, 0 TCP sessions, frame 1** | A DNS query has no TCP session. It must reach the result without being attributed to a conversation. |
| `http.pcap` (`c2_http.pcap`) | `_build_c2_http_packets` | **1 HTTP header finding, UA preserved, session score 0.315 (LOW)** | The matched User-Agent must survive to JSON/report/STIX/API/dashboard, attached to the conversation that sent it. |
| `dns_plus_http.pcap` | `_build_dns_packets + _build_c2_http_packets` | **HTTP session stays 0.315** (was 0.565) | Capture-wide DNS must not leak into an unrelated TCP score. |
| `two_http_sessions.pcap` | `_build_c2_http_packets + _build_benign_http_packets` | **exactly 1 header finding** | A shared client address is not attribution. |
| `duplicate_segment.pcap` | `_build_duplicate_first_segment_packets` | **1 fingerprint, 107 captured bytes, 77 distinct bytes** | Captured volume and distinct stream bytes are different quantities. |
| `truncated_hello.pcap` | `_build_truncated_hello_packets` | **2 disjoint ranges, 19 missing bytes, 0 fingerprints, coverage `partial`** | A capture hole must be visible, not concatenated over. |
| `reversed_order.pcap` | `_build_reversed_split_packets` | **positive 1 ms span, 1 ordering anomaly, same fingerprint** | Duration comes from observed time bounds, not file order. |
| `server_first.pcap` | upstream frames 2–6 | **ServerHello identified, `client_side == "dst"`, no invented ClientHello** | A mid-stream capture must not create a client handshake it did not see. |
| `split.pcapng` | `_build_split_tls_packets` via `wrpcapng` | **`parser_used == "scapy"` (dpkt fallback)** | The result must name the decoder that actually produced it. |
| `wireshark_tls13_client_hellos.pcap` | upstream frames 1 and 7 | **JA3 `25bd5fc6…` / `7ed44a80…`, matching reference JA4 values** | An independent reference reveals a serialisation bug the local fixture cannot. |

The Wireshark payloads live in `tests/fixtures/wireshark_tls13_rfc8446.json`
with the upstream commit and SHA-256; `tests/fixtures/fetch_wireshark_tls13.py`
re-downloads and re-extracts them so the check is reproducible (and offline).
