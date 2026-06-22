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