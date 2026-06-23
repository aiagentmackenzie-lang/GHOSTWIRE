# C2 IOC feeds

GHOSTWIRE can extend its runtime C2 fingerprint database from external IOC
feed files (JSON), so operators can add their own threat intelligence without
editing code. (production-plan Phase 4.2)

## Feed file format

One file = one JSON list of entries:

```json
[
  {
    "tool": "cobalt_strike",
    "match_type": "ja4",
    "value": "t13d1516h2_",
    "confidence": 0.70,
    "source": "FoxIO JA4 research dataset",
    "license": "FoxIO JA4 datasets (public research)"
  }
]
```

| Field | Required | Notes |
|---|:--:|---|
| `tool` | yes | Tool name; a new tool creates a new pattern block. |
| `match_type` | yes | One of `ja4`, `ja3`, `http_ua`, `ssh_banner`, `ssh_software`. |
| `value` | yes | The pattern (JA4 prefix, JA3 hash, UA string, banner). |
| `confidence` | yes | 0.0-1.0. Tier honestly: 0.90 exact published default, 0.70 research-derived. |
| `source` | no | Attribution. "unspecified" if omitted. |
| `license` | no | License of the dataset the entry came from. |

## Bundled sample feed

`sample_feed.json` re-states the FoxIO-published JA4 prefixes that are
already cited inline in `engine/fingerprint/c2_database.py`. It is safe to
ship: the entries are publicly published research, attributed, and marked
`research`-tier confidence. It demonstrates the loader without committing any
dataset we have not license-checked.

## Adding CIRCL / MISP hash feeds (NOT yet bundled)

Decision (Q3): we commit a *cited snapshot*, license-check first. CIRCL MISP
hashes and other community datasets have their own licensing terms. Before
adding any of them as a bundled feed:

1. Verify the dataset's license permits redistribution (and under what
   attribution/retention terms).
2. Record the license on every entry's `license` field.
3. Cite the exact source URL + access date.

Until that check is done, runtime-fetch from a private source you maintain is
the supported path for hash feeds:

```
GHOSTWIRE_FEEDS_DIR=/path/to/your/private/feeds ghostwire analyze capture.pcap
```

## How feeds load

`engine/fingerprint/c2_database.py` lazily ingests every `*.json` in
`GHOSTWIRE_FEEDS_DIR` (default: this directory) on the first `match_all` call,
via `engine.feeds.loader`. Invalid feed files are skipped with a warning; the
analysis path never fails on a malformed feed. The `refresh-feeds` CLI prints
a summary of what a feeds dir would load without running an analysis.