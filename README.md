# GHOSTWIRE — Network Forensics Engine

> *"The wire remembers everything."*

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Status](https://img.shields.io/badge/Status-Alpha-orange?style=flat)

GHOSTWIRE is a developer-built network forensics engine that combines C2 beacon detection, JA4+ fingerprinting, and session reconstruction into one focused hunting tool. Not an enterprise SIEM — a weapon for analysts.

## Features

- **PCAP/PCAPNG Ingestion** — Load and parse any capture file (dpkt + scapy)
- **Protocol Decoding** — HTTP, DNS, TLS (SNI extraction), SSH, ICMP tunnel detection
- **TCP Session Reconstruction** — Stream reassembly, out-of-order handling, state tracking
- **JA4+ Fingerprinting** — TLS, HTTP, and SSH client fingerprinting (with JA3 fallback)
- **C2 Beacon Detection** — Statistical jitter analysis, volume asymmetry, entropy scoring
- **DNS Threat Detection** — DGA detection, DNS tunneling, suspicious query patterns
- **C2 Tool Matching** — Fingerprint database for Cobalt Strike, Metasploit, Sliver, Havoc, Brute Ratel, Covenant
- **Composite Threat Scoring** — Weighted scoring across all detection signals
- **Rich CLI Output** — Dark-themed terminal dashboard with tables and highlights
- **JSON Export** — Machine-readable output for automation and pipelines

## Quick Start

```bash
# Install
git clone https://github.com/aiagentmackenzie-lang/GHOSTWIRE.git
cd GHOSTWIRE
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Analyze a PCAP
ghostwire analyze capture.pcap

# JSON output for automation
ghostwire analyze capture.pcap --output json

# Adjust sensitivity
ghostwire analyze capture.pcap --min-score 0.1 --min-packets 5

# Use specific parser
ghostwire analyze capture.pcap --parser scapy
```

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
                               CLI Dashboard / JSON
```

### C2 Beacon Detection Algorithm

1. **Jitter Analysis** — Calculates inter-arrival time (IAT) jitter ratio (std/mean). Beacons have consistent intervals → jitter < 0.1 = 95% confidence
2. **Volume Asymmetry** — C2 traffic is typically asymmetric (small request, variable response)
3. **Connection Regularity** — Long-duration low-rate sessions sustained over time
4. **Entropy Scoring** — Encrypted C2 channels show high Shannon entropy (>7.5)

### JA4+ Fingerprinting

Uses the official `ja4plus` library for modern TLS/TCP/HTTP/SSH fingerprinting:
- **JA4** — TLS client fingerprint (successor to JA3)
- **JA4S** — TLS server fingerprint
- **JA4H** — HTTP client fingerprint
- **JA4SSH** — SSH client fingerprint
- **JA4X** — X.509 certificate fingerprint

Matches against known C2 tool fingerprints for Cobalt Strike, Sliver, Metasploit, and more.

## Architecture

| Module | Purpose |
|--------|---------|
| `engine/parser/` | PCAP loading, protocol decoding, session reconstruction |
| `engine/fingerprint/` | JA4+ fingerprinting, C2 tool matching |
| `engine/detection/` | Beacon detection, DNS threats, composite scoring |
| `engine/cli.py` | CLI interface (click + rich) |

## Why GHOSTWIRE?

| Feature | RITA | Malcolm | Arkime | GHOSTWIRE |
|---------|------|---------|--------|-----------|
| C2 beacon detection | ✅ | ❌ | ❌ | ✅ |
| JA4+ fingerprinting | ❌ | ❌ | ❌ | ✅ |
| Single developer built | ❌ | ❌ | ❌ | ✅ |
| No infrastructure needed | ❌ | ❌ | ❌ | ✅ |
| PCAP-level analysis | ❌ | ✅ | ✅ | ✅ |
| DNS threat detection | ❌ | ❌ | ❌ | ✅ |

## Roadmap

- [x] Phase 1: PCAP parser + protocol decoder + JA4+ fingerprinting + C2 matching
- [x] Phase 2: C2 beacon detector + DNS threats + composite scoring
- [ ] Phase 3: React dashboard (timeline, beacon chart, network graph, geo map)
- [ ] Phase 4: STIX 2.1 export + MITRE ATT&CK mapping + report generator

## License

MIT

---

*Designed by Raphael Main + Agent Mackenzie. Built for analysts who hunt.*