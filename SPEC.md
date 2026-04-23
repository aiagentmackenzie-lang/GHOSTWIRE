# GHOSTWIRE — Network Forensics Engine

> "The wire remembers everything."

**Type:** Network forensics + C2 detection platform  
**Purpose:** PCAP ingestion → protocol extraction → session reconstruction → C2 beacon detection → visual threat hunting  
**Author:** Raphael Main + Agent Mackenzie  
**Created:** April 14, 2026  
**Status:** SPEC — Awaiting approval to build

---

## Why This Project

**The Problem:** Cybersecurity analyst candidates show up with Wireshark screenshots and VirusTotal scripts. Nobody builds a *real* forensics engine. The existing tools (RITA, Malcolm, Arkime) are enterprise-grade but massive and complex — no single developer-built tool demonstrates you understand network forensics at the packet level.

**The Opportunity:** Build something that proves you can:
1. Parse raw packets (not just call APIs)
2. Detect adversarial behavior in traffic (C2 beacons, lateral movement)
3. Reconstruct attacker sessions visually
4. Apply modern fingerprinting (JA4+, not just JA3)
5. Present findings in a way that tells a story

**Competitive Landscape:**

| Tool | Stars | What It Does | Gap |
|------|-------|--------------|-----|
| RITA | 546 | C2 beacon detection from Zeek logs | No PCAP parsing, no UI, Go only |
| Malcolm | 2,000 | Full PCAP analysis suite | Massive enterprise tool, 10+ containers |
| Arkime | 1,800+ | Full packet capture + indexing | Enterprise-scale, Java-heavy |
| pcap-hunter | ~50 | AI-assisted PCAP analysis | Basic UI, no C2 detection engine |
| C2-Profiler | 2 | C2 fingerprinting from PCAP | No beacon analysis, no visualization |

**GHOSTWIRE's niche:** A developer-built, single-binary network forensics engine that combines RITA-level C2 detection with JA4+ fingerprinting and a dark-themed analyst dashboard. Not enterprise bloat — a focused hunting tool.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   GHOSTWIRE ENGINE                    │
│                                                       │
│  ┌─────────┐  ┌──────────┐  ┌──────────────────┐     │
│  │  PCAP   │  │ Protocol │  │   Fingerprint    │     │
│  │ Parser  │→ │ Decoder  │→ │   Engine (JA4+)  │     │
│  │(scapy) │  │          │  │                  │     │
│  └─────────┘  └──────────┘  └──────────────────┘     │
│        │              │              │                │
│        ▼              ▼              ▼                │
│  ┌─────────────────────────────────────────┐         │
│  │           Session Reconstructor         │         │
│  │  TCP stream reassembly + HTTP/DNS/SSH   │         │
│  │  content extraction                     │         │
│  └─────────────────────────────────────────┘         │
│        │                                              │
│        ▼                                              │
│  ┌─────────────────────────────────────────┐         │
│  │         C2 Beacon Detector              │         │
│  │  - Timing analysis (jitter, interval)    │         │
│  │  - Volume scoring (bytes/session)        │         │
│  │  - Entropy analysis (payload randomness)│         │
│  │  - JA4+ fingerprint matching             │         │
│  │  - DNS pattern detection (DGAs)         │         │
│  └─────────────────────────────────────────┘         │
│        │                                              │
│        ▼                                              │
│  ┌─────────────────────────────────────────┐         │
│  │          Threat Scorer                   │         │
│  │  Weighted scoring across all signals     │         │
│  │  Confidence levels + IOC extraction      │         │
│  └─────────────────────────────────────────┘         │
│        │                                              │
│        ▼                                              │
│  ┌─────────────────────────────────────────┐         │
│  │     Fastify API + WebSocket Server       │         │
│  └─────────────────────────────────────────┘         │
│        │                                              │
│        ▼                                              │
│  ┌─────────────────────────────────────────┐         │
│  │     React Dashboard (Dark Theme)        │         │
│  └─────────────────────────────────────────┘         │
└─────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| **PCAP Parser** | Python + scapy + dpkt | scapy for parsing, dpkt for speed on large files |
| **JA4+ Fingerprinting** | ja4plus (PyPI) | Official FoxIO library, supports TLS/TCP/HTTP/SSH/X.509 |
| **C2 Detection Engine** | Custom Python | Statistical analysis (RITA-style algorithms) |
| **Session Reconstruction** | scapy + custom TCP reassembly | Build from packets, not libraries |
| **Backend API** | Fastify (TypeScript) | Fast, lightweight, WebSocket support |
| **Dashboard** | React + Vite + Tailwind | Dark cyberpunk theme, real-time updates |
| **Data Store** | SQLite (better-sqlite3) | Single-file, portable, fast for analysis data |
| **Visualization** | D3.js + deck.gl | Network graphs, timelines, geo maps |

**Why this stack over alternatives:**
- **Not Go** — Python is expected for security tools, you already know it, scapy/ja4plus are Python-native
- **Not Rust** — Too slow to build for a portfolio project, and scapy ecosystem doesn't exist
- **Not Electron** — Web dashboard is lighter, deployable, and actually impressive
- **Not PostgreSQL** — SQLite keeps it single-file portable, no setup required for demos

---

## Core Features

### Phase 1 — Foundation (Week 1)

#### 1.1 PCAP Ingestion & Protocol Decoder
- Load `.pcap` and `.pcapng` files
- Parse Ethernet → IP → TCP/UDP/ICMP headers
- Identify and decode application layers:
  - **HTTP** — Request/response reconstruction, header extraction
  - **DNS** — Query/response, domain extraction, response codes
  - **TLS** — SNI extraction, JA4+ fingerprinting
  - **SSH** — Version banners, key exchange fingerprints
  - **ICMP** — Tunnel detection (payload analysis)
- Output structured JSON per packet

#### 1.2 TCP Session Reconstructor
- Reassemble TCP streams from packet fragments
- Handle out-of-order packets, retransmissions
- Extract transmitted content per session (files, commands, responses)
- Tag sessions with protocol, duration, byte count

#### 1.3 JA4+ Fingerprinting Engine
- **JA4** — TLS client fingerprint (successor to JA3)
- **JA4S** — TLS server fingerprint
- **JA4H** — HTTP client fingerprint
- **JA4SSH** — SSH client fingerprint
- **JA4X** — X.509 certificate fingerprint
- Match fingerprints against known C2 tool database:
  - Cobalt Strike, Metasploit, Sliver, Havoc, Brute Ratel, Covenant
- Flag unknown/suspicious fingerprints for investigation

### Phase 2 — Detection Engine (Week 2)

#### 2.1 C2 Beacon Detector
The crown jewel. Implements statistical analysis of network behavior:

**Timing Analysis:**
- Calculate inter-arrival time (IAT) for each connection pair
- Compute jitter ratio (standard deviation / mean)
- Beacon score: low jitter = likely beacon (threshold: <0.3 = suspicious, <0.1 = high confidence)

**Volume Analysis:**
- Compare bytes sent vs received per session
- C2 typically has asymmetric patterns (small request, variable response)
- Score based on byte ratio consistency across sessions

**Entropy Analysis:**
- Shannon entropy of payload data
- Encrypted C2 traffic shows high entropy; legitimate traffic varies
- DNS tunneling: high entropy in subdomain labels

**Connection Pattern Analysis:**
- Persistent connections with regular intervals
- Sequential IP connections (failed → success pattern indicating scanning)
- Long-duration low-activity sessions

#### 2.2 DNS Threat Detector
- **DGA Detection** — Entropy analysis of domain names, n-gram scoring
- **DNS Tunneling** — Unusual record types (TXT, NULL), high subdomain entropy
- **Fast Flux** — Rapidly changing A records for same domain
- **Newly Registered Domains** — Flag domains with recent creation dates

#### 2.3 Threat Scorer
- Weighted composite score from all detection engines
- Confidence levels: LOW / MEDIUM / HIGH / CRITICAL
- IOC extraction: IPs, domains, URLs, file hashes, JA4+ fingerprints
- Exportable as STIX 2.1 format (industry standard for threat intel sharing)

### Phase 3 — Dashboard (Week 3)

#### 3.1 Session Timeline
- Interactive timeline of all network sessions
- Color-coded by protocol and threat score
- Zoom from hours → minutes → seconds
- Click session → full packet detail

#### 3.2 C2 Beacon Visualization
- Scatter plot: connection intervals over time
- Histogram: IAT distribution (beacon = tight cluster, benign = spread)
- Heat map: connection frequency by hour/day
- Side-by-side: known good vs suspicious traffic patterns

#### 3.3 Network Graph
- Force-directed graph: internal IPs ↔ external IPs
- Edge weight = connection count
- Node color = threat score
- Cluster detection for lateral movement patterns

#### 3.4 Geo Map
- External IP geolocation (MaxMind GeoLite2)
- Real-time attack origin visualization
- Filter by threat score, protocol, time range

#### 3.5 Session Inspector
- Reconstructed TCP streams (like "Follow TCP Stream" in Wireshark)
- HTTP content: requests, responses, extracted files
- DNS queries with response analysis
- TLS handshake details with JA4+ fingerprints

#### 3.6 Hunt Mode
- Interactive threat hunting notebook
- Write Python queries against parsed PCAP data
- Save and share hunt queries (JSON export)
- Pre-built hunt playbooks:
  - "Find Cobalt Strike beacons"
  - "Find DNS tunneling"
  - "Find data exfiltration"
  - "Find lateral movement"

### Phase 4 — Polish & Demo (Week 4)

#### 4.1 Sample PCAPs
- Bundle curated PCAP samples from public sources:
  - Malware Traffic Analysis (malware-traffic-analysis.net)
  - CTU datasets (CTU-13, CTU-42)
  - Stratosphere Lab datasets
- Pre-analyzed results for instant demo

#### 4.2 Report Generator
- Executive summary (non-technical)
- Technical report (full IOCs, timelines, recommendations)
- Markdown + PDF export
- MITRE ATT&CK mapping for detected techniques

#### 4.3 CLI Mode
- Full analysis from terminal (no UI needed)
- `ghostwire analyze capture.pcap --output report.json`
- `ghostwire hunt capture.pcap --query "suspicious_beacons"`
- Pipe-friendly JSON output for automation

---

## UI Design Language

**Theme:** Dark, neon-accented cyberpunk — but *functional*, not flashy  
**Inspiration:** Arkime's interface, but darker and more focused  
**Colors:**
- Background: `#0a0a0f` (near-black)
- Surface: `#13131a`
- Primary accent: `#00ff9f` (neon green)
- Danger: `#ff3366`
- Warning: `#ffaa00`
- Info: `#00aaff`
- Text: `#e0e0e0`

**Key Principle:** Every pixel must serve the analyst. No decorative elements that don't convey information. The "cyberpunk" feel comes from the color palette and data density, not from pointless animations.

---

## File Structure

```
GHOSTWIRE/
├── SPEC.md                    # This file
├── README.md                  # GitHub landing page
├── pyproject.toml             # Python packaging
├── package.json               # Dashboard (React)
│
├── engine/                    # Python — Core analysis engine
│   ├── __init__.py
│   ├── parser/                # PCAP parsing
│   │   ├── pcap_loader.py     # File ingestion (scapy + dpkt)
│   │   ├── protocol.py        # Protocol decoder
│   │   └── session.py         # TCP stream reassembly
│   ├── fingerprint/           # JA4+ fingerprinting
│   │   ├── ja4_engine.py      # TLS fingerprinting
│   │   ├── ja4h_engine.py    # HTTP fingerprinting
│   │   ├── ja4ssh_engine.py  # SSH fingerprinting
│   │   └── c2_database.py    # Known C2 fingerprint matching
│   ├── detection/             # Threat detection
│   │   ├── beacon.py          # C2 beacon detector
│   │   ├── dns_threats.py    # DNS anomaly detection
│   │   ├── scorer.py          # Composite threat scoring
│   │   └── hunt.py            # Built-in hunt queries
│   ├── recon/                 # Recon package (placeholder)
│   │   └── __init__.py         # Session reconstruction is in parser/session.py
│   ├── export/                # Report generation
│   │   ├── stix.py            # STIX 2.1 IOC export
│   │   ├── report.py         # Markdown/PDF reports
│   │   └── mitre_map.py      # MITRE ATT&CK mapping
│   └── cli.py                 # CLI entry point
│
├── dashboard/                 # React — Analyst dashboard
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── Timeline.tsx       # Session timeline
│   │   │   ├── BeaconChart.tsx   # C2 beacon visualization
│   │   │   ├── NetworkGraph.tsx  # Connection graph
│   │   │   ├── SessionView.tsx   # TCP stream inspector
│   │   │   ├── ProtoBreakdown.tsx # Protocol distribution
│   │   │   ├── FingerprintTable.tsx # JA4/JA3 fingerprint list
│   │   │   └── ThreatPanel.tsx   # Threat summary cards
│   │   ├── hooks/
│   │   │   └── useWebSocket.ts
│   │   └── theme/
│   │       └── dark.ts           # Cyberpunk dark theme
│   ├── vite.config.ts
│   └── tailwind.config.js
│
├── server/                    # Fastify API
│   ├── index.ts               # Entry point + WebSocket
│   ├── routes/
│   │   ├── analysis.ts        # Analysis endpoints
│   │   ├── sessions.ts        # Session data
│   │   └── hunt.ts            # Hunt query execution
│   └── db/
│       └── schema.sql         # SQLite schema
│
├── samples/                   # Sample PCAPs + pre-analyzed results
│   └── README.md              # Source attribution
│
└── tests/
    ├── test_parser.py
    ├── test_beacon.py
    ├── test_fingerprint.py
    └── fixtures/
        └── *.pcap             # Test PCAP files
```

---

## Dependencies

### Python (engine)
| Package | Version | Purpose |
|---------|---------|---------|
| scapy | ^2.6 | Packet parsing |
| dpkt | ^1.10 | Fast PCAP reading |
| ja4plus | ^0.4 | JA4+ fingerprinting |
| numpy | ^2.0 | Statistical analysis |
| scipy | ^1.14 | Entropy + distributions |
| maxminddb | ^2.0 | GeoIP lookups |
| rich | ^13.0 | CLI output |
| click | ^8.0 | CLI framework |
| pytest | ^8.0 | Testing |

### TypeScript (server + dashboard)
| Package | Version | Purpose |
|---------|---------|---------|
| fastify | ^5.0 | API server |
| better-sqlite3 | ^11.0 | SQLite driver |
| react | ^19.0 | Dashboard UI |
| d3 | ^7.0 | Charts + graphs |
| deck.gl | ^9.0 | Geo visualization |
| tailwindcss | ^4.0 | Styling |

---

## Demo Scenario (For Portfolio)

**The Pitch:** "Give me any PCAP file and I'll show you where the attacker is."

1. Load a known-malware PCAP (e.g., Cobalt Strike infection)
2. GHOSTWIRE parses, fingerprints, and scores in seconds
3. Dashboard lights up:
   - Timeline shows the infection timeline
   - Beacon chart reveals the C2 heartbeat
   - Network graph shows patient zero → C2 server
   - Geo map shows data going to Eastern Europe
4. JA4+ fingerprints match Cobalt Strike with 95%+ confidence
5. Export STIX report with all IOCs + MITRE ATT&CK mapping

**Why this closes interviews:** You're not describing theory. You're running a live investigation on stage. That's not junior-level. That's "hire this person now" level.

---

## What This Proves to Hiring Managers

| Skill | How GHOSTWIRE Demonstrates It |
|-------|-------------------------------|
| **Packet analysis** | Built parser from scapy, not Wireshark filters |
| **C2 detection** | Statistical beacon analysis, not just "known bad IP" matching |
| **TLS fingerprinting** | JA4+ implementation, not outdated JA3 |
| **TCP reconstruction** | Handled fragment reassembly, edge cases |
| **Threat hunting** | Interactive hunt mode with playbooks |
| **Reporting** | STIX export + MITRE ATT&CK mapping |
| **Visualization** | Built analyst dashboard, not just CLI output |
| **Engineering** | Full-stack: Python engine + TS API + React UI |

---

## Timeline

| Week | Deliverable | Status |
|------|------------|--------|
| 1 | PCAP parser + protocol decoder + JA4+ fingerprinting | 🔲 |
| 2 | C2 beacon detector + DNS threats + threat scorer | 🔲 |
| 3 | Dashboard (timeline, beacon chart, network graph, geo map) | 🔲 |
| 4 | CLI mode + reports + sample PCAPs + README + demo | 🔲 |

---

## Success Criteria

- [ ] Parses any PCAP/PCAPNG without crashing
- [ ] Detects beacons in known C2 traffic (Cobalt Strike, Sliver) with >80% accuracy
- [ ] JA4+ fingerprinting matches known tools correctly
- [ ] Dashboard renders 10K+ sessions without lag
- [ ] CLI mode produces valid JSON output
- [ ] STIX 2.1 export validates against schema
- [ ] README has demo GIF + installation instructions
- [ ] At least 1 blog post explaining the C2 detection algorithms

---

## Differentiators vs Existing Tools

| Feature | RITA | Malcolm | Arkime | GHOSTWIRE |
|---------|------|---------|--------|-----------|
| C2 beacon detection | ✅ | ❌ | ❌ | ✅ |
| JA4+ fingerprinting | ❌ | ❌ | ❌ | ✅ |
| Single developer built | ❌ | ❌ | ❌ | ✅ |
| Modern dark UI | ❌ | ✅ | ❌ | ✅ |
| No infrastructure needed | ❌ | ❌ | ❌ | ✅ |
| PCAP-level analysis | ❌ (Zeek logs) | ✅ | ✅ | ✅ |
| DNS threat detection | ❌ | ❌ | ❌ | ✅ |
| Hunt mode | ❌ | ❌ | ❌ | ✅ |
| STIX export | ❌ | ❌ | ❌ | ✅ |
| Setup complexity | Medium | High | High | **Low** |

---

*"The wire remembers everything. GHOSTWIRE makes it talk."*