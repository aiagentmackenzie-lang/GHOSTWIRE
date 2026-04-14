"""Known C2 tool fingerprint database.

Matches JA4+/JA3/JA4H fingerprints against known C2 frameworks.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class C2Match:
    """A match against a known C2 tool."""
    tool_name: str
    confidence: float  # 0.0 - 1.0
    match_type: str  # "ja4", "ja3", "ja4h", "ja4ssh", "http_pattern", "banner"
    matched_value: str  # The fingerprint/pattern that matched
    description: str = ""
    mitre_techniques: list[str] = None

    def __post_init__(self):
        if self.mitre_techniques is None:
            self.mitre_techniques = []

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "confidence": round(self.confidence, 2),
            "match_type": self.match_type,
            "matched_value": self.matched_value,
            "description": self.description,
            "mitre_techniques": self.mitre_techniques,
        }


# Known C2 tool fingerprints — curated from public research
# Sources: JA3er, FoxIO research, Active Countermeasures, public IOCs
KNOWN_C2_PATTERNS: dict[str, dict] = {
    # === Cobalt Strike ===
    "cobalt_strike": {
        "description": "Cobalt Strike — commercial adversary simulation / C2 framework",
        "mitre": ["T1071.001", "T1573.001", "T1059.001", "T1021.001"],
        "ja3_hashes": [
            # Cobalt Strike default JA3 (varies by version/malleable C2)
            "72a5876a4ce4f4a1a0b5e1a8e9c7f3d2",  # Placeholder — real hashes from JA3er
        ],
        "ja4_patterns": [
            # Cobalt Strike typically uses specific cipher suites
            "t13d1516h2_",  # Pattern prefix for CS 4.x with TLS 1.3
            "t12d0812h2_",  # CS 4.x default with TLS 1.2
        ],
        "http_patterns": {
            # Cobalt Strike URI patterns
            "user_agents": [
                "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0)",
                "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1)",
                "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)",
            ],
            "uri_patterns": ["/__init.gif", "/submit.php", "/__utm.gif"],
        },
    },
    # === Metasploit ===
    "metasploit": {
        "description": "Metasploit Framework — open-source penetration testing",
        "mitre": ["T1059", "T1071.001", "T1573.002"],
        "ja3_hashes": [],
        "ja4_patterns": [],
        "http_patterns": {
            "user_agents": [
                "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)",
                "Mozilla/5.0 (Windows NT 6.0; Trident/5.0)",
            ],
        },
    },
    # === Sliver ===
    "sliver": {
        "description": "Sliver — open-source adversary simulation framework",
        "mitre": ["T1071.001", "T1573.002", "T1021.001"],
        "ja3_hashes": [],
        "ja4_patterns": [
            # Sliver uses Go's default TLS stack
            "t12d0504h2_",  # Go default TLS 1.2 pattern
        ],
        "http_patterns": {
            "user_agents": [
                "Go-http-client/1.1",
                "Go-http-client/2.0",
            ],
        },
    },
    # === Havoc ===
    "havoc": {
        "description": "Havoc — modern C2 framework for red team operations",
        "mitre": ["T1071.001", "T1573.001"],
        "ja3_hashes": [],
        "ja4_patterns": [],
        "http_patterns": {},
    },
    # === Brute Ratel ===
    "brute_ratel": {
        "description": "Brute Ratel C4 — advanced adversary simulation",
        "mitre": ["T1071.001", "T1573.001", "T1021.001"],
        "ja3_hashes": [],
        "ja4_patterns": [],
        "http_patterns": {
            "user_agents": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/108.0",
            ],
        },
    },
    # === Covenant ===
    "covenant": {
        "description": "Covenant — .NET C2 framework",
        "mitre": ["T1071.001", "T1059.001", "T1021.001"],
        "ja3_hashes": [],
        "ja4_patterns": [],
        "http_patterns": {
            "user_agents": [
                "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
            ],
        },
    },
}


def match_ja4(ja4: str) -> list[C2Match]:
    """Match a JA4 fingerprint against known C2 patterns."""
    if not ja4:
        return []

    matches: list[C2Match] = []
    ja4_lower = ja4.lower()

    for tool_name, data in KNOWN_C2_PATTERNS.items():
        for pattern in data.get("ja4_patterns", []):
            if ja4_lower.startswith(pattern.lower()):
                matches.append(C2Match(
                    tool_name=tool_name,
                    confidence=0.85,
                    match_type="ja4",
                    matched_value=ja4,
                    description=data["description"],
                    mitre_techniques=data.get("mitre", []),
                ))

    return matches


def match_ja3(ja3: str) -> list[C2Match]:
    """Match a JA3 hash against known C2 patterns."""
    if not ja3:
        return []

    matches: list[C2Match] = []
    ja3_lower = ja3.lower()

    for tool_name, data in KNOWN_C2_PATTERNS.items():
        for known_hash in data.get("ja3_hashes", []):
            if ja3_lower == known_hash.lower():
                matches.append(C2Match(
                    tool_name=tool_name,
                    confidence=0.95,
                    match_type="ja3",
                    matched_value=ja3,
                    description=data["description"],
                    mitre_techniques=data.get("mitre", []),
                ))

    return matches


def match_http(user_agent: str) -> list[C2Match]:
    """Match HTTP User-Agent against known C2 patterns."""
    if not user_agent:
        return []

    matches: list[C2Match] = []
    ua_lower = user_agent.lower()

    for tool_name, data in KNOWN_C2_PATTERNS.items():
        for known_ua in data.get("http_patterns", {}).get("user_agents", []):
            if ua_lower == known_ua.lower():
                matches.append(C2Match(
                    tool_name=tool_name,
                    confidence=0.90,
                    match_type="http_pattern",
                    matched_value=user_agent,
                    description=data["description"],
                    mitre_techniques=data.get("mitre", []),
                ))
            elif known_ua.lower() in ua_lower:
                matches.append(C2Match(
                    tool_name=tool_name,
                    confidence=0.60,
                    match_type="http_pattern",
                    matched_value=user_agent,
                    description=f"Partial UA match — {data['description']}",
                    mitre_techniques=data.get("mitre", []),
                ))

    return matches


def match_ssh(banner: str, software: str) -> list[C2Match]:
    """Match SSH banner/software against known C2 patterns."""
    matches: list[C2Match] = []

    # Detect SSH-based C2 tunnels
    suspicious_software = ["Paramiko", "libssh", "PuTTY", "dropbear"]
    for sw in suspicious_software:
        if sw.lower() in software.lower():
            matches.append(C2Match(
                tool_name=f"ssh_{sw.lower()}",
                confidence=0.50,
                match_type="ja4ssh",
                matched_value=banner,
                description=f"SSH client using {sw} — common in automation/C2 tunnels",
                mitre_techniques=["T1571", "T1021.004"],
            ))

    return matches


def match_all(ja4: str = "", ja3: str = "", ja4h: str = "",
              user_agent: str = "", ssh_banner: str = "",
              ssh_software: str = "") -> list[C2Match]:
    """Run all C2 matching against available fingerprints."""
    all_matches: list[C2Match] = []

    if ja4:
        all_matches.extend(match_ja4(ja4))
    if ja3:
        all_matches.extend(match_ja3(ja3))
    if user_agent:
        all_matches.extend(match_http(user_agent))
    if ssh_banner or ssh_software:
        all_matches.extend(match_ssh(ssh_banner, ssh_software))

    # Deduplicate by tool name, keeping highest confidence
    seen: dict[str, C2Match] = {}
    for m in all_matches:
        if m.tool_name not in seen or m.confidence > seen[m.tool_name].confidence:
            seen[m.tool_name] = m

    results = sorted(seen.values(), key=lambda x: x.confidence, reverse=True)
    if results:
        logger.info(f"C2 matches found: {[m.tool_name for m in results]}")

    return results