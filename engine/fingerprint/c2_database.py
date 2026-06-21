"""Known C2 tool fingerprint database.

Matches JA4+/JA3/JA4H fingerprints and HTTP User-Agents against known C2
frameworks.

Honesty policy (audit H-03 / M-09):
  - Every pattern carries a `source` and a `confidence`. Confidence is tiered
    by how the pattern was obtained:
      0.90 — exact, published default (e.g. a framework's shipped default UA)
      0.70 — research-derived prefix/pattern (observable but not from a capture
             we hold); clearly marked
      0.50 — behavioral heuristic (e.g. SSH client software commonly used in
             automation/C2 tunnels)
  - We do NOT ship fabricated JA3/JA4 hashes. Specific 32-hex JA3 hashes are
    only included when we can attribute them to a published dataset; otherwise
    they are omitted rather than invented. JA4 entries are prefix patterns
    (the JA4 spec hashes the full cipher/extension list, so a prefix is a
    coarse signal, not a unique identifier) and are marked as such.
  - HTTP User-Agent matching is exact only. The previous substring match
    flagged ordinary Chrome traffic as Brute Ratel (audit M-10); C2 frameworks
    that mimic a real browser UA are meant to evade, and substring matching
    produced more false positives than true positives.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class C2Match:
    """A match against a known C2 tool."""
    tool_name: str
    confidence: float  # 0.0 - 1.0
    match_type: str  # "ja4", "ja3", "ja4h", "ja4ssh", "http_pattern", "banner"
    matched_value: str  # The fingerprint/pattern that matched
    description: str = ""
    mitre_techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "confidence": round(self.confidence, 2),
            "match_type": self.match_type,
            "matched_value": self.matched_value,
            "description": self.description,
            "mitre_techniques": self.mitre_techniques,
        }


# Known C2 tool indicators.
# `confidence` here is the DEFAULT for JA4 prefix matches from this entry; the
# HTTP user_agents list carries per-pattern confidence in the tuple form
# (ua, confidence, source).
KNOWN_C2_PATTERNS: dict[str, dict] = {
    "cobalt_strike": {
        "description": "Cobalt Strike — commercial adversary simulation / C2 framework",
        "mitre": ["T1071.001", "T1573.001", "T1059.001", "T1021.001"],
        "ja3_hashes": [
            # Cobalt Strike's JA3 varies heavily with the malleable C2 profile
            # and the Java runtime version. We ship no specific hash here because
            # a single "default" hash would be invented. Match on JA4 prefix /
            # User-Agent instead, and let analysts confirm against their own
            # captures.
        ],
        "ja4_patterns": [
            # Coarse JA4 prefixes observed in CS research (FoxIO / community).
            # A prefix match is NOT a unique identifier — it's a hint. Marked
            # research_prefix so confidence tiers at 0.70.
            ("t13d1516h2_", "research_prefix", "FoxIO JA4 research / community datasets"),
            ("t12d0812h2_", "research_prefix", "FoxIO JA4 research / community datasets"),
        ],
        "http_patterns": {
            # Cobalt Strike ships with these exact default User-Agents (documented
            # in the CS malleable C2 profile guidance and widely cited in
            # detection research). Exact-match only.
            "user_agents": [
                ("Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0)", 0.90,
                 "Cobalt Strike default UA (documented)"),
                ("Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1)", 0.90,
                 "Cobalt Strike default UA (documented)"),
                ("Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)", 0.90,
                 "Cobalt Strike default UA (documented)"),
            ],
            "uri_patterns": ["/__init.gif", "/submit.php", "/__utm.gif"],
        },
    },
    "metasploit": {
        "description": "Metasploit Framework — open-source penetration testing",
        "mitre": ["T1059", "T1071.001", "T1573.002"],
        "ja3_hashes": [],
        "ja4_patterns": [
            ("t12d0503h2_", "research_prefix", "Metasploit Ruby OpenSSL JA4 research prefix"),
        ],
        "http_patterns": {
            "user_agents": [
                ("Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)", 0.85,
                 "Metasploit default UA (research-documented)"),
                ("Mozilla/5.0 (Windows NT 6.0; Trident/5.0)", 0.85,
                 "Metasploit default UA (research-documented)"),
            ],
        },
    },
    "sliver": {
        "description": "Sliver — open-source adversary simulation framework",
        "mitre": ["T1071.001", "T1573.002", "T1021.001"],
        "ja3_hashes": [],
        "ja4_patterns": [
            ("t12d0504h2_", "research_prefix", "Sliver / Go crypto/tls JA4 research prefix"),
            ("t13d0604h2_", "research_prefix", "Sliver / Go crypto/tls JA4 research prefix"),
        ],
        "http_patterns": {
            "user_agents": [
                ("Go-http-client/1.1", 0.95, "Sliver / Go default UA (exact)"),
                ("Go-http-client/2.0", 0.95, "Sliver / Go default UA (exact)"),
            ],
        },
    },
    "havoc": {
        "description": "Havoc — modern C2 framework for red team operations",
        "mitre": ["T1071.001", "T1573.001"],
        "ja3_hashes": [],
        "ja4_patterns": [
            ("t12d0604h2_", "research_prefix", "Havoc agent JA4 research prefix"),
        ],
        "http_patterns": {"user_agents": []},
    },
    "brute_ratel": {
        "description": "Brute Ratel C4 — advanced adversary simulation",
        "mitre": ["T1071.001", "T1573.001", "T1021.001"],
        "ja3_hashes": [],
        "ja4_patterns": [
            ("t12d0804h2_", "research_prefix", "BRc4 common JA4 research prefix"),
        ],
        # Brute Ratel's documented UA is a generic Chrome string; exact-match
        # would false-positive on real Chrome traffic, so we intentionally do
        # NOT ship it as a User-Agent indicator. Detect BRc4 via JA4 prefix or
        # behavioral signals instead.
        "http_patterns": {"user_agents": []},
    },
    "covenant": {
        "description": "Covenant — .NET C2 framework",
        "mitre": ["T1071.001", "T1059.001", "T1021.001"],
        "ja3_hashes": [],
        "ja4_patterns": [
            ("t12d0704h2_", "research_prefix", ".NET Framework TLS JA4 research prefix"),
        ],
        "http_patterns": {
            "user_agents": [
                ("Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko", 0.85,
                 "Covenant default UA (research-documented)"),
            ],
        },
    },
}


def match_ja4(ja4: str) -> list[C2Match]:
    """Match a JA4 fingerprint against known C2 prefix patterns.

    JA4 prefixes are coarse — a prefix match is a hint, not a unique
    identifier — so confidence tiers at 0.70 (research_prefix).
    """
    if not ja4:
        return []

    matches: list[C2Match] = []
    ja4_lower = ja4.lower()

    for tool_name, data in KNOWN_C2_PATTERNS.items():
        for pattern, _kind, source in data.get("ja4_patterns", []):
            if ja4_lower.startswith(pattern.lower()):
                matches.append(C2Match(
                    tool_name=tool_name,
                    confidence=0.70,
                    match_type="ja4",
                    matched_value=ja4,
                    description=f"{data['description']} (JA4 prefix match — {source})",
                    mitre_techniques=data.get("mitre", []),
                ))

    return matches


def match_ja3(ja3: str) -> list[C2Match]:
    """Match a JA3 hash against known C2 patterns.

    We ship no fabricated JA3 hashes. Any hash listed in the database must be
    attributed to a published dataset; matches against attributed hashes tier
    at 0.90, unattributed entries are omitted entirely.
    """
    if not ja3:
        return []

    ja3_lower = ja3.lower()
    matches: list[C2Match] = []

    for tool_name, data in KNOWN_C2_PATTERNS.items():
        for known_hash in data.get("ja3_hashes", []):
            if isinstance(known_hash, tuple):
                hash_val, conf = known_hash[0], known_hash[1]
            else:
                hash_val, conf = known_hash, 0.90
            if ja3_lower == hash_val.lower():
                matches.append(C2Match(
                    tool_name=tool_name,
                    confidence=conf,
                    match_type="ja3",
                    matched_value=ja3,
                    description=data["description"],
                    mitre_techniques=data.get("mitre", []),
                ))

    return matches


def match_http(user_agent: str) -> list[C2Match]:
    """Match HTTP User-Agent against known C2 patterns (exact match only)."""
    if not user_agent:
        return []

    matches: list[C2Match] = []
    ua_lower = user_agent.lower().strip()

    for tool_name, data in KNOWN_C2_PATTERNS.items():
        for entry in data.get("http_patterns", {}).get("user_agents", []):
            known_ua, conf, _source = entry
            if ua_lower == known_ua.lower():
                matches.append(C2Match(
                    tool_name=tool_name,
                    confidence=conf,
                    match_type="http_pattern",
                    matched_value=user_agent,
                    description=data["description"],
                    mitre_techniques=data.get("mitre", []),
                ))

    return matches


def match_ssh(banner: str, software: str) -> list[C2Match]:
    """Match SSH banner/software against known C2 patterns."""
    matches: list[C2Match] = []

    # SSH clients commonly used in automation/C2 tunnels. Behavioral heuristic,
    # not a C2 framework signature — confidence 0.50 and flagged as heuristic.
    suspicious_software = ["Paramiko", "libssh", "PuTTY", "dropbear"]
    for sw in suspicious_software:
        if sw.lower() in software.lower():
            matches.append(C2Match(
                tool_name=f"ssh_{sw.lower()}",
                confidence=0.50,
                match_type="ja4ssh",
                matched_value=banner,
                description=f"SSH client using {sw} — common in automation/C2 tunnels (heuristic)",
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
