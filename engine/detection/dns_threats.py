"""DNS threat detection — DGA, tunneling, fast flux, suspicious patterns."""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Common legitimate TLDs for filtering
_COMMON_TLDS = {"com", "net", "org", "edu", "gov", "mil", "io", "co", "uk", "de", "fr", "br", "jp"}

# High-entropy domain indicators (DGA)
_HEX_PATTERN = re.compile(r"^[0-9a-f]+$")
_CONSONANT_CLUSTER = re.compile(r"[bcdfghjklmnpqrstvwxyz]{5,}", re.IGNORECASE)


@dataclass
class DNSThreat:
    """DNS threat detection result."""
    domain: str = ""
    threat_type: str = ""  # "dga", "tunneling", "fast_flux", "suspicious"
    confidence: float = 0.0
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)
    entropy: float = 0.0
    query_type: str = ""
    response_code: str = ""

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "threat_type": self.threat_type,
            "confidence": round(self.confidence, 2),
            "score": round(self.score, 3),
            "reasons": self.reasons,
            "entropy": round(self.entropy, 3),
            "query_type": self.query_type,
        }


def _domain_entropy(domain: str) -> float:
    """Calculate Shannon entropy of domain name (excluding TLD)."""
    parts = domain.split(".")
    if len(parts) < 2:
        label = domain
    else:
        label = parts[0]  # Just the subdomain/second-level domain

    if not label:
        return 0.0

    freq: dict[str, int] = {}
    for c in label.lower():
        freq[c] = freq.get(c, 0) + 1
    length = len(label)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _is_hex_domain(domain: str) -> bool:
    """Check if domain labels are entirely hex — common DGA pattern."""
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    # Check first label (most likely DGA part)
    first = labels[0].replace("-", "")
    return len(first) >= 8 and bool(_HEX_PATTERN.match(first))


def _consonant_ratio(domain: str) -> float:
    """Ratio of consonants in domain — high ratio suggests DGA."""
    label = domain.split(".")[0].replace("-", "")
    if not label:
        return 0.0
    consonants = sum(1 for c in label.lower() if c in "bcdfghjklmnpqrstvwxyz")
    return consonants / len(label)


def detect_dga(domain: str, query_type: str = "A") -> Optional[DNSThreat]:
    """Detect potential DGA-generated domain names.

    DGA indicators:
    - High entropy in domain labels
    - Hex-only subdomains
    - Excessive consonant clusters
    - Very long domain names
    """
    if not domain or domain.endswith(".arpa") or domain in (".", "localhost"):
        return None

    # Skip common CDNs and well-known services
    known_good = {"google", "amazon", "cloudflare", "microsoft", "apple", "facebook",
                  "akamai", "fastly", "cloudfront", "azure", "aws"}
    if any(kg in domain.lower() for kg in known_good):
        return None

    threat = DNSThreat(domain=domain, query_type=query_type)
    score = 0.0

    # Entropy check
    entropy = _domain_entropy(domain)
    threat.entropy = entropy
    if entropy > 3.8:
        score += 0.4
        threat.reasons.append(f"High domain entropy ({entropy:.2f})")
    elif entropy > 3.2:
        score += 0.2

    # Hex domain check
    if _is_hex_domain(domain):
        score += 0.35
        threat.reasons.append("Hex-only domain label — common DGA pattern")

    # Consonant ratio
    c_ratio = _consonant_ratio(domain)
    if c_ratio > 0.75:
        score += 0.2
        threat.reasons.append(f"High consonant ratio ({c_ratio:.2f}) — unnatural text")

    # Length check
    first_label = domain.split(".")[0]
    if len(first_label) > 20:
        score += 0.15
        threat.reasons.append(f"Very long domain label ({len(first_label)} chars)")

    # Consonant cluster check
    if _CONSONANT_CLUSTER.search(first_label):
        score += 0.1
        threat.reasons.append("Unusual consonant cluster detected")

    if score < 0.2:
        return None

    threat.score = min(score, 1.0)
    threat.threat_type = "dga"
    threat.confidence = min(score, 1.0)

    return threat


def detect_dns_tunneling(domain: str, query_type: str = "A") -> Optional[DNSThreat]:
    """Detect potential DNS tunneling.

    DNS tunneling indicators:
    - TXT/NULL record queries
    - Very long subdomain labels (data encoded in subdomain)
    - Excessive subdomain depth
    """
    if not domain or domain in (".", "localhost") or domain.endswith(".arpa"):
        return None

    threat = DNSThreat(domain=domain, query_type=query_type)
    score = 0.0

    # Unusual query types
    if query_type in ("TXT", "NULL", "ANY"):
        score += 0.5
        threat.reasons.append(f"Unusual DNS query type: {query_type}")

    # Long subdomain labels (data exfil via DNS)
    labels = domain.split(".")
    if labels:
        first_label = labels[0]
        if len(first_label) > 30:
            score += 0.5
            threat.reasons.append(f"Extremely long subdomain ({len(first_label)} chars) — possible data encoding")
        elif len(first_label) > 20:
            score += 0.3
            threat.reasons.append(f"Long subdomain ({len(first_label)} chars)")

    # Many subdomain levels
    if len(labels) > 4:
        score += 0.2
        threat.reasons.append(f"Deep subdomain structure ({len(labels)} levels)")

    if score < 0.2:
        return None

    threat.score = min(score, 1.0)
    threat.threat_type = "tunneling"
    threat.confidence = min(score, 1.0)

    return threat


def analyze_dns(domain: str, query_type: str = "A", response_code: str = "NOERROR") -> list[DNSThreat]:
    """Run all DNS threat detection on a domain."""
    threats: list[DNSThreat] = []

    dga = detect_dga(domain, query_type)
    if dga:
        threats.append(dga)

    tunnel = detect_dns_tunneling(domain, query_type)
    if tunnel:
        threats.append(tunnel)

    return threats