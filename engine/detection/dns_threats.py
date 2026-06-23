"""DNS threat detection — DGA, tunneling, fast flux, suspicious patterns."""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Common legitimate TLDs for filtering
_COMMON_TLDS = {"com", "net", "org", "edu", "gov", "mil", "io", "co", "uk", "de", "fr", "br", "jp"}

# High-entropy domain indicators (DGA)
_HEX_PATTERN = re.compile(r"^[0-9a-f]+$")
_CONSONANT_CLUSTER = re.compile(r"[bcdfghjklmnpqrstvwxyz]{5,}", re.IGNORECASE)

# DGA analysis targets the registrable label (the SLD, i.e. the label
# immediately before the TLD), NOT the first label - because the first label is
# often a benign host like "www" / "mail" / "ns" which is short and
# consonant-heavy and would false-positive. DGA traditionally generates the SLD
# itself. (Real-traffic fix: www.tunnelblick.net was flagging on "www".)
def _registrable_label(domain: str) -> str:
    labels = domain.split(".")
    if len(labels) >= 2:
        return labels[-2]
    return domain


# Plausible DNS query types (name or small number). Garbage qtypes (e.g. 17219,
# 49896) come from misparsed/non-DNS UDP on real captures and must not produce
# "tunneling" threats. (Real-traffic fix.)
_VALID_QTYPE_NAMES = {
    "A", "NS", "CNAME", "SOA", "PTR", "MX", "TXT", "AAAA", "SRV", "ANY",
    "NULL", "CAA", "DS", "DNSKEY", "NSEC", "NSEC3", "TLSA", "SVCB", "HTTPS",
    "RRSIG", "AXFR", "IXFR",
}


def _is_plausible_dns(domain: str, query_type: str) -> bool:
    """Reject domains/qtypes that are obviously parser garbage."""
    if not domain:
        return False
    if any(ord(c) < 32 or ord(c) > 126 for c in domain):
        return False
    if query_type.isdigit():
        return int(query_type) <= 300
    return query_type.upper() in _VALID_QTYPE_NAMES


def _is_netbios_name(domain: str) -> bool:
    """True if ``domain`` is a NetBIOS-encoded name (NBNS/NBNS broadcast).

    NetBIOS Name Service (UDP/137) uses the DNS wire format but encodes each
    byte of a 16-byte NetBIOS name as two characters in ``A``-``P``
    (char = 'A' + nibble), yielding a single 32-character label like
    ``CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`` or ``EJFDEBFEEBFACACACACACACACACACAAA``.

    On a real ICS capture (4SICS) these Windows broadcasts were the ONLY
    surviving "DNS threats" after parser hardening — and they are not DNS at
    all. The 32-char length is not data exfil; it is the fixed NetBIOS name
    encoding. Flagging them as tunneling is a false positive a production tool
    must not emit. (Real-traffic fix 2026-06-23.)
    """
    # NetBIOS names are a single 32-char label (no dots) drawn from A-P.
    if "." in domain or len(domain) != 32:
        return False
    return all("A" <= c <= "P" for c in domain)


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
    """Shannon entropy of the registrable label (SLD). DGA generates the SLD."""
    label = _registrable_label(domain)
    if not label:
        return 0.0

    freq: dict[str, int] = {}
    for c in label.lower():
        freq[c] = freq.get(c, 0) + 1
    length = len(label)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _is_hex_domain(domain: str) -> bool:
    """True if the SLD (registrable label) is a long hex-only string - a DGA
    hallmark. We do NOT flag hex *subdomains* of a legitimate SLD (e.g.
    cb922b3f.fanoutcdn.com) because real CDNs use hash subdomains."""
    if len(domain.split(".")) < 2:
        return False
    sld = _registrable_label(domain).replace("-", "")
    return len(sld) >= 8 and bool(_HEX_PATTERN.match(sld))


def _consonant_ratio(domain: str) -> float:
    """Consonant ratio of the SLD - high ratio suggests an algorithmic name."""
    label = _registrable_label(domain).replace("-", "")
    if not label:
        return 0.0
    consonants = sum(1 for c in label.lower() if c in "bcdfghjklmnpqrstvwxyz")
    return consonants / len(label)


def detect_dga(domain: str, query_type: str = "A") -> DNSThreat | None:
    """Detect potential DGA-generated domain names.

    DGA indicators:
    - High entropy in domain labels
    - Hex-only subdomains
    - Excessive consonant clusters
    - Very long domain names
    """
    if not domain or domain.endswith(".arpa") or domain in (".", "localhost"):
        return None

    # Skip common CDNs and well-known services. Match on the registrable
    # domain (the second-level label, i.e. the label immediately before the
    # TLD), NOT on substrings -- audit M-06: substring matching made "aws"
    # match "drawsomething.com" and "apple" match "snapple.com".
    known_good_slds = {
        "google", "amazon", "cloudflare", "microsoft", "apple", "facebook",
        "akamai", "fastly", "cloudfront", "azure", "aws", "github",
        "googleapis", "gstatic", "googleusercontent", "githubusercontent",
        "amazonaws", "fanoutcdn", "cdnjs", "jsdelivr", "akamaized",
        "cloudflarecdn", "kunlun", "edgekey", "edgesuite",
    }
    labels = domain.split(".")
    if len(labels) >= 2:
        sld_label = labels[-2].lower()
        if sld_label in known_good_slds:
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

    # Consonant ratio - only meaningful on a long enough SLD. Short org names
    # like "dlink" / "kth" are mostly consonants by chance and would FP.
    sld_for_ratio = _registrable_label(domain)
    if len(sld_for_ratio) >= 6:
        c_ratio = _consonant_ratio(domain)
        if c_ratio > 0.75:
            score += 0.2
            threat.reasons.append(f"High consonant ratio ({c_ratio:.2f}) — unnatural text")

    # Length check (on the SLD, not the first/host label)
    sld_label = _registrable_label(domain)
    if len(sld_label) > 20:
        score += 0.15
        threat.reasons.append(f"Very long SLD label ({len(sld_label)} chars)")

    # Consonant cluster check (on the SLD)
    if _CONSONANT_CLUSTER.search(sld_label):
        score += 0.1
        threat.reasons.append("Unusual consonant cluster detected")

    if score < 0.2:
        return None

    threat.score = min(score, 1.0)
    threat.threat_type = "dga"
    threat.confidence = min(score, 1.0)

    return threat


def detect_dns_tunneling(domain: str, query_type: str = "A") -> DNSThreat | None:
    """Detect potential DNS tunneling.

    DNS tunneling indicators:
    - TXT/NULL record queries
    - Very long subdomain labels (data encoded in subdomain)
    - Excessive subdomain depth
    """
    if not domain or domain in (".", "localhost") or domain.endswith(".arpa"):
        return None

    # Skip well-known services (same registrable-SLD allowlist as DGA) so real
    # deep-subdomain services like 1-courier.sandbox.push.apple.com do not FP.
    _known_good = {
        "google", "amazon", "cloudflare", "microsoft", "apple", "facebook",
        "akamai", "fastly", "cloudfront", "azure", "aws", "github",
        "googleapis", "gstatic", "googleusercontent", "githubusercontent",
        "amazonaws", "fanoutcdn", "cdnjs", "jsdelivr", "akamaized",
        "cloudflarecdn", "kunlun", "edgekey", "edgesuite",
    }
    labels = domain.split(".")
    if len(labels) >= 2 and labels[-2].lower() in _known_good:
        return None

    threat = DNSThreat(domain=domain, query_type=query_type)
    score = 0.0

    # Unusual query types
    if query_type in ("TXT", "NULL", "ANY"):
        score += 0.5
        threat.reasons.append(f"Unusual DNS query type: {query_type}")

    # Long subdomain labels (data exfil via DNS)
    if labels:
        first_label = labels[0]
        if len(first_label) > 30:
            score += 0.5
            threat.reasons.append(f"Extremely long subdomain ({len(first_label)} chars) — possible data encoding")
        elif len(first_label) > 20:
            score += 0.3
            threat.reasons.append(f"Long subdomain ({len(first_label)} chars)")

    # Deep subdomain structure - only flag at >5 levels (4-5 is common for modern
    # CDNs / push / sandbox services).
    if len(labels) > 5:
        score += 0.2
        threat.reasons.append(f"Deep subdomain structure ({len(labels)} levels)")

    if score < 0.2:
        return None

    threat.score = min(score, 1.0)
    threat.threat_type = "tunneling"
    threat.confidence = min(score, 1.0)

    return threat


def analyze_dns(domain: str, query_type: str = "A", response_code: str = "NOERROR") -> list[DNSThreat]:
    """Run all DNS threat detection on a domain.

    Fails closed on parser garbage: a domain with control/non-ASCII bytes or an
    implausible qtype (e.g. 17219 from a misparsed UDP packet) produces no
    threats rather than a fake "tunneling" finding.

    Also skips NetBIOS-encoded names (NBNS on UDP/137, which reuses the DNS wire
    format): their fixed 32-char ``A``-``P`` encoding is not data exfil.
    """
    if not _is_plausible_dns(domain, query_type):
        return []
    if _is_netbios_name(domain):
        return []

    threats: list[DNSThreat] = []

    dga = detect_dga(domain, query_type)
    if dga:
        threats.append(dga)

    tunnel = detect_dns_tunneling(domain, query_type)
    if tunnel:
        threats.append(tunnel)

    return threats
