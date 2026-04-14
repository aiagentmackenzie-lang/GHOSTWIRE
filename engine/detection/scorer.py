"""Composite threat scorer — weighted scoring across all detection signals."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from engine.detection.beacon import BeaconScore
from engine.detection.dns_threats import DNSThreat
from engine.fingerprint.c2_database import C2Match

logger = logging.getLogger(__name__)


@dataclass
class ThreatScore:
    """Composite threat assessment for a session or endpoint."""
    target: str  # session_id, IP, or domain
    target_type: str  # "session", "ip", "domain"
    overall_score: float = 0.0
    confidence: str = "LOW"
    beacon_score: Optional[float] = None
    c2_matches: list[C2Match] = field(default_factory=list)
    dns_threats: list[DNSThreat] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "overall_score": round(self.overall_score, 3),
            "confidence": self.confidence,
            "beacon_score": round(self.beacon_score, 3) if self.beacon_score else None,
            "c2_matches": [m.to_dict() for m in self.c2_matches],
            "dns_threats": [t.to_dict() for t in self.dns_threats],
            "iocs": self.iocs,
            "mitre_techniques": self.mitre_techniques,
            "summary": self.summary,
        }


def score_session(
    session_id: str,
    beacon: Optional[BeaconScore] = None,
    c2_matches: Optional[list[C2Match]] = None,
    dns_threats: Optional[list[DNSThreat]] = None,
) -> ThreatScore:
    """Compute composite threat score for a session.

    Weights:
    - Beacon detection: 40%
    - C2 fingerprint match: 35%
    - DNS threats: 25%
    """
    threat = ThreatScore(target=session_id, target_type="session")
    c2_matches = c2_matches or []
    dns_threats = dns_threats or []

    # Beacon contribution
    beacon_value = beacon.overall_score if beacon else 0.0
    threat.beacon_score = beacon_value

    # C2 match contribution (highest confidence match)
    c2_value = max((m.confidence for m in c2_matches), default=0.0)

    # DNS threat contribution (highest scoring threat)
    dns_value = max((t.score for t in dns_threats), default=0.0)

    # Weighted composite
    threat.overall_score = (0.40 * beacon_value + 0.35 * c2_value + 0.25 * dns_value)

    # Assign confidence
    if threat.overall_score >= 0.80:
        threat.confidence = "CRITICAL"
    elif threat.overall_score >= 0.60:
        threat.confidence = "HIGH"
    elif threat.overall_score >= 0.40:
        threat.confidence = "MEDIUM"
    elif threat.overall_score >= 0.25:
        threat.confidence = "LOW"
    else:
        threat.confidence = "NEGLIGIBLE"

    # Collect IOCs
    for m in c2_matches:
        threat.iocs.append(f"C2:{m.tool_name} ({m.matched_value})")
        threat.mitre_techniques.extend(m.mitre_techniques)

    for t in dns_threats:
        threat.iocs.append(f"DNS:{t.domain} ({t.threat_type})")

    # Deduplicate MITRE techniques
    threat.mitre_techniques = list(set(threat.mitre_techniques))

    # Build summary
    parts = []
    if beacon and beacon.confidence in ("HIGH", "CRITICAL"):
        parts.append(f"C2 beacon detected (jitter: {beacon.iat_jitter:.3f})")
    if c2_matches:
        parts.append(f"Known C2: {', '.join(m.tool_name for m in c2_matches)}")
    if dns_threats:
        parts.append(f"DNS threats: {', '.join(t.threat_type for t in dns_threats)}")
    threat.summary = "; ".join(parts) if parts else "No significant threats detected"

    return threat