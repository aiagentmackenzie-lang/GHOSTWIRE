"""Composite threat scorer — weighted scoring across all detection signals.

The weights are unchanged (beacon 0.40, C2 rule match 0.35, DNS 0.25) so
historical scores remain comparable. What changed in Wave 1 is *attribution*:

* ``score_session`` only receives evidence that belongs to that conversation.
  A DNS observation is not a TCP signal and is no longer passed in from a
  capture-wide collection (the 0.315 → 0.565 jump in the audit came from doing
  exactly that).
* Every component records the value it used, the weight, the contribution and
  the finding ids that supplied it, so the prose, the structured list and the
  number cannot drift apart.
* The summary describes the *rule match*, not a confirmed compromise. A
  User-Agent string match establishes a string match.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from engine.detection.beacon import BeaconScore
from engine.detection.dns_threats import DNSThreat
from engine.fingerprint.c2_database import C2Match

logger = logging.getLogger(__name__)

#: Weights for the composite session score. Named so output can state them.
SCORE_WEIGHTS: dict[str, float] = {
    "beacon": 0.40,
    "c2": 0.35,
    "dns": 0.25,
}

#: Severity bands, inclusive lower bound, upper bound exclusive (except top).
SEVERITY_BANDS: list[tuple[str, float]] = [
    ("CRITICAL", 0.80),
    ("HIGH", 0.60),
    ("MEDIUM", 0.40),
    ("LOW", 0.25),
    ("NEGLIGIBLE", 0.0),
]

SCORE_SCALE = "weighted_composite_0_1"


def severity_for(score: float) -> str:
    for label, lower in SEVERITY_BANDS:
        if score >= lower:
            return label
    return "NEGLIGIBLE"


@dataclass
class ScoreComponent:
    """One input to a conversation score, with its unit and provenance."""
    source: str                 # "beacon" | "c2" | "dns" | "beacon_floor"
    value: float                # the signal value on ``value_scale``
    weight: float               # weight applied to this signal on the composite
    contribution: float         # weight * value (or the floor's delta)
    value_scale: str = "0_1"
    finding_id: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "value": round(self.value, 6),
            "weight": self.weight,
            "contribution": round(self.contribution, 6),
            "value_scale": self.value_scale,
            "finding_id": self.finding_id or None,
            "detail": self.detail,
        }


@dataclass
class ThreatScore:
    """Composite threat assessment for a session or endpoint."""
    target: str  # session_id, IP, or domain
    target_type: str  # "session", "ip", "domain"
    overall_score: float = 0.0
    confidence: str = "LOW"
    beacon_score: float | None = None
    c2_matches: list[C2Match] = field(default_factory=list)
    dns_threats: list[DNSThreat] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    summary: str = ""
    components: list[ScoreComponent] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    endpoints: dict = field(default_factory=dict)
    client_side: str = "unknown"
    role_basis: str = ""
    # Measured beacon inputs (None when no beacon detector ran on this session).
    beacon_detail: dict | None = None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "overall_score": round(self.overall_score, 3),
            "score_scale": SCORE_SCALE,
            "confidence": self.confidence,
            "beacon_score": round(self.beacon_score, 3) if self.beacon_score else None,
            "c2_matches": [m.to_dict() for m in self.c2_matches],
            "dns_threats": [t.to_dict() for t in self.dns_threats],
            "iocs": self.iocs,
            "mitre_techniques": self.mitre_techniques,
            "summary": self.summary,
            "finding_ids": self.finding_ids,
            "components": [c.to_dict() for c in self.components],
            "endpoints": self.endpoints,
            "client_side": self.client_side,
            "role_basis": self.role_basis,
            "beacon_detail": self.beacon_detail,
        }


def score_session(
    session_id: str,
    beacon: BeaconScore | None = None,
    c2_matches: list[C2Match] | None = None,
    dns_threats: list[DNSThreat] | None = None,
    *,
    c2_finding_ids: list[str] | None = None,
    beacon_finding_id: str | None = None,
    dns_finding_ids: list[str] | None = None,
) -> ThreatScore:
    """Compute composite threat score for a session.

    Weights:
    - Beacon detection: 40%
    - C2 fingerprint match: 35%
    - DNS threats: 25%

    ``dns_threats`` is kept for API compatibility with callers that genuinely
    have a DNS observation *inside* this conversation. The analysis pipeline
    does not use it: DNS observations are standalone findings, because sharing a
    client address or timestamp is not evidence that a query and a TCP session
    are the same event.
    """
    threat = ThreatScore(target=session_id, target_type="session")
    c2_matches = c2_matches or []
    dns_threats = dns_threats or []
    # Record the inputs that produced the score. The 0.2.x serializer emitted an
    # empty structured list here while the prose named the same match, so the
    # two views of one finding disagreed.
    threat.c2_matches = list(c2_matches)
    threat.dns_threats = list(dns_threats)
    c2_finding_ids = c2_finding_ids or []
    dns_finding_ids = dns_finding_ids or []

    # Beacon contribution
    beacon_value = beacon.overall_score if beacon else 0.0
    threat.beacon_score = beacon_value
    if beacon is not None:
        threat.beacon_detail = {
            "overall_score": round(beacon.overall_score, 6),
            "confidence": beacon.confidence,
            "iat_mean": round(beacon.iat_mean, 6),
            "iat_std": round(beacon.iat_std, 6),
            "iat_jitter": round(beacon.iat_jitter, 6),
            "packet_count": beacon.packet_count,
            "duration": round(beacon.duration, 6),
            "byte_ratio": round(beacon.byte_ratio, 6),
            "components": {
                "jitter": round(beacon.jitter_score, 6),
                "volume": round(beacon.volume_score, 6),
                "regularity": round(beacon.regularity_score, 6),
                "entropy": round(beacon.entropy_score, 6),
            },
            "units": {
                "iat_mean": "seconds (mean inter-arrival of intervals > 1s)",
                "iat_jitter": "std/mean, dimensionless",
                "duration": "seconds (observed time bounds)",
                "byte_ratio": "src_to_dst / total payload bytes",
            },
        }

    # C2 match contribution (highest confidence match)
    c2_value = max((m.confidence for m in c2_matches), default=0.0)

    # DNS threat contribution (highest scoring threat)
    dns_value = max((t.score for t in dns_threats), default=0.0)

    # Weighted composite
    composite = (
        SCORE_WEIGHTS["beacon"] * beacon_value
        + SCORE_WEIGHTS["c2"] * c2_value
        + SCORE_WEIGHTS["dns"] * dns_value
    )

    threat.components = []
    if beacon_value:
        threat.components.append(ScoreComponent(
            source="beacon", value=beacon_value, weight=SCORE_WEIGHTS["beacon"],
            contribution=SCORE_WEIGHTS["beacon"] * beacon_value,
            value_scale="beacon_score_0_1", finding_id=beacon_finding_id or "",
            detail="beacon detector score",
        ))
    if c2_value:
        threat.components.append(ScoreComponent(
            source="c2", value=c2_value, weight=SCORE_WEIGHTS["c2"],
            contribution=SCORE_WEIGHTS["c2"] * c2_value,
            value_scale="rule_weight_0_1",
            finding_id=(c2_finding_ids[0] if c2_finding_ids else ""),
            detail="highest-confidence C2 rule match in this conversation",
        ))
    if dns_value:
        threat.components.append(ScoreComponent(
            source="dns", value=dns_value, weight=SCORE_WEIGHTS["dns"],
            contribution=SCORE_WEIGHTS["dns"] * dns_value,
            value_scale="rule_score_0_1",
            finding_id=(dns_finding_ids[0] if dns_finding_ids else ""),
            detail="DNS rule score attributed to this conversation",
        ))

    # Strong-beacon floor (audit H-04): a textbook beacon (jitter < 0.1) should
    # not be drowned to LOW just because C2/DNS signals are absent. When the
    # beacon detector itself is HIGH/CRITICAL, the beacon score is the floor
    # and C2/DNS signals act as a boost toward CRITICAL — not as a penalty.
    # Without this, a perfect beacon caps at 0.40*0.95 = 0.38 < MEDIUM.
    if beacon and beacon.confidence in ("HIGH", "CRITICAL"):
        threat.overall_score = max(composite, beacon_value)
        if threat.overall_score > composite:
            threat.components.append(ScoreComponent(
                source="beacon_floor", value=beacon_value,
                weight=1.0, contribution=threat.overall_score - composite,
                value_scale="beacon_score_0_1",
                finding_id=beacon_finding_id or "",
                detail="HIGH/CRITICAL beacon floor raised the composite",
            ))
    else:
        threat.overall_score = composite

    # Assign confidence
    threat.confidence = severity_for(threat.overall_score)

    # Collect IOCs
    for m in c2_matches:
        threat.iocs.append(f"C2:{m.tool_name} ({m.matched_value})")
        threat.mitre_techniques.extend(m.mitre_techniques)

    for t in dns_threats:
        threat.iocs.append(f"DNS:{t.domain} ({t.threat_type})")

    # Deduplicate MITRE techniques
    threat.mitre_techniques = list(set(threat.mitre_techniques))

    threat.finding_ids = [i for i in (
        ([beacon_finding_id] if beacon_finding_id else [])
        + c2_finding_ids
        + dns_finding_ids
    ) if i]

    # Build summary. Deliberately describes the rule match, not a confirmed
    # compromise: an exact User-Agent string establishes a string match.
    parts = []
    if beacon and beacon.confidence in ("HIGH", "CRITICAL"):
        parts.append(f"Beacon timing heuristic fired (jitter: {beacon.iat_jitter:.3f})")
    if c2_matches:
        tools = ", ".join(sorted({m.tool_name for m in c2_matches}))
        parts.append(f"Rule match: {tools} (tool attribution is an inference)")
    if dns_threats:
        parts.append(f"DNS rule matched: {', '.join(sorted({t.threat_type for t in dns_threats}))}")
    threat.summary = "; ".join(parts) if parts else "No rule matched this conversation"

    return threat
