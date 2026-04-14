"""C2 Beacon Detector — statistical analysis of network timing and volume.

Detects command-and-control beacon patterns in network traffic using:
- Inter-arrival time (IAT) jitter analysis
- Volume asymmetry scoring
- Connection regularity detection
- Shannon entropy of payloads
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Optional

from engine.parser.session import TCPSession

logger = logging.getLogger(__name__)


@dataclass
class BeaconScore:
    """C2 beacon detection score for a session."""
    session_id: str
    overall_score: float = 0.0  # 0.0 - 1.0
    confidence: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    jitter_score: float = 0.0
    volume_score: float = 0.0
    regularity_score: float = 0.0
    entropy_score: float = 0.0
    iat_mean: float = 0.0
    iat_std: float = 0.0
    iat_jitter: float = 0.0  # std/mean — key indicator
    duration: float = 0.0
    packet_count: int = 0
    byte_ratio: float = 0.0
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "overall_score": round(self.overall_score, 3),
            "confidence": self.confidence,
            "jitter_score": round(self.jitter_score, 3),
            "volume_score": round(self.volume_score, 3),
            "regularity_score": round(self.regularity_score, 3),
            "entropy_score": round(self.entropy_score, 3),
            "iat_mean": round(self.iat_mean, 2),
            "iat_std": round(self.iat_std, 2),
            "iat_jitter": round(self.iat_jitter, 3),
            "duration": round(self.duration, 2),
            "packet_count": self.packet_count,
            "byte_ratio": round(self.byte_ratio, 3),
            "reasons": self.reasons,
        }


def _mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    return math.sqrt(sum((x - m) ** 2 for x in values) / len(values))


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def detect_beacon(session: TCPSession, min_packets: int = 10) -> Optional[BeaconScore]:
    """Analyze a TCP session for C2 beacon patterns.

    Args:
        session: Reconstructed TCP session.
        min_packets: Minimum packets required for statistical significance.

    Returns:
        BeaconScore if session is analyzable, None if too few packets.
    """
    if session.packet_count < min_packets:
        return None

    score = BeaconScore(
        session_id=session.session_id,
        duration=session.duration,
        packet_count=session.packet_count,
    )

    # === 1. JITTER ANALYSIS ===
    # C2 beacons have very consistent timing → low jitter (std/mean)
    # Use the LONGER IATs (beacon-to-beacon) not the short response gaps
    if session.inter_arrival_times:
        iats = session.inter_arrival_times
        # Filter out short IATs (< 1s) which are likely request-response pairs
        # Real beacon intervals are typically > 10s
        beacon_iats = [i for i in iats if i > 1.0]
        if len(beacon_iats) >= 3:
            iats = beacon_iats

        score.iat_mean = _mean(iats)
        score.iat_std = _std(iats)
        score.iat_jitter = score.iat_std / score.iat_mean if score.iat_mean > 0 else 0.0

        # Scoring: lower jitter = more beacon-like
        # jitter < 0.1 = very suspicious, < 0.3 = suspicious, < 0.5 = interesting
        if score.iat_jitter < 0.1:
            score.jitter_score = 0.95
            score.reasons.append(f"Extremely low jitter ({score.iat_jitter:.3f}) — consistent beacon interval")
        elif score.iat_jitter < 0.2:
            score.jitter_score = 0.80
            score.reasons.append(f"Low jitter ({score.iat_jitter:.3f}) — likely beacon pattern")
        elif score.iat_jitter < 0.3:
            score.jitter_score = 0.60
            score.reasons.append(f"Moderate-low jitter ({score.iat_jitter:.3f}) — possible beacon")
        elif score.iat_jitter < 0.5:
            score.jitter_score = 0.35
            score.reasons.append(f"Marginal jitter ({score.iat_jitter:.3f}) — irregular beacon possible")
        else:
            score.jitter_score = 0.1

    # === 2. VOLUME ASYMMETRY ===
    # C2 typically: small request → variable response (command + response)
    total_bytes = session.src_to_dst_bytes + session.dst_to_src_bytes
    if total_bytes > 0:
        score.byte_ratio = session.src_to_dst_bytes / total_bytes
        # Very asymmetric traffic (90%+ one direction) is suspicious for non-standard protocols
        if 0.05 < score.byte_ratio < 0.15 or 0.85 < score.byte_ratio < 0.95:
            score.volume_score = 0.6
            score.reasons.append(f"Highly asymmetric traffic (ratio: {score.byte_ratio:.2f})")
        elif 0.15 < score.byte_ratio < 0.25 or 0.75 < score.byte_ratio < 0.85:
            score.volume_score = 0.3

    # === 3. CONNECTION REGULARITY ===
    # Long-duration sessions with consistent activity = potential persistent C2
    if session.duration > 60 and session.packet_count > 20:
        packets_per_second = session.packet_count / session.duration
        # Consistent low-rate traffic (1-10 pkts/sec sustained) is typical C2 heartbeat
        if 0.01 < packets_per_second < 1.0 and score.iat_jitter < 0.5:
            score.regularity_score = 0.7
            score.reasons.append(f"Sustained low-rate traffic ({packets_per_second:.2f} pkt/s over {session.duration:.0f}s)")
        elif 1.0 <= packets_per_second < 5.0 and score.iat_jitter < 0.3:
            score.regularity_score = 0.5
            score.reasons.append(f"Regular moderate-rate traffic ({packets_per_second:.1f} pkt/s)")
        elif packets_per_second >= 5.0:
            score.regularity_score = 0.1  # High rate = likely normal traffic

    # === 4. ENTROPY ANALYSIS ===
    # Encrypted C2 shows high entropy; check payload
    combined_payload = session.client_payload + session.server_payload
    if combined_payload:
        entropy = _shannon_entropy(combined_payload[:4096])  # Sample first 4KB
        # High entropy (>7.5) with low volume = encrypted C2 channel
        if entropy > 7.5:
            score.entropy_score = 0.5
            score.reasons.append(f"High payload entropy ({entropy:.2f}) — likely encrypted C2")
        elif entropy > 6.5:
            score.entropy_score = 0.25

    # === COMPOSITE SCORE ===
    # Weighted combination: jitter is most important signal
    weights = {
        "jitter": 0.40,
        "volume": 0.20,
        "regularity": 0.25,
        "entropy": 0.15,
    }
    score.overall_score = (
        weights["jitter"] * score.jitter_score +
        weights["volume"] * score.volume_score +
        weights["regularity"] * score.regularity_score +
        weights["entropy"] * score.entropy_score
    )

    # Assign confidence level
    if score.overall_score >= 0.80:
        score.confidence = "CRITICAL"
    elif score.overall_score >= 0.60:
        score.confidence = "HIGH"
    elif score.overall_score >= 0.40:
        score.confidence = "MEDIUM"
    elif score.overall_score >= 0.25:
        score.confidence = "LOW"
    else:
        score.confidence = "NEGLIGIBLE"

    return score


def detect_beacons(sessions: list[TCPSession], min_packets: int = 10,
                   min_score: float = 0.25) -> list[BeaconScore]:
    """Scan all sessions for C2 beacon patterns.

    Args:
        sessions: List of reconstructed TCP sessions.
        min_packets: Minimum packets for analysis.
        min_score: Minimum score threshold to include in results.

    Returns:
        List of BeaconScore objects, sorted by score descending.
    """
    results: list[BeaconScore] = []

    for session in sessions:
        score = detect_beacon(session, min_packets)
        if score and score.overall_score >= min_score:
            results.append(score)

    results.sort(key=lambda s: s.overall_score, reverse=True)

    if results:
        logger.info(f"C2 beacon detection: {len(results)} suspicious sessions found "
                    f"({sum(1 for r in results if r.confidence in ('HIGH', 'CRITICAL'))} high confidence)")

    return results