"""Tests for the composite threat scorer (engine/detection/scorer.py)."""

import pytest

from engine.detection.beacon import BeaconScore
from engine.detection.dns_threats import DNSThreat
from engine.detection.scorer import score_session
from engine.fingerprint.c2_database import C2Match


class TestScoreSession:
    """Tests for score_session()."""

    def test_beacon_only_scoring(self):
        """A CRITICAL beacon alone should score CRITICAL overall (audit H-04 fix).

        Before the fix, the weighted composite capped a beacon-only signal at
        0.40*0.85 = 0.34 → LOW, drowning a textbook beacon. The strong-beacon
        floor raises overall to the beacon score when the beacon is HIGH/CRITICAL.
        """
        beacon = BeaconScore(
            session_id="test-session",
            overall_score=0.85,
            confidence="CRITICAL",
            iat_jitter=0.05,
        )
        result = score_session("test-session", beacon=beacon)
        assert result.overall_score == pytest.approx(0.85, abs=0.01)
        assert result.confidence == "CRITICAL"
        assert result.beacon_score == 0.85

    def test_medium_beacon_no_floor(self):
        """A MEDIUM/LOW beacon (not HIGH/CRITICAL) must NOT trigger the floor —
        the weighted composite applies normally so absent C2/DNS doesn't inflate."""
        beacon = BeaconScore(session_id="s", overall_score=0.5, confidence="MEDIUM")
        result = score_session("s", beacon=beacon)
        assert result.overall_score == pytest.approx(0.5 * 0.40, abs=0.01)
        assert result.confidence == "NEGLIGIBLE"  # 0.20 < 0.25

    def test_strong_beacon_floor_regression(self):
        """Audit H-04 regression: a CRITICAL beacon with NO c2/dns must reach
        CRITICAL overall, not be drowned to LOW by the weighted composite."""
        beacon = BeaconScore(session_id="s", overall_score=0.95, confidence="CRITICAL",
                             iat_jitter=0.02)
        result = score_session("s", beacon=beacon)
        # Without the floor this would be 0.40*0.95 = 0.38 (LOW). With the floor
        # it is max(0.38, 0.95) = 0.95 → CRITICAL.
        assert result.overall_score == pytest.approx(0.95, abs=0.01)
        assert result.confidence == "CRITICAL"

    def test_c2_only_scoring(self):
        """Session with only C2 match should score correctly."""
        c2 = C2Match(
            tool_name="cobalt_strike",
            confidence=0.90,
            match_type="http_pattern",
            matched_value="test-ua",
            description="Cobalt Strike",
        )
        result = score_session("test-session", c2_matches=[c2])
        assert result.overall_score == pytest.approx(0.90 * 0.35, abs=0.01)
        # IOC format includes matched value
        assert "C2:cobalt_strike (test-ua)" in result.iocs

    def test_dns_only_scoring(self):
        """Session with only DNS threat should score correctly."""
        dns = DNSThreat(
            domain="xkrqzmwjtpbd.vvcc",
            threat_type="dga",
            confidence=0.80,
            score=0.80,
        )
        result = score_session("test-session", dns_threats=[dns])
        assert result.overall_score == pytest.approx(0.80 * 0.25, abs=0.01)

    def test_combined_scoring(self):
        """Session with HIGH beacon + C2 + DNS: composite boosts above the beacon floor."""
        beacon = BeaconScore(session_id="s1", overall_score=0.75, confidence="HIGH")
        c2 = C2Match(tool_name="sliver", confidence=0.85, match_type="ja4",
                     matched_value="t12d0504h2_abc", description="Sliver")
        dns = DNSThreat(domain="evil.evil.com", threat_type="dga", confidence=0.7, score=0.7)

        result = score_session("s1", beacon=beacon, c2_matches=[c2], dns_threats=[dns])
        composite = 0.40 * 0.75 + 0.35 * 0.85 + 0.25 * 0.7  # 0.7725
        # Beacon is HIGH → floor at 0.75; composite (0.7725) > 0.75, so composite wins
        assert result.overall_score == pytest.approx(max(composite, 0.75), abs=0.01)
        assert result.overall_score >= 0.75

    def test_no_signals_low_score(self):
        """Session with no signals should have negligible score."""
        result = score_session("quiet-session")
        assert result.overall_score == 0.0
        assert result.confidence == "NEGLIGIBLE"

    def test_ioc_collection(self):
        """IOCs should be collected from C2 matches and DNS threats."""
        c2 = C2Match(tool_name="cobalt_strike", confidence=0.9, match_type="ja3",
                     matched_value="hash123", description="CS",
                     mitre_techniques=["T1071.001"])
        dns = DNSThreat(domain="evil.com", threat_type="dga", confidence=0.7, score=0.7)

        result = score_session("s1", c2_matches=[c2], dns_threats=[dns])
        assert "C2:cobalt_strike (hash123)" in result.iocs
        assert "DNS:evil.com (dga)" in result.iocs
        assert "T1071.001" in result.mitre_techniques

    def test_confidence_critical(self):
        """Overall score >= 0.80 should yield CRITICAL confidence."""
        beacon = BeaconScore(session_id="s", overall_score=1.0, confidence="CRITICAL")
        c2 = C2Match(tool_name="t", confidence=1.0, match_type="x", matched_value="y")
        dns = DNSThreat(domain="d", threat_type="dga", confidence=1.0, score=1.0)
        result = score_session("s", beacon=beacon, c2_matches=[c2], dns_threats=[dns])
        # 0.40*1.0 + 0.35*1.0 + 0.25*1.0 = 1.0 → CRITICAL
        assert result.confidence == "CRITICAL"

    def test_confidence_high(self):
        """Overall score 0.60-0.79 should yield HIGH confidence."""
        beacon = BeaconScore(session_id="s", overall_score=0.70, confidence="HIGH")
        c2 = C2Match(tool_name="t", confidence=0.95, match_type="x", matched_value="y")
        result = score_session("s", beacon=beacon, c2_matches=[c2])
        # composite = 0.40*0.70 + 0.35*0.95 = 0.6125; floor at 0.70 → 0.70 → HIGH
        assert result.overall_score == pytest.approx(0.70, abs=0.01)
        assert result.confidence == "HIGH"

    def test_to_dict_roundtrip(self):
        """ThreatScore.to_dict() should produce serializable dict."""
        beacon = BeaconScore(session_id="s1", overall_score=0.5, confidence="MEDIUM")
        result = score_session("s1", beacon=beacon)
        d = result.to_dict()
        assert d["target"] == "s1"
        assert d["target_type"] == "session"
        assert isinstance(d["overall_score"], float)

    def test_deduplicated_mitre_techniques(self):
        """Duplicate MITRE techniques should be deduplicated."""
        c2 = C2Match(tool_name="t1", confidence=0.9, match_type="x", matched_value="y",
                     mitre_techniques=["T1071.001"])
        c2_2 = C2Match(tool_name="t2", confidence=0.8, match_type="x", matched_value="z",
                       mitre_techniques=["T1071.001", "T1573.001"])
        result = score_session("s1", c2_matches=[c2, c2_2])
        assert result.mitre_techniques.count("T1071.001") == 1
        assert "T1573.001" in result.mitre_techniques
