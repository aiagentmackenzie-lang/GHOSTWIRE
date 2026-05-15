"""Tests for the composite threat scorer (engine/detection/scorer.py)."""

import pytest
from engine.detection.scorer import score_session
from engine.detection.beacon import BeaconScore
from engine.detection.dns_threats import DNSThreat
from engine.fingerprint.c2_database import C2Match


class TestScoreSession:
    """Tests for score_session()."""

    def test_beacon_only_scoring(self):
        """Session with only beacon detection should score correctly."""
        beacon = BeaconScore(
            session_id="test-session",
            overall_score=0.85,
            confidence="CRITICAL",
            iat_jitter=0.05,
        )
        result = score_session("test-session", beacon=beacon)
        assert result.overall_score == pytest.approx(0.85 * 0.40, abs=0.01)
        # 0.34 → LOW confidence (>=0.25 but <0.40)
        assert result.confidence == "LOW"
        assert result.beacon_score == 0.85

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
        """Session with beacon + C2 + DNS should use weighted composite."""
        beacon = BeaconScore(session_id="s1", overall_score=0.9, confidence="HIGH")
        c2 = C2Match(tool_name="sliver", confidence=0.85, match_type="ja4",
                     matched_value="t12d0504h2_abc", description="Sliver")
        dns = DNSThreat(domain="evil.evil.com", threat_type="dga", confidence=0.7, score=0.7)

        result = score_session("s1", beacon=beacon, c2_matches=[c2], dns_threats=[dns])
        expected = 0.40 * 0.9 + 0.35 * 0.85 + 0.25 * 0.7
        assert result.overall_score == pytest.approx(expected, abs=0.01)

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
        beacon = BeaconScore(session_id="s", overall_score=0.85, confidence="HIGH")
        result = score_session("s", beacon=beacon)
        # 0.85 * 0.40 = 0.34 → not HIGH alone
        # Need combined score >= 0.60: use strong C2 too
        c2 = C2Match(tool_name="t", confidence=0.95, match_type="x", matched_value="y")
        result = score_session("s", beacon=beacon, c2_matches=[c2])
        # 0.40*0.85 + 0.35*0.95 = 0.34 + 0.3325 = 0.6725 → HIGH
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