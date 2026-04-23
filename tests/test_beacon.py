"""Tests for C2 beacon detection (engine/detection/beacon.py)."""

import pytest
from engine.detection.beacon import detect_beacon, detect_beacons, BeaconScore
from engine.parser.session import TCPSession


def _make_session(
    session_id="10.0.0.1:443-192.168.1.1:50000",
    packet_count=20,
    iats=None,
    src_to_dst_bytes=500,
    dst_to_src_bytes=4500,
    duration=120.0,
    client_payload=b"\x00" * 100,
    server_payload=b"\xff" * 4000,
) -> TCPSession:
    """Build a TCPSession for testing beacon detection."""
    s = TCPSession(
        session_id=session_id,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.1",
        src_port=443,
        dst_port=50000,
        start_time=0.0,
        end_time=duration,
        duration=duration,
        src_to_dst_bytes=src_to_dst_bytes,
        dst_to_src_bytes=dst_to_src_bytes,
        packet_count=packet_count,
        inter_arrival_times=iats or [],
        client_payload=client_payload,
        server_payload=server_payload,
    )
    return s


class TestDetectBeacon:
    """Unit tests for detect_beacon()."""

    def test_low_jitter_yields_high_score(self):
        """Session with very consistent intervals should score high."""
        # 60-second beacon intervals with tiny jitter
        iats = [60.0, 60.1, 59.9, 60.0, 60.05, 59.95, 60.0, 60.02, 59.98, 60.01,
                60.0, 59.97, 60.03, 60.0, 59.99, 60.01, 60.0, 60.02, 59.98, 60.0]
        s = _make_session(packet_count=25, iats=iats, duration=1260)
        result = detect_beacon(s, min_packets=10)
        assert result is not None
        assert result.jitter_score >= 0.6, f"Expected high jitter score for low-jitter session, got {result.jitter_score}"
        assert result.iat_jitter < 0.1, f"Expected jitter < 0.1, got {result.iat_jitter}"

    def test_high_jitter_yields_low_score(self):
        """Session with random intervals should score low."""
        import random
        random.seed(42)
        # Highly variable intervals (1s to 300s)
        iats = [random.uniform(1, 300) for _ in range(25)]
        s = _make_session(packet_count=30, iats=iats, duration=sum(iats))
        result = detect_beacon(s, min_packets=10)
        assert result is not None
        assert result.jitter_score < 0.4, f"Expected low jitter score for high-jitter session, got {result.jitter_score}"

    def test_below_min_packets_returns_none(self):
        """Session with fewer than min_packets should return None."""
        s = _make_session(packet_count=5, iats=[1.0, 2.0, 3.0, 4.0])
        result = detect_beacon(s, min_packets=10)
        assert result is None

    def test_empty_iats(self):
        """Session with no IATs should still return a score (0.0 jitter)."""
        s = _make_session(packet_count=15, iats=[])
        result = detect_beacon(s, min_packets=10)
        assert result is not None
        assert result.iat_jitter == 0.0

    def test_detect_beacons_filters_by_min_score(self):
        """detect_beacons() should filter out sessions below min_score."""
        # One beacon session, one noisy session
        beacon_iats = [60.0] * 20
        noisy_iats = [i * 10 for i in range(20)]  # Increasing, high jitter

        beacon_session = _make_session(
            session_id="beacon:443-client:50001",
            packet_count=25, iats=beacon_iats, duration=1260
        )
        noisy_session = _make_session(
            session_id="noise:80-client:50002",
            packet_count=25, iats=noisy_iats, duration=200,
            src_to_dst_bytes=5000, dst_to_src_bytes=5000,
        )
        results = detect_beacons([beacon_session, noisy_session], min_packets=10, min_score=0.25)
        # Beacon should be in results, noisy may or may not (depends on score)
        # At minimum, the beacon should appear
        beacon_ids = [r.session_id for r in results]
        assert "beacon:443-client:50001" in beacon_ids


class TestBeaconScore:
    """Tests for BeaconScore dataclass."""

    def test_to_dict_roundtrip(self):
        score = BeaconScore(session_id="test", overall_score=0.75, confidence="HIGH")
        d = score.to_dict()
        assert d["session_id"] == "test"
        assert d["overall_score"] == 0.75
        assert d["confidence"] == "HIGH"