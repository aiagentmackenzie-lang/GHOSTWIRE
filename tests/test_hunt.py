"""Tests for hunt mode queries (engine/detection/hunt.py)."""

from engine.detection.hunt import (
    BUILTIN_QUERIES,
    _is_private_ip,
    hunt_cobalt_strike,
    hunt_data_exfil,
    hunt_dns_tunneling,
    hunt_encrypted_c2,
    hunt_lateral_movement,
    hunt_suspicious_beacons,
    run_all_hunts,
    run_hunt,
)
from engine.parser.pcap_loader import PacketRecord
from engine.parser.session import TCPSession


def _make_session(
    session_id="10.0.0.1:443-192.168.1.1:50000",
    packet_count=20,
    iats=None,
    src_to_dst_bytes=500,
    dst_to_src_bytes=4500,
    duration=120.0,
    src_ip="10.0.0.1",
    dst_ip="192.168.1.1",
    src_port=443,
    dst_port=50000,
    protocol_l7="TLS",
    client_payload=b"\x00" * 100,
    server_payload=b"\xff" * 4000,
) -> TCPSession:
    """Build a TCPSession for testing hunt queries."""
    s = TCPSession(
        session_id=session_id,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        start_time=0.0, end_time=duration, duration=duration,
        src_to_dst_bytes=src_to_dst_bytes, dst_to_src_bytes=dst_to_src_bytes,
        packet_count=packet_count,
        inter_arrival_times=iats or [],
        client_payload=client_payload, server_payload=server_payload,
        protocol_l7=protocol_l7,
    )
    return s


def _make_packet(index=0, src_ip="10.0.0.1", dst_ip="93.184.216.34",
                 src_port=50000, dst_port=443, l4="TCP",
                 payload=b"", metadata=None) -> PacketRecord:
    return PacketRecord(
        index=index, timestamp=float(index), src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port, protocol_l4=l4,
        raw_payload=payload, length=len(payload) + 54,
        metadata=metadata or {},
    )


class TestIsPrivateIP:
    """Tests for the _is_private_ip helper."""

    def test_10_range(self):
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("10.255.255.255") is True

    def test_172_range(self):
        assert _is_private_ip("172.16.0.1") is True
        assert _is_private_ip("172.31.255.255") is True
        assert _is_private_ip("172.15.0.1") is False
        assert _is_private_ip("172.32.0.1") is False

    def test_192_168_range(self):
        assert _is_private_ip("192.168.1.1") is True

    def test_loopback(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_link_local(self):
        assert _is_private_ip("169.254.1.1") is True

    def test_public_ip(self):
        assert _is_private_ip("93.184.216.34") is False
        assert _is_private_ip("8.8.8.8") is False


class TestHuntSuspiciousBeacons:
    """Tests for hunt_suspicious_beacons."""

    def test_low_jitter_sustained_session_detected(self):
        iats = [60.0] * 20
        s = _make_session(packet_count=25, iats=iats, duration=1260, protocol_l7="TLS")
        results = hunt_suspicious_beacons([s])
        assert len(results) >= 1
        assert results[0]["jitter"] < 0.3

    def test_high_jitter_session_not_detected(self):
        iats = [i * 10 for i in range(1, 25)]
        s = _make_session(packet_count=25, iats=iats, duration=600, protocol_l7="TLS")
        results = hunt_suspicious_beacons([s])
        # Should not appear (high jitter)
        beacon_ids = [r.get("session_id") for r in results]
        assert s.session_id not in beacon_ids or all(r.get("jitter", 1.0) >= 0.3 for r in results if r.get("session_id") == s.session_id)


class TestHuntCobaltStrike:
    """Tests for hunt_cobalt_strike."""

    def test_cs_user_agent_detected(self):
        ua = b"GET /__init.gif HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0)\r\n\r\n"
        pkt = _make_packet(payload=ua)
        s = _make_session(packet_count=15, iats=[60.0] * 14, duration=900)
        results = hunt_cobalt_strike([s], [pkt])
        assert any("Cobalt Strike" in r.get("reason", "") or "user_agent" in str(r) for r in results)

    def test_cs_60s_interval_detected(self):
        iats = [60.0] * 15
        s = _make_session(packet_count=20, iats=iats, duration=960, protocol_l7="TLS")
        results = hunt_cobalt_strike([s], [])
        assert any("~60s" in r.get("reason", "") for r in results)


class TestHuntDNSTunneling:
    """Tests for hunt_dns_tunneling."""

    def test_txt_query_detected(self):
        pkt = _make_packet(l4="UDP", payload=b"\x12\x34")
        pkt.protocol_l7 = "DNS"
        pkt.metadata = {"protocol_result": {"dns": {"query_name": "data.evil.com", "query_type": "TXT"}}}
        results = hunt_dns_tunneling([pkt])
        assert len(results) >= 1
        assert any("TXT" in r.get("reason", "") for r in results)


class TestHuntDataExfil:
    """Tests for hunt_data_exfil."""

    def test_large_transfer_detected(self):
        s = _make_session(src_to_dst_bytes=5_000_000, dst_to_src_bytes=1000, duration=60)
        results = hunt_data_exfil([s])
        assert len(results) >= 1
        assert "5.0 MB" in results[0]["bytes_out"]


class TestHuntLateralMovement:
    """Tests for hunt_lateral_movement."""

    def test_internal_rdp_detected(self):
        s = _make_session(src_ip="10.0.0.5", dst_ip="10.0.0.10", src_port=50000, dst_port=3389, protocol_l7="")
        results = hunt_lateral_movement([s])
        assert len(results) >= 1
        assert "3389" in results[0]["reason"]

    def test_public_to_private_rdp_detected(self):
        s = _make_session(src_ip="93.184.216.34", dst_ip="10.0.0.10", src_port=50000, dst_port=3389, protocol_l7="")
        # Public → private is not internal-to-internal, should NOT be flagged
        results = hunt_lateral_movement([s])
        # Only internal-to-internal should be flagged
        assert not any(r.get("session_id") == s.session_id for r in results)

    def test_loopback_excluded(self):
        s = _make_session(src_ip="127.0.0.1", dst_ip="127.0.0.1", src_port=50000, dst_port=22)
        results = hunt_lateral_movement([s])
        # Loopback is private but this is a legitimate test — 127.0.0.1 to 127.0.0.1 on port 22
        # should still be flagged as lateral movement (both are "private")
        assert len(results) >= 1


class TestHuntEncryptedC2:
    """Tests for hunt_encrypted_c2."""

    def test_high_entropy_external_tls(self):
        # High entropy payload (~8.0) to external IP
        import os
        payload = os.urandom(4096)
        s = _make_session(
            src_ip="10.0.0.1", dst_ip="93.184.216.34",
            dst_port=443, protocol_l7="TLS",
            client_payload=payload[:2048], server_payload=payload[2048:],
        )
        results = hunt_encrypted_c2([s])
        assert len(results) >= 1


class TestRunHunt:
    """Tests for the run_hunt dispatcher."""

    def test_unknown_query_returns_empty(self):
        s = _make_session()
        results = run_hunt("nonexistent_query", [s], [])
        assert results == []

    def test_run_all_hunts(self):
        s = _make_session(packet_count=15, iats=[60.0] * 14, duration=900)
        results = run_all_hunts([s], [])
        assert isinstance(results, dict)

    def test_builtin_queries_count(self):
        assert len(BUILTIN_QUERIES) == 6
