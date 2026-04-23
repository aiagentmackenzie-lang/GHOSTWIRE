"""Tests for TCP session reconstruction (engine/parser/session.py)."""

import pytest
from engine.parser.session import reconstruct_sessions, TCPSession, _make_session_key
from engine.parser.pcap_loader import PacketRecord


def _make_packet(index, timestamp, src_ip, dst_ip, src_port, dst_port,
                 payload=b"", flags=0x02, l4="TCP") -> PacketRecord:
    """Build a PacketRecord for testing session reconstruction."""
    return PacketRecord(
        index=index,
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol_l4=l4,
        raw_payload=payload,
        length=len(payload) + 54,  # Approximate
        metadata={"tcp_flags": flags},
    )


class TestSessionKey:
    """Tests for session key canonicalization."""

    def test_canonical_ordering(self):
        """Session key should always put smaller IP:port first."""
        key1 = _make_session_key("10.0.0.1", 443, "192.168.1.1", 50000)
        key2 = _make_session_key("192.168.1.1", 50000, "10.0.0.1", 443)
        assert key1 == key2, "Same session should produce same key regardless of direction"

    def test_different_sessions_different_keys(self):
        """Different 5-tuples should produce different keys."""
        key1 = _make_session_key("10.0.0.1", 443, "192.168.1.1", 50000)
        key2 = _make_session_key("10.0.0.2", 443, "192.168.1.1", 50000)
        assert key1 != key2, "Different source IPs should produce different keys"


class TestReconstructSessions:
    """Tests for session reconstruction."""

    def test_packets_grouped_by_5tuple(self):
        """Packets with same 5-tuple should be in the same session."""
        pkts = [
            _make_packet(0, 1.0, "10.0.0.1", "192.168.1.1", 443, 50000, b"hello"),
            _make_packet(1, 2.0, "192.168.1.1", "10.0.0.1", 50000, 443, b"world"),
            _make_packet(2, 3.0, "10.0.0.1", "192.168.1.1", 443, 50000, b"!"),
        ]
        sessions = reconstruct_sessions(pkts)
        # All three should be in one session
        assert len(sessions) == 1
        assert sessions[0].packet_count == 3

    def test_different_sessions(self):
        """Packets to different destinations should be in separate sessions."""
        pkts = [
            _make_packet(0, 1.0, "10.0.0.1", "1.1.1.1", 443, 50000),
            _make_packet(1, 2.0, "10.0.0.1", "2.2.2.2", 443, 50001),
        ]
        sessions = reconstruct_sessions(pkts)
        assert len(sessions) == 2

    def test_iat_calculation(self):
        """Inter-arrival times should be calculated between consecutive packets."""
        pkts = [
            _make_packet(0, 1.0, "10.0.0.1", "1.1.1.1", 443, 50000),
            _make_packet(1, 5.0, "10.0.0.1", "1.1.1.1", 443, 50000),
            _make_packet(2, 10.0, "10.0.0.1", "1.1.1.1", 443, 50000),
        ]
        sessions = reconstruct_sessions(pkts)
        assert len(sessions) == 1
        iats = sessions[0].inter_arrival_times
        assert len(iats) == 2
        assert iats[0] == pytest.approx(4.0)
        assert iats[1] == pytest.approx(5.0)

    def test_rst_state_tracking(self):
        """RST flag should mark session as RST."""
        pkts = [
            _make_packet(0, 1.0, "10.0.0.1", "1.1.1.1", 443, 50000, flags=0x02),
            _make_packet(1, 2.0, "1.1.1.1", "10.0.0.1", 50000, 443, flags=0x04),  # RST
        ]
        sessions = reconstruct_sessions(pkts)
        assert sessions[0].state == "RST"

    def test_fin_state_tracking(self):
        """FIN flag should mark session as CLOSED."""
        pkts = [
            _make_packet(0, 1.0, "10.0.0.1", "1.1.1.1", 443, 50000, flags=0x02),
            _make_packet(1, 2.0, "1.1.1.1", "10.0.0.1", 50000, 443, flags=0x01),  # FIN
        ]
        sessions = reconstruct_sessions(pkts)
        assert sessions[0].state == "CLOSED"

    def test_non_tcp_packets_ignored(self):
        """Non-TCP packets should be ignored by session reconstruction."""
        pkts = [
            _make_packet(0, 1.0, "10.0.0.1", "1.1.1.1", 443, 50000, l4="UDP"),
        ]
        sessions = reconstruct_sessions(pkts)
        assert len(sessions) == 0

    def test_payload_reassembly(self):
        """Client and server payloads should be reassembled separately."""
        pkts = [
            _make_packet(0, 1.0, "10.0.0.1", "1.1.1.1", 443, 50000, payload=b"req1"),
            _make_packet(1, 2.0, "1.1.1.1", "10.0.0.1", 50000, 443, payload=b"resp1"),
            _make_packet(2, 3.0, "10.0.0.1", "1.1.1.1", 443, 50000, payload=b"req2"),
        ]
        sessions = reconstruct_sessions(pkts)
        assert len(sessions) == 1
        # First packet direction determines client→server
        assert b"req1" in sessions[0].client_payload
        assert b"resp1" in sessions[0].server_payload