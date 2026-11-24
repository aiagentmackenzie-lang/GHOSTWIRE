"""Wave 1 slice 3: reconstruction, roles, timing and fingerprint evidence.

These controls come from the Sweep 3 "capture support matrix" and the revised
delivery slices. Each one is a distinction the 0.2.x suite could not express:
captured vs distinct bytes, a capture hole, a reversed file order, a capture
that starts on the server side, and a server whose declared framing the decoder
did not understand.
"""

from __future__ import annotations

import pytest

from engine.analysis import run_analysis
from engine.parser.pcap_loader import load_pcap
from engine.parser.session import SessionAccumulator, reconstruct_sessions

SPLIT_SNI = "evil.example.com"


def _sessions_from(pcap: str, eager: bool):
    packets = load_pcap(pcap)
    if eager:
        return reconstruct_sessions(packets)
    acc = SessionAccumulator()
    for pkt in packets:
        acc.feed(pkt)
    return acc.build()


class TestCompleteAndSplitHelloAgree:
    def test_same_sni_ja3_ja4(self, complete_hello_pcap, split_tls_pcap):
        complete = run_analysis(complete_hello_pcap)
        split = run_analysis(split_tls_pcap)

        assert len(complete.tls_fps) == 1
        assert len(split.tls_fps) == 1
        for field in ("sni", "ja3_hash", "ja4"):
            assert getattr(complete.tls_fps[0], field) == getattr(split.tls_fps[0], field)
        assert split.tls_fps[0].sni == SPLIT_SNI

        # The frame references must describe the layout: one frame vs two.
        assert complete.sessions[0].src_reassembly.ranges[0].frames == [1]
        assert split.sessions[0].src_reassembly.ranges[0].frames == [1, 2]
        assert split.sessions[0].src_reassembly.ranges[0].length == 77


class TestDuplicateSegment:
    def test_one_fingerprint_captured_and_distinct_bytes_differ(
            self, duplicate_segment_pcap):
        for eager in (False, True):
            sessions = _sessions_from(duplicate_segment_pcap, eager)
            assert len(sessions) == 1, f"eager={eager}"
            session = sessions[0]
            reassembly = session.src_reassembly

            # 30 + 30 + 47 bytes on the wire, 77 distinct stream bytes.
            assert reassembly.captured_payload_bytes == 107
            assert reassembly.distinct_stream_bytes == 77
            assert len(reassembly.payload) == 77
            assert reassembly.gaps == []
            assert reassembly.ranges[0].frames == [1, 2, 3]

        result = run_analysis(duplicate_segment_pcap)
        assert len(result.tls_fps) == 1
        assert result.tls_fps[0].sni == SPLIT_SNI


class TestCaptureGap:
    def test_truncated_record_exposes_two_ranges_and_19_missing_bytes(
            self, truncated_hello_pcap):
        for eager in (False, True):
            sessions = _sessions_from(truncated_hello_pcap, eager)
            session = sessions[0]
            reassembly = session.src_reassembly

            assert [(r.start, r.end) for r in reassembly.ranges] == [(1, 12), (31, 78)]
            assert [(g.start, g.end, g.missing_bytes) for g in reassembly.gaps] == [
                (12, 31, 19),
            ]
            assert reassembly.missing_bytes == 19
            assert reassembly.distinct_stream_bytes == 58  # 11 + 47 captured
            # The stored payload is the contiguous prefix only — no invented join.
            assert len(reassembly.payload) == 11

        result = run_analysis(truncated_hello_pcap)
        # The ClientHello record spans the hole, so no fingerprint may be made.
        assert result.tls_fps == []
        assert result.findings == []
        assert result.coverage.status == "partial"
        assert result.coverage.stream_gaps == 1
        assert result.coverage.stream_missing_bytes == 19
        assert any("gap" in reason for reason in result.coverage.reasons)
        # An analyst must not read this as "clean".
        assert "partial" in result.summary.lower()

    def test_role_still_resolved_from_the_truncated_header(self, truncated_hello_pcap):
        result = run_analysis(truncated_hello_pcap)
        session = result.sessions[0]
        assert session.client_side == "src"
        assert session.role_basis == "tls_client_hello"


class TestOrderingAndTimeBounds:
    def test_reversed_file_order_reports_positive_span_and_anomaly(
            self, reversed_order_pcap):
        for eager in (False, True):
            sessions = _sessions_from(reversed_order_pcap, eager)
            session = sessions[0]
            assert session.duration == pytest.approx(0.001, abs=1e-9)
            assert session.duration > 0
            assert session.start_time == pytest.approx(1.0)
            assert session.end_time == pytest.approx(1.001)
            assert session.ordering_anomalies == 1
            assert session.negative_iat_count == 1

    def test_capture_time_bounds_are_min_and_max(self, reversed_order_pcap):
        result = run_analysis(reversed_order_pcap)
        capture = result.run.capture
        assert capture["first_timestamp"] == pytest.approx(1.0)
        assert capture["last_timestamp"] == pytest.approx(1.001)
        assert capture["ordering_anomalies"] == 1
        assert capture["duration_seconds"] == pytest.approx(0.001)

    def test_ipv6_span_is_1440_5_seconds_on_both_paths(self, ipv6_beacon_pcap):
        for eager in (False, True):
            sessions = _sessions_from(ipv6_beacon_pcap, eager)
            assert len(sessions) == 1
            assert sessions[0].start_time == pytest.approx(0.0)
            assert sessions[0].end_time == pytest.approx(1440.5)
            assert sessions[0].duration == pytest.approx(1440.5)


class TestEpochZero:
    def test_zero_timestamp_is_not_an_uninitialised_marker(self):
        """Epoch second 0 is a valid timestamp, not "no start time yet"."""
        from engine.parser.pcap_loader import PacketRecord

        def pkt(ts, seq, payload=b"x"):
            return PacketRecord(
                index=0, timestamp=ts, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=40000, dst_port=80, protocol_l4="TCP",
                raw_payload=payload,
                metadata={"tcp_flags": 0x18, "tcp_seq": seq, "tcp_ack": 1},
            )

        acc = SessionAccumulator()
        acc.feed(pkt(0.0, 1))
        acc.feed(pkt(2.5, 2))
        session = acc.build()[0]
        assert session.start_time == 0.0
        assert session.duration == pytest.approx(2.5)


class TestServerFirstCapture:
    def test_visible_server_hello_is_identified_without_inventing_a_client(self, server_first_pcap):
        result = run_analysis(server_first_pcap)
        assert result.coverage.frames_read == 5
        assert len(result.sessions) == 1

        session = result.sessions[0]
        # Recording began on the server side (10.9.0.2:443).
        assert session.src_ip == "10.9.0.2"
        assert session.src_port == 443
        assert session.client_side == "dst"
        assert session.role_basis == "tls_server_hello"

        assert len(result.tls_fps) == 1
        fp = result.tls_fps[0]
        assert fp.is_server_hello is True
        assert fp.is_client_hello is False
        assert fp.source_ip == "10.9.0.2"
        assert fp.ja4s  # a real ServerHello fingerprint

        # No client handshake may be reported for a capture that has none.
        assert not any(f.is_client_hello for f in result.tls_fps)


class TestUnsupportedFraming:
    def test_unsupported_link_type_is_a_coverage_finding(self, tmp_path):
        """Read every frame, decode none: the result must say so."""
        import struct

        p = tmp_path / "ppp.pcap"
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 9)
        frames = b"".join(
            struct.pack("<IIII", ts, 0, 40, 40) + b"\x00" * 40 for ts in (1, 2)
        )
        p.write_bytes(header + frames)

        result = run_analysis(str(p))
        assert result.coverage.status == "unsupported_decode"
        assert result.coverage.frames_read == 2
        assert result.coverage.frames_decoded == 0
        assert result.findings == []
        out = result.to_output()
        assert out["threats"] == []
        assert "not mean the capture was clean" in out["summary"]
        assert result.run.capture["parser_used"] in ("dpkt", "scapy")
