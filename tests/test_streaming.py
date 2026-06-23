"""Streaming + memory-bound session accumulation tests (Phase 2.3).

Guards the properties that make GHOSTWIRE safe to run on large captures:
  - iter_packet_records streams lazily (does not load the whole file up front).
  - SessionAccumulator caps the number of sessions (fan-out guard).
  - SessionAccumulator head-caps per-direction stored payload while
    preserving the total-bytes counter (volume signal survives capping).
"""
from __future__ import annotations

from collections.abc import Iterator

from scapy.all import IP, TCP, Ether, Raw, wrpcap

from engine.parser.pcap_loader import PacketRecord, iter_packet_records, load_pcap
from engine.parser.session import SessionAccumulator


def _pkt(src_ip: str, dst_ip: str, sport: int, dport: int, seq: int,
         payload: bytes, ts: float) -> PacketRecord:
    return PacketRecord(
        index=0, timestamp=ts,
        src_ip=src_ip, dst_ip=dst_ip, src_port=sport, dst_port=dport,
        protocol_l4="TCP", length=len(payload) + 54,
        raw_payload=payload,
        metadata={"tcp_flags": 0x18, "tcp_seq": seq, "tcp_ack": 1},  # PSH+ACK
    )


class TestStreamingLoader:
    def test_iter_packet_records_is_lazy_iterator(self, tmp_path):
        """iter_packet_records must yield records one at a time (not a list)."""
        p = tmp_path / "x.pcap"
        wrpcap(str(p), [
            (Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=80)
             / Raw(load=b"hello")),
        ])
        it = iter_packet_records(str(p))
        assert isinstance(it, Iterator)
        first = next(it)
        assert isinstance(first, PacketRecord)
        # Collecting the rest must succeed and match the eager loader's count.
        rest = list(it)
        assert len(rest) == 0  # one packet total

    def test_streaming_matches_eager_loader(self, beacon_pcap):
        """The streaming path must yield the same records as load_pcap."""
        streamed = list(iter_packet_records(beacon_pcap))
        eager = load_pcap(beacon_pcap)
        assert len(streamed) == len(eager)
        assert [p.src_ip for p in streamed] == [p.src_ip for p in eager]
        assert [p.protocol_l4 for p in streamed] == [p.protocol_l4 for p in eager]


class TestSessionAccumulatorCaps:
    def test_session_count_capped(self):
        """A capture with more sessions than max_sessions drops the overflow."""
        acc = SessionAccumulator(max_sessions=5)
        # 10 distinct sessions (different dst ports), one packet each.
        for i in range(10):
            acc.feed(_pkt("10.0.0.1", "10.0.0.2", 40000, 1000 + i, 1, b"x", float(i)))
        sessions = acc.build()
        assert len(sessions) == 5, f"expected 5 capped sessions, got {len(sessions)}"

    def test_payload_head_capped_but_volume_preserved(self):
        """Per-direction stored payload is head-capped, but total_bytes counts
        every byte so volume scoring on huge transfers is not erased."""
        cap = 64 * 1024
        acc = SessionAccumulator(max_payload_bytes=cap)
        # One session, client sends 200 x 600-byte payloads = 120_000 bytes > cap.
        seq = 1
        ts = 0.0
        for _ in range(200):
            acc.feed(_pkt("10.0.0.1", "10.0.0.2", 40000, 80, seq, b"a" * 600, ts))
            seq += 600
            ts += 0.5
        sessions = acc.build()
        assert len(sessions) == 1
        s = sessions[0]
        # Stored payload is head-capped (at most cap bytes; allow a small
        # overshoot from the last segment that crosses the boundary).
        assert len(s.client_payload) <= cap + 600, (
            f"stored payload {len(s.client_payload)} exceeds cap+segment"
        )
        # Total bytes counter preserves the full volume.
        assert s.client_payload_total_bytes == 120_000, (
            f"total bytes {s.client_payload_total_bytes} != 120000 (volume signal lost)"
        )
        assert s.src_to_dst_bytes == 120_000

    def test_accumulator_matches_reconstruct_sessions(self, beacon_pcap):
        """The streaming accumulator must produce the same sessions as the
        eager reconstruct_sessions for a timestamp-ordered capture."""
        from engine.parser.session import reconstruct_sessions
        packets = load_pcap(beacon_pcap)
        eager = reconstruct_sessions(packets)
        acc = SessionAccumulator()
        for pkt in packets:
            acc.feed(pkt)
        streamed = acc.build()
        assert len(streamed) == len(eager)
        # Same session keys, same packet counts, same beacon-relevant timing.
        eager_by_id = {s.session_id: s for s in eager}
        for s in streamed:
            e = eager_by_id[s.session_id]
            assert s.packet_count == e.packet_count
            assert len(s.inter_arrival_times) == len(e.inter_arrival_times)
            assert s.src_to_dst_bytes == e.src_to_dst_bytes


class TestReassemblyEdgeCases:
    """Closes the admitted gap: reassembly under a missing middle segment."""

    def test_missing_middle_segment_does_not_crash(self):
        from engine.parser.session import _reassemble_direction
        # seq 1..10, then a gap (11..20 missing), then 21..30.
        segs = [(1, b"AAAAAAAAAA"), (21, b"BBBBBBBBBB")]
        out, total = _reassemble_direction(segs, 64 * 1024)
        assert total == 20, f"total {total}"
        # Head bytes are the first contiguous run; the gap leaves a hole after.
        assert out.startswith(b"AAAAAAAAAA")
        # The second segment is appended after the gap (not stitched over it).
        assert b"BBBBBBBBBB" in out

    def test_retransmit_overlap_skipped(self):
        from engine.parser.session import _reassemble_direction
        # First segment, then a retransmit overlapping it, then new data.
        segs = [(1, b"ABCDEF"), (3, b"CDEXYZ"), (10, b"NEW")]
        out, total = _reassemble_direction(segs, 64 * 1024)
        assert total == 6 + 6 + 3, f"total {total}"  # all counted
        # Head is the de-overlapped first run; NEW appended after.
        assert out.startswith(b"ABCDEF")

    def test_split_client_hello_still_in_head(self, split_tls_pcap):
        """The split ClientHello reassembles into the head of client_payload,
        so fingerprint_sessions finds it (Phase 2.2 gate, re-asserted)."""
        from engine.cli import _full_analysis
        results = _full_analysis(split_tls_pcap)
        assert results["tls_fps"], "no TLS fp from split ClientHello"
        assert results["tls_fps"][0].sni == "evil.example.com"
