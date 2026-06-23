"""TCP session reconstruction - group packets by 5-tuple, reassemble streams."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field

from engine.parser.pcap_loader import PacketRecord

logger = logging.getLogger(__name__)


@dataclass
class TCPSession:
    """A reconstructed TCP session (5-tuple)."""
    session_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    start_time: float = 0.0
    end_time: float = 0.0
    duration: float = 0.0
    src_to_dst_bytes: int = 0
    dst_to_src_bytes: int = 0
    packet_count: int = 0
    src_packets: int = 0
    dst_packets: int = 0
    state: str = "ACTIVE"  # ACTIVE, CLOSED, TIMEOUT, RST
    protocol_l7: str = ""
    client_payload: bytes = b""  # src->dst reassembled (head-capped)
    server_payload: bytes = b""  # dst->src reassembled (head-capped)
    # Total bytes seen in each direction (counts bytes even when the stored
    # payload is head-capped). Used for volume scoring on huge transfers so
    # capping the stored buffer does not erase the volume signal. (Phase 2.3)
    client_payload_total_bytes: int = 0
    server_payload_total_bytes: int = 0
    inter_arrival_times: list[float] = field(default_factory=list)
    flags_seen: set[int] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "src_to_dst_bytes": self.src_to_dst_bytes,
            "dst_to_src_bytes": self.dst_to_src_bytes,
            "packet_count": self.packet_count,
            "state": self.state,
            "protocol_l7": self.protocol_l7,
            "client_payload_size": len(self.client_payload),
            "server_payload_size": len(self.server_payload),
            "client_payload_total_bytes": self.client_payload_total_bytes,
            "server_payload_total_bytes": self.server_payload_total_bytes,
            "avg_iat": sum(self.inter_arrival_times) / len(self.inter_arrival_times) if self.inter_arrival_times else 0,
            "iat_count": len(self.inter_arrival_times),
        }


def _make_session_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
    """Create canonical session key - always sort so smaller IP:port comes first."""
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"


def _is_syn_only(flags: int) -> bool:
    """Check if this is a SYN-only packet (connection initiation)."""
    return bool((flags & 0x02) and not (flags & 0x10))  # SYN set, ACK not set


def _is_fin(flags: int) -> bool:
    return bool(flags & 0x01)


def _is_rst(flags: int) -> bool:
    return bool(flags & 0x04)


def _reassemble_direction(segments: list[tuple[int, bytes]], cap: int) -> tuple[bytes, int]:
    """Reassemble one direction's payload, sequence-ordered, head-capped.

    `segments` is a list of (tcp_seq, payload) tuples. Sorts by seq so a
    ClientHello split across TCP segments is stitched back together, skips
    retransmits (overlap with the previously appended range), and head-caps
    the stored buffer at `cap` bytes while still counting every byte toward
    the returned total. (production-plan Phase 2.4 / 2.3)
    """
    if not segments:
        return b"", 0
    segments = sorted(segments, key=lambda s: s[0])
    out = bytearray()
    total = 0
    last_end: int | None = None
    for seq, data in segments:
        if not data:
            continue
        total += len(data)
        if len(out) >= cap:
            continue  # buffer already capped; still count bytes toward total
        # Skip retransmitted / overlapping bytes already covered.
        if last_end is not None and seq < last_end:
            overlap = last_end - seq
            if overlap >= len(data):
                continue  # fully retransmitted segment
            data = data[overlap:]
        out.extend(data)
        last_end = (last_end if last_end is not None else seq) + len(data)
        if len(out) > cap:
            del out[cap:]  # head-cap
    return bytes(out), total


def reconstruct_sessions(packets: list[PacketRecord], session_timeout: float = 300.0,
                         max_payload_bytes: int = 16 * 1024,
                         max_sessions: int = 20_000) -> list[TCPSession]:
    """Reconstruct TCP sessions from packet records.

    Groups packets by canonical 5-tuple, reassembles each direction's payload
    in TCP-sequence order (so split handshakes stitch back together),
    head-caps the stored payload at `max_payload_bytes` per direction (with a
    total-bytes counter preserved for volume scoring), and caps the number of
    sessions at `max_sessions` (a guard against a pathologically fan-out
    capture exhausting memory). Tracks session state and timing metadata.

    Args:
        packets: List of PacketRecord objects from pcap_loader.
        session_timeout: Seconds after which an idle session is marked TIMEOUT.
        max_payload_bytes: Per-direction stored-payload head cap.
        max_sessions: Hard cap on the number of sessions returned.

    Returns:
        List of reconstructed TCPSession objects (at most `max_sessions`).
    """
    # Group TCP packets by session key
    session_packets: dict[str, list[PacketRecord]] = defaultdict(list)
    session_direction: dict[str, tuple[str, int, str, int]] = {}

    for pkt in packets:
        if pkt.protocol_l4 != "TCP" or not pkt.src_ip:
            continue

        key = _make_session_key(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)

        # Store original direction for first packet (client -> server)
        if key not in session_direction:
            session_direction[key] = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)

        session_packets[key].append(pkt)

    if len(session_packets) > max_sessions:
        logger.warning(
            f"Session fan-out ({len(session_packets)}) exceeds cap ({max_sessions}); "
            f"only the first {max_sessions} sessions will be returned. "
            f"Raise max_sessions or slice the capture."
        )
        # Deterministic truncation: keep the sessions with the most packets, which
        # are the ones most likely to matter for beacon/forensic analysis.
        keys_by_size = sorted(session_packets, key=lambda k: len(session_packets[k]), reverse=True)
        keep = set(keys_by_size[:max_sessions])
        session_packets = {k: v for k, v in session_packets.items() if k in keep}

    # Reconstruct each session
    sessions: list[TCPSession] = []

    for key, pkts in session_packets.items():
        pkts.sort(key=lambda p: p.timestamp)
        orig = session_direction[key]

        session = TCPSession(
            session_id=key,
            src_ip=orig[0],
            src_port=orig[1],
            dst_ip=orig[2],
            dst_port=orig[3],
            start_time=pkts[0].timestamp,
            end_time=pkts[-1].timestamp,
        )

        # Timing / metadata pass (timestamp-ordered) + collect per-direction
        # (seq, payload) segments for the sequence-ordered reassembly pass.
        last_time: float | None = None
        client_segments: list[tuple[int, bytes]] = []
        server_segments: list[tuple[int, bytes]] = []

        for pkt in pkts:
            session.packet_count += 1
            session.end_time = pkt.timestamp

            is_client_to_server = (pkt.src_ip == session.src_ip and pkt.src_port == session.src_port)

            if is_client_to_server:
                session.src_packets += 1
                session.src_to_dst_bytes += len(pkt.raw_payload)
                if pkt.raw_payload:
                    client_segments.append((pkt.metadata.get("tcp_seq", 0), pkt.raw_payload))
            else:
                session.dst_packets += 1
                session.dst_to_src_bytes += len(pkt.raw_payload)
                if pkt.raw_payload:
                    server_segments.append((pkt.metadata.get("tcp_seq", 0), pkt.raw_payload))

            # Track inter-arrival times
            if last_time is not None:
                iat = pkt.timestamp - last_time
                if iat > 0:
                    session.inter_arrival_times.append(iat)
            last_time = pkt.timestamp

            # Track TCP flags
            flags = pkt.metadata.get("tcp_flags", 0)
            if flags:
                session.flags_seen.add(flags)

                if _is_rst(flags):
                    session.state = "RST"
                elif _is_fin(flags):
                    session.state = "CLOSED"

            # Pick up L7 protocol from packet records
            if pkt.protocol_l7 and not session.protocol_l7:
                session.protocol_l7 = pkt.protocol_l7

        # Sequence-ordered reassembly with head-cap + total-bytes counter.
        # (Phase 2.4 - was timestamp-ordered concatenation that corrupts stream
        # content and hides split-TLS handshakes from the fingerprinter.)
        session.client_payload, session.client_payload_total_bytes = _reassemble_direction(
            client_segments, max_payload_bytes
        )
        session.server_payload, session.server_payload_total_bytes = _reassemble_direction(
            server_segments, max_payload_bytes
        )
        session.duration = session.end_time - session.start_time

        # Check for timeout
        if session.state == "ACTIVE" and session.duration > session_timeout:
            session.state = "TIMEOUT"

        sessions.append(session)

    logger.info(f"Reconstructed {len(sessions)} TCP sessions from {len(packets)} packets")
    return sessions


# ─── Streaming / memory-bounded accumulation (Phase 2.3) ──────────────────────
#
# SessionAccumulator is the incremental counterpart to reconstruct_sessions:
# packets are fed one at a time as they are parsed (see iter_packet_records),
# and per-session state is bounded so a huge capture does not OOM the process.
# Each direction stores payload segments only up to `max_payload_bytes`; once
# that head cap is reached, further payloads are counted toward total_bytes
# (for volume scoring) but not stored. The number of sessions is capped at
# `max_sessions`. Timing/IAT/flags are tracked as packets arrive; this assumes
# the capture is timestamp-ordered (true for real captures and our fixtures),
# which is the standard property streaming parsers rely on.


class _DirAcc:
    """One direction of a session under construction (bounded payload store)."""
    __slots__ = ("segments", "stored_bytes", "total_bytes", "packet_count", "capped")

    def __init__(self) -> None:
        self.segments: list[tuple[int, bytes]] = []
        self.stored_bytes = 0
        self.total_bytes = 0
        self.packet_count = 0
        self.capped = False

    def feed(self, seq: int, payload: bytes, cap: int) -> None:
        self.packet_count += 1
        if not payload:
            return
        self.total_bytes += len(payload)
        if self.capped:
            return  # already have enough head bytes; just count the volume
        self.segments.append((seq, payload))
        self.stored_bytes += len(payload)
        if self.stored_bytes >= cap:
            self.capped = True


class _SessionState:
    """Per-session accumulator state (fed incrementally)."""
    __slots__ = (
        "direction", "client", "server", "packet_count", "src_packets",
        "dst_packets", "start_time", "end_time", "last_time",
        "inter_arrival_times", "flags_seen", "state", "protocol_l7",
    )

    def __init__(self, direction: tuple[str, int, str, int]) -> None:
        self.direction = direction
        self.client = _DirAcc()
        self.server = _DirAcc()
        self.packet_count = 0
        self.src_packets = 0
        self.dst_packets = 0
        self.start_time = 0.0
        self.end_time = 0.0
        self.last_time: float | None = None
        self.inter_arrival_times: list[float] = []
        self.flags_seen: set[int] = set()
        self.state = "ACTIVE"
        self.protocol_l7 = ""

    def feed(self, pkt: PacketRecord, cap: int) -> None:
        self.packet_count += 1
        if self.start_time == 0.0:
            self.start_time = pkt.timestamp
        self.end_time = pkt.timestamp

        src_ip, src_port, dst_ip, dst_port = self.direction
        is_client_to_server = (pkt.src_ip == src_ip and pkt.src_port == src_port)

        if is_client_to_server:
            self.src_packets += 1
            if pkt.raw_payload:
                self.client.feed(pkt.metadata.get("tcp_seq", 0), pkt.raw_payload, cap)
        else:
            self.dst_packets += 1
            if pkt.raw_payload:
                self.server.feed(pkt.metadata.get("tcp_seq", 0), pkt.raw_payload, cap)

        if self.last_time is not None:
            iat = pkt.timestamp - self.last_time
            if iat > 0:
                self.inter_arrival_times.append(iat)
        self.last_time = pkt.timestamp

        flags = pkt.metadata.get("tcp_flags", 0)
        if flags:
            self.flags_seen.add(flags)
            if _is_rst(flags):
                self.state = "RST"
            elif _is_fin(flags):
                self.state = "CLOSED"

        if pkt.protocol_l7 and not self.protocol_l7:
            self.protocol_l7 = pkt.protocol_l7


class SessionAccumulator:
    """Incrementally build bounded TCPSessions from a stream of packets.

    Use instead of :func:`reconstruct_sessions` when the capture is streamed
    (``iter_packet_records``) and holding the full packet list in memory is
    undesirable. (production-plan Phase 2.3)
    """

    def __init__(self, session_timeout: float = 300.0,
                 max_payload_bytes: int = 16 * 1024,
                 max_sessions: int = 20_000) -> None:
        self.session_timeout = session_timeout
        self.max_payload_bytes = max_payload_bytes
        self.max_sessions = max_sessions
        self._states: dict[str, _SessionState] = {}
        self._warned_cap = False

    def feed(self, pkt: PacketRecord) -> None:
        if pkt.protocol_l4 != "TCP" or not pkt.src_ip:
            return
        key = _make_session_key(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
        st = self._states.get(key)
        if st is None:
            if len(self._states) >= self.max_sessions:
                if not self._warned_cap:
                    logger.warning(
                        f"Session fan-out exceeds cap ({self.max_sessions}); "
                        f"further sessions are dropped. Raise max_sessions or "
                        f"slice the capture."
                    )
                    self._warned_cap = True
                return
            st = _SessionState((pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port))
            self._states[key] = st
        st.feed(pkt, self.max_payload_bytes)

    def build(self) -> list[TCPSession]:
        """Finalize and return the accumulated sessions (reassembled payloads)."""
        sessions: list[TCPSession] = []
        for key, st in self._states.items():
            src_ip, src_port, dst_ip, dst_port = st.direction
            session = TCPSession(
                session_id=key,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                start_time=st.start_time,
                end_time=st.end_time,
                packet_count=st.packet_count,
                src_packets=st.src_packets,
                dst_packets=st.dst_packets,
                state=st.state,
                protocol_l7=st.protocol_l7,
                flags_seen=set(st.flags_seen),
                inter_arrival_times=list(st.inter_arrival_times),
            )
            session.client_payload, _client_reassembled = _reassemble_direction(
                st.client.segments, self.max_payload_bytes
            )
            session.server_payload, _server_reassembled = _reassemble_direction(
                st.server.segments, self.max_payload_bytes
            )
            # Total-bytes counters come from the per-direction accumulators so
            # bytes dropped after the head cap still count (volume scoring on
            # huge transfers survives capping). The reassembled-from-stored
            # totals are intentionally not used here - they would reflect only
            # the capped head, not the full transfer.
            session.client_payload_total_bytes = st.client.total_bytes
            session.server_payload_total_bytes = st.server.total_bytes
            session.src_to_dst_bytes = st.client.total_bytes
            session.dst_to_src_bytes = st.server.total_bytes
            session.duration = session.end_time - session.start_time
            if session.state == "ACTIVE" and session.duration > self.session_timeout:
                session.state = "TIMEOUT"
            sessions.append(session)
        logger.info(f"Reconstructed {len(sessions)} TCP sessions (streaming accumulator)")
        return sessions
