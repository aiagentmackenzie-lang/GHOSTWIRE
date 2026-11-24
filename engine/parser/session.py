"""TCP session reconstruction - group packets by 5-tuple, reassemble streams.

The reassembly contract is deliberately explicit, because a finding derived
from a reconstructed stream has to say which bytes supported it:

* ``ranges``   - merged, sequence-number intervals the capture actually provided
* ``gaps``     - intervals inside the observed sequence span with no captured
                 bytes (a capture gap, not a TCP retransmission)
* ``payload``  - the contiguous prefix only. Bytes after a hole are *not*
                 concatenated onto it: doing so silently joins unrelated TLS
                 records and hides the loss from every downstream detector.
* ``captured_payload_bytes`` vs ``distinct_stream_bytes`` - the first counts
                 every transmitted payload byte (retransmits included); the
                 second counts each sequence byte once.
* ``client_side`` / ``role_basis`` - which endpoint was the client, and the
                 evidence for that claim. When recording begins mid-stream on
                 the server side, the first sender is the *server*; the role is
                 resolved from SYN / TLS / HTTP evidence instead of packet order.
* ``start_time``/``end_time`` - the observed time bounds (min/max), never the
                 first/last packet in file order. A reversed capture therefore
                 reports a positive span plus an ordering anomaly.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field

from engine.parser.pcap_loader import PacketRecord

logger = logging.getLogger(__name__)

# Enough protocol sniffing to decide roles; not a decoder.
_TLS_HANDSHAKE = 0x16
_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ",
                 b"OPTIONS ", b"TRACE ", b"CONNECT ")


@dataclass
class SequenceRange:
    """A contiguous captured sequence interval."""
    start: int          # inclusive TCP sequence number
    end: int            # exclusive
    frames: list[int] = field(default_factory=list)  # one-based frame numbers

    @property
    def length(self) -> int:
        return max(0, self.end - self.start)

    def to_dict(self) -> dict:
        return {
            "start": self.start,
            "end": self.end,
            "length": self.length,
            "frames": list(self.frames),
        }


@dataclass
class StreamGap:
    """A sequence interval inside the observed span with no captured bytes."""
    start: int
    end: int

    @property
    def missing_bytes(self) -> int:
        return max(0, self.end - self.start)

    def to_dict(self) -> dict:
        return {
            "start": self.start,
            "end": self.end,
            "missing_bytes": self.missing_bytes,
        }


@dataclass
class Reassembly:
    """Result of assembling one direction of one conversation.

    ``samples`` keeps the capture timestamp of each stored segment start, so a
    stream-derived observation can report *when* its bytes were captured
    instead of leaving the time blank. It is bounded by the stored payload (the
    head cap), not by the capture size.
    """
    payload: bytes = b""
    captured_payload_bytes: int = 0
    distinct_stream_bytes: int = 0
    ranges: list[SequenceRange] = field(default_factory=list)
    gaps: list[StreamGap] = field(default_factory=list)
    capped: bool = False
    samples: list[dict] = field(default_factory=list)  # [{"offset", "timestamp"}]

    def timestamp_at(self, offset: int) -> float | None:
        """Capture timestamp of the segment that supplied byte ``offset``."""
        best: float | None = None
        for sample in self.samples:
            if sample["offset"] <= offset:
                best = sample["timestamp"]
            else:
                break
        return best

    @property
    def discontinuity(self) -> bool:
        return bool(self.gaps)

    @property
    def missing_bytes(self) -> int:
        return sum(g.missing_bytes for g in self.gaps)

    def to_dict(self) -> dict:
        return {
            "stored_bytes": len(self.payload),
            "captured_payload_bytes": self.captured_payload_bytes,
            "distinct_stream_bytes": self.distinct_stream_bytes,
            "missing_bytes": self.missing_bytes,
            "discontinuity": self.discontinuity,
            "capped": self.capped,
            "ranges": [r.to_dict() for r in self.ranges],
            "gaps": [g.to_dict() for g in self.gaps],
            "first_timestamp": (self.samples[0]["timestamp"] if self.samples else None),
            "last_timestamp": (self.samples[-1]["timestamp"] if self.samples else None),
        }


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
    client_payload: bytes = b""  # src->dst reassembled head (contiguous prefix)
    server_payload: bytes = b""  # dst->src reassembled head (contiguous prefix)
    # Total bytes seen in each direction (counts bytes even when the stored
    # payload is head-capped). Used for volume scoring on huge transfers so
    # capping the stored buffer does not erase the volume signal. (Phase 2.3)
    client_payload_total_bytes: int = 0
    server_payload_total_bytes: int = 0
    inter_arrival_times: list[float] = field(default_factory=list)
    flags_seen: set[int] = field(default_factory=set)
    # ── Role and reconstruction evidence (Wave 1 slice 3) ──────────────────
    client_side: str = "unknown"      # "src" | "dst" | "unknown"
    role_basis: str = "unresolved"
    src_reassembly: Reassembly = field(default_factory=Reassembly)
    dst_reassembly: Reassembly = field(default_factory=Reassembly)
    ordering_anomalies: int = 0
    negative_iat_count: int = 0

    # ── Role helpers ───────────────────────────────────────────────────────
    @property
    def client_is_src(self) -> bool:
        """True when the client endpoint is the first-packet sender."""
        return self.client_side == "src"

    def client_stream(self) -> bytes:
        """Reassembled bytes sent BY the client (empty when role is unknown)."""
        if self.client_side == "src":
            return self.client_payload
        if self.client_side == "dst":
            return self.server_payload
        return b""

    def server_stream(self) -> bytes:
        """Reassembled bytes sent BY the server (empty when role is unknown)."""
        if self.client_side == "src":
            return self.server_payload
        if self.client_side == "dst":
            return self.client_payload
        return b""

    def client_reassembly(self) -> Reassembly | None:
        if self.client_side == "src":
            return self.src_reassembly
        if self.client_side == "dst":
            return self.dst_reassembly
        return None

    def server_reassembly(self) -> Reassembly | None:
        if self.client_side == "src":
            return self.dst_reassembly
        if self.client_side == "dst":
            return self.src_reassembly
        return None

    def client_endpoint(self) -> tuple[str, int]:
        if self.client_side == "dst":
            return (self.dst_ip, self.dst_port)
        return (self.src_ip, self.src_port)

    def server_endpoint(self) -> tuple[str, int]:
        if self.client_side == "dst":
            return (self.src_ip, self.src_port)
        return (self.dst_ip, self.dst_port)

    def endpoint_dict(self, side: str) -> dict:
        """Typed endpoint for ``side`` ("src"/"dst") in wire direction."""
        if side == "src":
            ip, port = self.src_ip, self.src_port
        else:
            ip, port = self.dst_ip, self.dst_port
        return {
            "ip": ip,
            "port": port,
            "role": ("client" if self.client_side == side
                     else "server" if self.client_side in ("src", "dst") else "unknown"),
            "address_family": "ipv6" if ":" in (ip or "") else "ipv4",
        }

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": round(self.duration, 6),
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
            "client_side": self.client_side,
            "role_basis": self.role_basis,
            "endpoints": {
                "src": self.endpoint_dict("src"),
                "dst": self.endpoint_dict("dst"),
            },
            "streams": {
                "src_to_dst": self.src_reassembly.to_dict(),
                "dst_to_src": self.dst_reassembly.to_dict(),
            },
            "ordering_anomalies": self.ordering_anomalies,
            "negative_iat_count": self.negative_iat_count,
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


# ─── Reassembly ─────────────────────────────────────────────────────────────

_Segment = tuple


def _segment_parts(seg: _Segment) -> tuple[int, bytes, int | None, float | None]:
    """Normalise a segment tuple to (seq, payload, frame_number, timestamp)."""
    if len(seg) >= 4:
        return (int(seg[0]), bytes(seg[1]),
                int(seg[2]) if seg[2] is not None else None,
                float(seg[3]) if seg[3] is not None else None)
    if len(seg) >= 3:
        return (int(seg[0]), bytes(seg[1]),
                int(seg[2]) if seg[2] is not None else None, None)
    return int(seg[0]), bytes(seg[1]), None, None


def _merge_ranges(segments: list[_Segment]) -> tuple[list[SequenceRange], int, int]:
    """Merge captured segments into disjoint sequence ranges.

    Returns (ranges, captured_bytes, distinct_bytes). ``captured_bytes`` counts
    every transmitted payload byte (retransmits included); ``distinct_bytes``
    counts each sequence byte once.
    """
    parsed: list[tuple[int, int, int | None]] = []
    captured = 0
    for seg in segments:
        seq, data, frame, _ts = _segment_parts(seg)
        if not data:
            continue
        captured += len(data)
        parsed.append((seq, seq + len(data), frame))

    parsed.sort(key=lambda x: (x[0], x[1]))
    merged: list[SequenceRange] = []
    distinct = 0
    for start, end, frame in parsed:
        if merged and start <= merged[-1].end:
            last = merged[-1]
            if end > last.end:
                distinct += end - last.end
                last.end = end
            if frame is not None and frame not in last.frames:
                last.frames.append(frame)
            continue
        merged.append(SequenceRange(start=start, end=end,
                                    frames=[frame] if frame is not None else []))
        distinct += end - start
    return merged, captured, distinct


def _uncovered(covered: list[tuple[int, int]], start: int, end: int) -> list[tuple[int, int]]:
    """Sub-ranges of [start, end) not present in ``covered`` (sorted, merged)."""
    holes: list[tuple[int, int]] = []
    cursor = start
    for c_start, c_end in covered:
        if c_end <= cursor:
            continue
        if c_start >= end:
            break
        if c_start > cursor:
            holes.append((cursor, min(c_start, end)))
        cursor = max(cursor, c_end)
        if cursor >= end:
            break
    if cursor < end:
        holes.append((cursor, end))
    return holes


def _merge_covered(covered: list[tuple[int, int]], start: int, end: int) -> list[tuple[int, int]]:
    """Insert [start, end) into a sorted, merged interval list."""
    merged: list[tuple[int, int]] = []
    placed = False
    for c_start, c_end in covered:
        if c_end < start:
            merged.append((c_start, c_end))
        elif c_start > end:
            if not placed:
                merged.append((start, end))
                placed = True
            merged.append((c_start, c_end))
        else:
            start = min(start, c_start)
            end = max(end, c_end)
    if not placed:
        merged.append((start, end))
    return merged


def _reassemble_direction_detail(segments: list[_Segment], cap: int,
                                 captured_total: int | None = None) -> Reassembly:
    """Sequence-ordered reassembly with explicit ranges, gaps and byte counts.

    The stored ``payload`` is the **contiguous prefix only** (the run starting
    at the lowest sequence number). A hole in the capture ends the stored run:
    bytes captured after the hole are recorded in ``ranges`` but are not
    concatenated onto the prefix, because joining them would fabricate a
    stream the capture never showed.
    """
    if not segments:
        return Reassembly()
    ranges, captured, distinct = _merge_ranges(segments)

    gaps: list[StreamGap] = []
    for prev, nxt in zip(ranges, ranges[1:], strict=False):
        if nxt.start > prev.end:
            gaps.append(StreamGap(start=prev.end, end=nxt.start))

    # Bytes for the contiguous prefix, head-capped.
    #
    # Build the prefix by sequence position, not by segment arrival order: a
    # retransmitted first segment must not be appended twice, which is exactly
    # how 30 duplicated bytes used to turn a 77-byte handshake into 107 bytes of
    # concatenated garbage. The first transmission of each sequence byte wins.
    base = ranges[0].start
    prefix_len = ranges[0].length if ranges else 0
    keep = min(prefix_len, cap)
    out = bytearray(keep)
    covered: list[tuple[int, int]] = []  # sorted, merged, relative to `base`
    samples: list[dict] = []
    for seg in segments:
        if len(covered) == 1 and covered[0] == (0, keep):
            break
        seq, data, _frame, ts = _segment_parts(seg)
        if not data:
            continue
        start = max(seq, base)
        end = min(seq + len(data), base + keep)
        if end <= start:
            continue
        for hole_start, hole_end in _uncovered(covered, start - base, end - base):
            src = (base + hole_start) - seq
            out[hole_start:hole_end] = data[src:src + (hole_end - hole_start)]
        covered = _merge_covered(covered, start - base, end - base)
        if ts is not None:
            samples.append({"offset": start - base, "timestamp": ts})

    return Reassembly(
        payload=bytes(out),
        captured_payload_bytes=captured if captured_total is None else captured_total,
        distinct_stream_bytes=distinct,
        ranges=ranges,
        gaps=gaps,
        capped=keep < prefix_len,
        samples=samples,
    )


def _reassemble_direction(segments: list[tuple[int, bytes]], cap: int) -> tuple[bytes, int]:
    """Reassemble one direction's payload, sequence-ordered, head-capped.

    Backwards-compatible wrapper returning ``(contiguous_prefix, captured)``.
    Call :func:`_reassemble_direction_detail` when ranges/gaps matter.

    Sorts by seq so a ClientHello split across TCP segments is stitched back
    together, skips retransmits, and head-caps the stored buffer at ``cap``
    bytes while still counting every transmitted byte toward the total.
    (production-plan Phase 2.4 / 2.3)
    """
    detail = _reassemble_direction_detail(segments, cap)
    return detail.payload, detail.captured_payload_bytes


# ─── Role resolution ────────────────────────────────────────────────────────

def _tls_handshake_type(payload: bytes) -> int | None:
    """Handshake type of a stream that begins with a TLS handshake record.

    Only the record header and the handshake type byte are needed to know
    *who* initiated the handshake, so an incomplete record (a capture that
    starts mid-record) still resolves the role. Completeness is enforced
    separately by the fingerprinter.
    """
    if len(payload) < 6 or payload[0] != _TLS_HANDSHAKE:
        return None
    return payload[5]


def _looks_http_request(payload: bytes) -> bool:
    return any(payload.startswith(m) for m in _HTTP_METHODS)


def _resolve_roles(syn_side: str | None, src_payload: bytes, dst_payload: bytes,
                   src_hello: int | None = None,
                   dst_hello: int | None = None) -> tuple[str, str]:
    """Resolve which side is the client from protocol evidence.

    Returns ``(client_side, basis)`` where client_side is "src", "dst" or
    "unknown". Order of precedence: an observed TCP SYN (connection
    initiation), a ClientHello, a visible ServerHello (which makes the *other*
    side the client), an HTTP request line. Anything else stays unknown — the
    observed wire direction is still recorded, but a client role is not
    invented from packet order or port numbers.
    """
    if syn_side in ("src", "dst"):
        return syn_side, "tcp_syn"

    if src_hello is None:
        src_hello = _tls_handshake_type(src_payload)
    if dst_hello is None:
        dst_hello = _tls_handshake_type(dst_payload)

    if src_hello == 0x01:
        return "src", "tls_client_hello"
    if dst_hello == 0x01:
        return "dst", "tls_client_hello"
    if src_hello == 0x02:
        return "dst", "tls_server_hello"
    if dst_hello == 0x02:
        return "src", "tls_server_hello"
    if _looks_http_request(src_payload):
        return "src", "http_request"
    if _looks_http_request(dst_payload):
        return "dst", "http_request"
    return "unknown", "unresolved (no SYN, TLS or HTTP initiation observed)"


def reconstruct_sessions(packets: list[PacketRecord], session_timeout: float = 300.0,
                         max_payload_bytes: int = 16 * 1024,
                         max_sessions: int = 20_000) -> list[TCPSession]:
    """Reconstruct TCP sessions from packet records.

    Groups packets by canonical 5-tuple, reassembles each direction's payload
    in TCP-sequence order (so split handshakes stitch back together), records
    the sequence ranges and gaps behind every stream, head-caps the stored
    payload at `max_payload_bytes` per direction (with a total-bytes counter
    preserved for volume scoring), resolves which endpoint is the client from
    protocol evidence, and caps the number of sessions at `max_sessions`.

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
        orig = session_direction[key]

        session = TCPSession(
            session_id=key,
            src_ip=orig[0],
            src_port=orig[1],
            dst_ip=orig[2],
            dst_port=orig[3],
        )

        # Timing / metadata pass (timestamp-ordered) + collect per-direction
        # (seq, payload, frame) segments for the sequence-ordered pass.
        last_time: float | None = None
        client_segments: list[tuple] = []
        server_segments: list[tuple] = []
        syn_side: str | None = None

        for pkt in pkts:
            session.packet_count += 1

            is_client_to_server = (pkt.src_ip == session.src_ip and pkt.src_port == session.src_port)

            if is_client_to_server:
                session.src_packets += 1
                session.src_to_dst_bytes += len(pkt.raw_payload)
                if pkt.raw_payload:
                    client_segments.append(
                        (pkt.metadata.get("tcp_seq", 0), pkt.raw_payload,
                         pkt.frame_number, pkt.timestamp)
                    )
            else:
                session.dst_packets += 1
                session.dst_to_src_bytes += len(pkt.raw_payload)
                if pkt.raw_payload:
                    server_segments.append(
                        (pkt.metadata.get("tcp_seq", 0), pkt.raw_payload,
                         pkt.frame_number, pkt.timestamp)
                    )

            # Track inter-arrival times
            if last_time is not None:
                iat = pkt.timestamp - last_time
                if iat > 0:
                    session.inter_arrival_times.append(iat)
                elif iat < 0:
                    session.negative_iat_count += 1
                    session.ordering_anomalies += 1
            last_time = pkt.timestamp

            # Track TCP flags
            flags = pkt.metadata.get("tcp_flags", 0)
            if flags:
                session.flags_seen.add(flags)

                if _is_rst(flags):
                    session.state = "RST"
                elif _is_fin(flags):
                    session.state = "CLOSED"
                if _is_syn_only(flags) and syn_side is None:
                    syn_side = "src" if is_client_to_server else "dst"

            # Pick up L7 protocol from packet records
            if pkt.protocol_l7 and not session.protocol_l7:
                session.protocol_l7 = pkt.protocol_l7

        session.src_reassembly = _reassemble_direction_detail(client_segments, max_payload_bytes)
        session.dst_reassembly = _reassemble_direction_detail(server_segments, max_payload_bytes)
        session.client_payload = session.src_reassembly.payload
        session.server_payload = session.dst_reassembly.payload
        session.client_payload_total_bytes = session.src_reassembly.captured_payload_bytes
        session.server_payload_total_bytes = session.dst_reassembly.captured_payload_bytes

        # Observed time bounds (min/max), never first/last in file order.
        stamps = [p.timestamp for p in pkts]
        session.start_time = min(stamps)
        session.end_time = max(stamps)
        session.duration = session.end_time - session.start_time

        session.client_side, session.role_basis = _resolve_roles(
            syn_side, session.client_payload, session.server_payload
        )

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
# `max_sessions`. Timing/IAT/flags are tracked as packets arrive; a capture
# whose file order disagrees with its timestamps is counted as an ordering
# anomaly and duration is taken from the observed time bounds, so a reversed
# file still reports a positive span.


class _DirAcc:
    """One direction of a session under construction (bounded payload store)."""
    __slots__ = ("segments", "stored_bytes", "total_bytes", "packet_count", "capped")

    def __init__(self) -> None:
        self.segments: list[tuple] = []
        self.stored_bytes = 0
        self.total_bytes = 0
        self.packet_count = 0
        self.capped = False

    def feed(self, seq: int, payload: bytes, cap: int, frame: int | None = None,
             timestamp: float | None = None) -> None:
        self.packet_count += 1
        if not payload:
            return
        self.total_bytes += len(payload)
        if self.capped:
            return  # already have enough head bytes; just count the volume
        self.segments.append((seq, payload, frame if frame is not None else -1,
                              timestamp))
        self.stored_bytes += len(payload)
        if self.stored_bytes >= cap:
            self.capped = True


class _SessionState:
    """Per-session accumulator state (fed incrementally)."""
    __slots__ = (
        "direction", "client", "server", "packet_count", "src_packets",
        "dst_packets", "start_time", "end_time", "last_time", "seen_packet",
        "min_time", "max_time", "ordering_anomalies", "negative_iat_count",
        "inter_arrival_times", "flags_seen", "state", "protocol_l7", "syn_side",
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
        self.seen_packet = False
        self.min_time = float("inf")
        self.max_time = float("-inf")
        self.ordering_anomalies = 0
        self.negative_iat_count = 0
        self.inter_arrival_times: list[float] = []
        self.flags_seen: set[int] = set()
        self.state = "ACTIVE"
        self.protocol_l7 = ""
        self.syn_side: str | None = None

    def feed(self, pkt: PacketRecord, cap: int) -> None:
        self.packet_count += 1
        # Epoch zero is a valid timestamp: use an explicit "seen" flag rather
        # than 0.0 as the uninitialised marker.
        if not self.seen_packet:
            self.seen_packet = True
        self.min_time = min(self.min_time, pkt.timestamp)
        self.max_time = max(self.max_time, pkt.timestamp)
        self.start_time = self.min_time
        self.end_time = self.max_time

        src_ip, src_port, _dst_ip, _dst_port = self.direction
        is_client_to_server = (pkt.src_ip == src_ip and pkt.src_port == src_port)

        if is_client_to_server:
            self.src_packets += 1
            if pkt.raw_payload:
                self.client.feed(pkt.metadata.get("tcp_seq", 0), pkt.raw_payload, cap,
                                 pkt.frame_number, pkt.timestamp)
        else:
            self.dst_packets += 1
            if pkt.raw_payload:
                self.server.feed(pkt.metadata.get("tcp_seq", 0), pkt.raw_payload, cap,
                                 pkt.frame_number, pkt.timestamp)

        if self.last_time is not None:
            iat = pkt.timestamp - self.last_time
            if iat > 0:
                self.inter_arrival_times.append(iat)
            elif iat < 0:
                # Timestamps went backwards between file-order neighbours: the
                # stream bytes are still usable, the timing is not.
                self.negative_iat_count += 1
                self.ordering_anomalies += 1
        self.last_time = pkt.timestamp

        flags = pkt.metadata.get("tcp_flags", 0)
        if flags:
            self.flags_seen.add(flags)
            if _is_rst(flags):
                self.state = "RST"
            elif _is_fin(flags):
                self.state = "CLOSED"
            if _is_syn_only(flags) and self.syn_side is None:
                self.syn_side = "src" if is_client_to_server else "dst"

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
        self.sessions_dropped = 0

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
                self.sessions_dropped += 1
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
                ordering_anomalies=st.ordering_anomalies,
                negative_iat_count=st.negative_iat_count,
            )
            session.src_reassembly = _reassemble_direction_detail(
                st.client.segments, self.max_payload_bytes, st.client.total_bytes
            )
            session.dst_reassembly = _reassemble_direction_detail(
                st.server.segments, self.max_payload_bytes, st.server.total_bytes
            )
            session.client_payload = session.src_reassembly.payload
            session.server_payload = session.dst_reassembly.payload
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

            session.client_side, session.role_basis = _resolve_roles(
                st.syn_side,
                session.src_reassembly.payload,
                session.dst_reassembly.payload,
            )

            if session.state == "ACTIVE" and session.duration > self.session_timeout:
                session.state = "TIMEOUT"
            sessions.append(session)
        logger.info(f"Reconstructed {len(sessions)} TCP sessions (streaming accumulator)")
        return sessions
