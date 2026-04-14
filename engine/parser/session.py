"""TCP session reconstruction — group packets by 5-tuple, reassemble streams."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

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
    client_payload: bytes = b""  # src→dst reassembled
    server_payload: bytes = b""  # dst→src reassembled
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
            "avg_iat": sum(self.inter_arrival_times) / len(self.inter_arrival_times) if self.inter_arrival_times else 0,
            "iat_count": len(self.inter_arrival_times),
        }


def _make_session_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
    """Create canonical session key — always sort so smaller IP:port comes first."""
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"


def _is_syn_only(flags: int) -> bool:
    """Check if this is a SYN-only packet (connection initiation)."""
    return (flags & 0x02) and not (flags & 0x10)  # SYN set, ACK not set


def _is_fin(flags: int) -> bool:
    return bool(flags & 0x01)


def _is_rst(flags: int) -> bool:
    return bool(flags & 0x04)


def reconstruct_sessions(packets: list[PacketRecord], session_timeout: float = 300.0) -> list[TCPSession]:
    """Reconstruct TCP sessions from packet records.

    Groups packets by canonical 5-tuple, reassembles payload streams,
    tracks session state and timing metadata.

    Args:
        packets: List of PacketRecord objects from pcap_loader.
        session_timeout: Seconds after which an idle session is marked TIMEOUT.

    Returns:
        List of reconstructed TCPSession objects.
    """
    # Group TCP packets by session key
    session_packets: dict[str, list[PacketRecord]] = defaultdict(list)
    session_direction: dict[str, tuple[str, int, str, int]] = {}  # key → original (src_ip, src_port, dst_ip, dst_port)

    for pkt in packets:
        if pkt.protocol_l4 != "TCP" or not pkt.src_ip:
            continue

        key = _make_session_key(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)

        # Store original direction for first packet (client → server)
        if key not in session_direction:
            session_direction[key] = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)

        session_packets[key].append(pkt)

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

        # Build payload streams and track timing
        last_time: Optional[float] = None
        client_chunks: list[bytes] = []
        server_chunks: list[bytes] = []

        for pkt in pkts:
            session.packet_count += 1
            session.end_time = pkt.timestamp

            # Determine direction
            is_client_to_server = (pkt.src_ip == session.src_ip and pkt.src_port == session.src_port)

            if is_client_to_server:
                session.src_packets += 1
                session.src_to_dst_bytes += len(pkt.raw_payload)
                if pkt.raw_payload:
                    client_chunks.append(pkt.raw_payload)
            else:
                session.dst_packets += 1
                session.dst_to_src_bytes += len(pkt.raw_payload)
                if pkt.raw_payload:
                    server_chunks.append(pkt.raw_payload)

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

        # Reassemble payloads (ordered by sequence — simplified; full reassembly would use seq numbers)
        session.client_payload = b"".join(client_chunks)
        session.server_payload = b"".join(server_chunks)
        session.duration = session.end_time - session.start_time

        # Check for timeout
        if session.state == "ACTIVE" and session.duration > session_timeout:
            session.state = "TIMEOUT"

        sessions.append(session)

    logger.info(f"Reconstructed {len(sessions)} TCP sessions from {len(packets)} packets")
    return sessions