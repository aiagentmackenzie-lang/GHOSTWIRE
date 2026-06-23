"""PCAP/PCAPNG file loader using scapy and dpkt (streaming + list)."""

from __future__ import annotations

import logging
import socket
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Try dpkt first (faster), fall back to scapy
_USE_DPKT = True
try:
    import dpkt
except ImportError:
    _USE_DPKT = False
    logger.warning("dpkt not installed, falling back to scapy (slower for large files)")

try:
    from scapy.all import ICMP as ScapyICMP
    from scapy.all import IP as ScapyIP
    from scapy.all import TCP as ScapyTCP
    from scapy.all import UDP as ScapyUDP
    from scapy.all import IPv6 as ScapyIPv6
    from scapy.all import PcapReader as ScapyPcapReader
except ImportError:
    pass  # Will fail at runtime if neither available


@dataclass
class PacketRecord:
    """Structured representation of a single packet."""
    index: int
    timestamp: float
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol_l3: str = ""   # IP, ARP, etc.
    protocol_l4: str = ""   # TCP, UDP, ICMP
    protocol_l7: str = ""   # HTTP, DNS, TLS, SSH, etc.
    length: int = 0
    ttl: int = 0
    raw_payload: bytes = b""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        # Truncate raw_payload hex to prevent enormous JSON output
        if self.raw_payload:
            d["raw_payload"] = self.raw_payload[:512].hex()
            if len(self.raw_payload) > 512:
                d["payload_truncated"] = True
                d["original_payload_size"] = len(self.raw_payload)
        else:
            d["raw_payload"] = ""
        return d


def _ip_to_str(ip_bytes: bytes) -> str:
    """Convert 4-byte IP to dotted string."""
    return ".".join(str(b) for b in ip_bytes)


def _ip6_to_str(ip_bytes: bytes) -> str:
    """Convert 16-byte IPv6 address to compressed string."""
    return socket.inet_ntop(socket.AF_INET6, bytes(ip_bytes))


def _mac_to_str(mac_bytes: bytes) -> str:
    """Convert 6-byte MAC to colon-separated hex."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def _fill_l4_dpkt(record: PacketRecord, l4: Any) -> None:
    """Populate L4 fields on a PacketRecord from a dpkt L4 payload object.

    Shared by the IPv4 and IPv6 dpkt paths so neither duplicates the
    TCP/UDP/ICMP dispatch.
    """
    if isinstance(l4, dpkt.tcp.TCP):
        tcp = l4
        record.protocol_l4 = "TCP"
        record.src_port = tcp.sport
        record.dst_port = tcp.dport
        record.raw_payload = bytes(tcp.data) if tcp.data else b""
        record.metadata["tcp_flags"] = tcp.flags
        record.metadata["tcp_seq"] = tcp.seq
        record.metadata["tcp_ack"] = tcp.ack
        record.metadata["tcp_win"] = tcp.win
    elif isinstance(l4, dpkt.udp.UDP):
        udp = l4
        record.protocol_l4 = "UDP"
        record.src_port = udp.sport
        record.dst_port = udp.dport
        record.raw_payload = bytes(udp.data) if udp.data else b""
    elif isinstance(l4, dpkt.icmp.ICMP):
        record.protocol_l4 = "ICMP"
        icmp = l4
        record.metadata["icmp_type"] = icmp.type
        record.metadata["icmp_code"] = icmp.code
        record.raw_payload = bytes(icmp.data) if icmp.data else b""
    else:
        # ICMP6 or other L4 over IPv6 - best-effort payload capture.
        try:
            if isinstance(l4, dpkt.icmp6.ICMP6):
                record.protocol_l4 = "ICMP6"
                record.metadata["icmp_type"] = getattr(l4, "type", 0)
                record.metadata["icmp_code"] = getattr(l4, "code", 0)
                record.raw_payload = bytes(l4.data) if l4.data else b""
                return
        except (ImportError, AttributeError):
            pass
        # Unknown L4 - keep whatever bytes we can.
        record.protocol_l4 = type(l4).__name__
        if hasattr(l4, "data") and l4.data:
            record.raw_payload = bytes(l4.data)


def _iter_dpkt(filepath: Path) -> Iterator[PacketRecord]:
    """Yield PacketRecords from a PCAP using dpkt (streaming fast path).

    Raises ValueError if the file cannot be parsed as a valid PCAP/PCAPNG.
    """
    with open(filepath, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            # Try PCAPNG format
            f.seek(0)
            try:
                pcap = dpkt.pcapng.Reader(f)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError) as e:
                raise ValueError(
                    f"File is not a valid PCAP/PCAPNG: {filepath.name}"
                ) from e

        for idx, (ts, buf) in enumerate(pcap):
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                record = PacketRecord(index=idx, timestamp=ts, length=len(buf))

                # IPv4 (EtherType 0x0800)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    record.src_ip = _ip_to_str(ip.src)
                    record.dst_ip = _ip_to_str(ip.dst)
                    record.ttl = ip.ttl
                    record.protocol_l3 = "IP"
                    _fill_l4_dpkt(record, ip.data)
                    yield record
                    continue

                # IPv6 (EtherType 0x86DD)
                if isinstance(eth.data, dpkt.ip6.IP6):
                    ip6 = eth.data
                    record.src_ip = _ip6_to_str(ip6.src)
                    record.dst_ip = _ip6_to_str(ip6.dst)
                    # dpkt stores hop limit as 'hlim' on IP6
                    record.ttl = getattr(ip6, "hlim", 0)
                    record.protocol_l3 = "IPv6"
                    _fill_l4_dpkt(record, ip6.data)
                    yield record
                    continue

                # Non-IP L3 (ARP, etc.)
                record.protocol_l3 = type(eth.data).__name__
                yield record

            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as e:
                logger.debug(f"Packet {idx} parse error: {e}")
                yield PacketRecord(index=idx, timestamp=ts, length=len(buf))


def _fill_l4_scapy(record: PacketRecord, pkt: Any) -> None:
    """Populate L4 fields from a scapy packet (shared IPv4/IPv6 path)."""
    if pkt.haslayer(ScapyTCP):
        tcp = pkt[ScapyTCP]
        record.protocol_l4 = "TCP"
        record.src_port = tcp.sport
        record.dst_port = tcp.dport
        record.raw_payload = bytes(tcp.payload) if tcp.payload else b""
        record.metadata["tcp_flags"] = int(tcp.flags)
        record.metadata["tcp_seq"] = tcp.seq
        record.metadata["tcp_ack"] = tcp.ack
    elif pkt.haslayer(ScapyUDP):
        udp = pkt[ScapyUDP]
        record.protocol_l4 = "UDP"
        record.src_port = udp.sport
        record.dst_port = udp.dport
        record.raw_payload = bytes(udp.payload) if udp.payload else b""
    elif pkt.haslayer(ScapyICMP):
        record.protocol_l4 = "ICMP"
        icmp = pkt[ScapyICMP]
        record.metadata["icmp_type"] = icmp.type
        record.metadata["icmp_code"] = icmp.code
        record.raw_payload = bytes(icmp.payload) if icmp.payload else b""


def _iter_scapy(filepath: Path) -> Iterator[PacketRecord]:
    """Yield PacketRecords from a PCAP using scapy (streaming fallback path).

    Uses PcapReader (read-packet-at-a-time) instead of rdpcap (loads the whole
    file into memory) so a large capture does not OOM the process.
    (production-plan Phase 2.3)
    """
    with ScapyPcapReader(str(filepath)) as reader:
        for idx, pkt in enumerate(reader):
            record = PacketRecord(
                index=idx,
                timestamp=float(pkt.time),
                length=len(pkt),
            )

            if pkt.haslayer(ScapyIP):
                ip = pkt[ScapyIP]
                record.src_ip = ip.src
                record.dst_ip = ip.dst
                record.ttl = ip.ttl
                record.protocol_l3 = "IP"
                _fill_l4_scapy(record, pkt)
            elif 'ScapyIPv6' in globals() and pkt.haslayer(ScapyIPv6):
                ip6 = pkt[ScapyIPv6]
                record.src_ip = ip6.src
                record.dst_ip = ip6.dst
                record.ttl = getattr(ip6, "hlim", 0)
                record.protocol_l3 = "IPv6"
                _fill_l4_scapy(record, pkt)

            yield record


def iter_packet_records(filepath: str | Path, *, parser: str = "auto") -> Iterator[PacketRecord]:
    """Stream PacketRecords from a PCAP/PCAPNG file, one at a time.

    Memory-bounded alternative to :func:`load_pcap`: the caller can process
    packets incrementally (identify protocol, fingerprint, accumulate bounded
    sessions) without ever holding the whole capture in memory. (Phase 2.3)

    Args:
        filepath: Path to the capture file.
        parser: "dpkt" (fast), "scapy" (full), or "auto" (dpkt if available).

    Yields:
        PacketRecord objects.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the file format is unsupported.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Capture file not found: {path}")

    suffix = path.suffix.lower()
    if suffix not in (".pcap", ".pcapng", ".cap"):
        raise ValueError(f"Unsupported file format: {suffix}. Use .pcap or .pcapng")

    logger.info(f"Streaming {path} ({path.stat().st_size / 1_048_576:.1f} MB)")

    if parser == "auto":
        parser = "dpkt" if _USE_DPKT else "scapy"

    # Build the ordered list of parsers to try. On a ValueError (format
    # mismatch) we fall through to the next parser; other exceptions propagate.
    if parser == "dpkt" and _USE_DPKT:
        parsers: list[str] = ["dpkt", "scapy"]
    elif parser == "scapy":
        parsers = ["scapy"]
    else:
        parsers = ["scapy"]

    last_error: str | None = None
    for p in parsers:
        try:
            if p == "dpkt":
                yield from _iter_dpkt(path)
                return
            else:
                yield from _iter_scapy(path)
                return
        except ValueError:
            last_error = f"File is not a valid capture: {path.name}"
            logger.debug(f"Parser {p} failed, trying next fallback")
            continue
        except Exception as e:
            last_error = str(e)
            logger.debug(f"Parser {p} failed with {e}, trying next fallback")
            continue

    raise ValueError(last_error or f"Failed to parse capture file: {path.name}")


def load_pcap(filepath: str | Path, *, parser: str = "auto") -> list[PacketRecord]:
    """Load a PCAP or PCAPNG file and return structured packet records (list).

    Eager counterpart to :func:`iter_packet_records`. Convenience for callers
    that want the whole list (hunt command, unit tests). Use
    ``iter_packet_records`` directly when memory bounding matters (analyze on
    large captures - see Phase 2.3).

    Args:
        filepath: Path to the capture file.
        parser: "dpkt" (fast), "scapy" (full), or "auto" (dpkt if available).

    Returns:
        List of PacketRecord objects.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the file format is unsupported.
    """
    records = list(iter_packet_records(filepath, parser=parser))
    logger.info(f"Loaded {len(records)} packets")
    return records
