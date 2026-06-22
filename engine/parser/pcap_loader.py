"""PCAP/PCAPNG file loader using scapy and dpkt."""

from __future__ import annotations

import logging
import socket
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
    from scapy.all import rdpcap
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
        # ICMP6 or other L4 over IPv6 — best-effort payload capture.
        try:
            import dpkt as _dpkt  # local to avoid module-level cost
            if isinstance(l4, _dpkt.icmp6.ICMP6):
                record.protocol_l4 = "ICMP6"
                record.metadata["icmp_type"] = getattr(l4, "type", 0)
                record.metadata["icmp_code"] = getattr(l4, "code", 0)
                record.raw_payload = bytes(l4.data) if l4.data else b""
                return
        except (ImportError, AttributeError):
            pass
        # Unknown L4 — keep whatever bytes we can.
        record.protocol_l4 = type(l4).__name__
        if hasattr(l4, "data") and l4.data:
            record.raw_payload = bytes(l4.data)


def _parse_with_dpkt(filepath: Path) -> list[PacketRecord]:
    """Parse PCAP using dpkt — fast path.

    Raises ValueError if the file cannot be parsed as a valid PCAP/PCAPNG.
    """
    packets: list[PacketRecord] = []

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
                    packets.append(record)
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
                    packets.append(record)
                    continue

                # Non-IP L3 (ARP, etc.)
                record.protocol_l3 = type(eth.data).__name__
                packets.append(record)

            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as e:
                logger.debug(f"Packet {idx} parse error: {e}")
                packets.append(PacketRecord(index=idx, timestamp=ts, length=len(buf)))

    return packets


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


def _parse_with_scapy(filepath: Path) -> list[PacketRecord]:
    """Parse PCAP using scapy — fallback / verification path."""
    packets: list[PacketRecord] = []
    raw_pkts = rdpcap(str(filepath))

    for idx, pkt in enumerate(raw_pkts):
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

        packets.append(record)

    return packets


def load_pcap(filepath: str | Path, *, parser: str = "auto") -> list[PacketRecord]:
    """Load a PCAP or PCAPNG file and return structured packet records.

    Args:
        filepath: Path to the capture file.
        parser: "dpkt" (fast), "scapy" (full), or "auto" (dpkt if available).

    Returns:
        List of PacketRecord objects.

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

    logger.info(f"Loading {path} ({path.stat().st_size / 1_048_576:.1f} MB)")

    if parser == "auto":
        parser = "dpkt" if _USE_DPKT else "scapy"

    last_error = None

    # Try requested parser; on failure, fall back to the other one
    parsers_to_try = []
    if parser == "dpkt" and _USE_DPKT:
        parsers_to_try = ["dpkt", "scapy"]
    elif parser == "scapy":
        parsers_to_try = ["scapy"]
    else:
        # dpkt requested but not available — use scapy
        parsers_to_try = ["scapy"]

    for p in parsers_to_try:
        try:
            if p == "dpkt":
                packets = _parse_with_dpkt(path)
            else:
                packets = _parse_with_scapy(path)
            logger.info(f"Loaded {len(packets)} packets (parser={p})")
            return packets
        except ValueError:
            # dpkt couldn't parse — try scapy fallback
            last_error = f"File is not a valid capture: {path.name}"
            logger.debug(f"Parser {p} failed, trying next fallback")
            continue
        except Exception as e:
            last_error = str(e)
            logger.debug(f"Parser {p} failed with {e}, trying next fallback")
            continue

    # All parsers failed
    raise ValueError(last_error or f"Failed to parse capture file: {path.name}")
