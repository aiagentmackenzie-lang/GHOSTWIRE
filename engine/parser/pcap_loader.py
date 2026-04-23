"""PCAP/PCAPNG file loader using scapy and dpkt."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import BinaryIO

logger = logging.getLogger(__name__)

# Try dpkt first (faster), fall back to scapy
_USE_DPKT = True
try:
    import dpkt
except ImportError:
    _USE_DPKT = False
    logger.warning("dpkt not installed, falling back to scapy (slower for large files)")

try:
    from scapy.all import rdpcap, IP as ScapyIP, TCP as ScapyTCP, UDP as ScapyUDP, ICMP as ScapyICMP, Raw
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
        d["raw_payload"] = self.raw_payload.hex() if self.raw_payload else ""
        return d


def _ip_to_str(ip_bytes: bytes) -> str:
    """Convert 4-byte IP to dotted string."""
    return ".".join(str(b) for b in ip_bytes)


def _mac_to_str(mac_bytes: bytes) -> str:
    """Convert 6-byte MAC to colon-separated hex."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


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

                if not isinstance(eth.data, dpkt.ip.IP):
                    record.protocol_l3 = type(eth.data).__name__
                    packets.append(record)
                    continue

                ip = eth.data
                record.src_ip = _ip_to_str(ip.src)
                record.dst_ip = _ip_to_str(ip.dst)
                record.ttl = ip.ttl
                record.protocol_l3 = "IP"

                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    record.protocol_l4 = "TCP"
                    record.src_port = tcp.sport
                    record.dst_port = tcp.dport
                    record.raw_payload = bytes(tcp.data) if tcp.data else b""
                    record.metadata["tcp_flags"] = tcp.flags
                    record.metadata["tcp_seq"] = tcp.seq
                    record.metadata["tcp_ack"] = tcp.ack
                    record.metadata["tcp_win"] = tcp.win

                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    record.protocol_l4 = "UDP"
                    record.src_port = udp.sport
                    record.dst_port = udp.dport
                    record.raw_payload = bytes(udp.data) if udp.data else b""

                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    record.protocol_l4 = "ICMP"
                    icmp = ip.data
                    record.metadata["icmp_type"] = icmp.type
                    record.metadata["icmp_code"] = icmp.code
                    record.raw_payload = bytes(icmp.data) if icmp.data else b""

                packets.append(record)

            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as e:
                logger.debug(f"Packet {idx} parse error: {e}")
                packets.append(PacketRecord(index=idx, timestamp=ts, length=len(buf)))

    return packets


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