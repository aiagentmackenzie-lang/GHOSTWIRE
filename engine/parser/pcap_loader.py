"""PCAP/PCAPNG file loader using scapy and dpkt (streaming + list).

Two things matter beyond parsing frames for an analyst:

* **Which decoder actually produced the result.** ``iter_packet_records`` can
  fall back from dpkt to Scapy. A ``ParserReport`` (passed in by the caller)
  records the declared parser, the parser that produced records, the declared
  link type, how many frames were read, and how many of those produced a
  usable IP/TCP/UDP decode. Without that, "0 sessions" cannot be distinguished
  from "the parser read every frame and understood none of it".
* **Link-layer framing.** dpkt requires the caller to strip the link header,
  so a raw-IP capture read as Ethernet yields frames with no addresses. The
  link type from the capture header now selects the framing (Ethernet, raw
  IPv4/IPv6, BSD loopback, Linux cooked), and an unrecognised link type is
  reported instead of silently producing empty packets.
"""

from __future__ import annotations

import logging
import socket
import struct
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


# ─── Link types ──────────────────────────────────────────────────────────────
# libpcap LINKTYPE_* values for the framings we decode. Anything else is
# reported as unsupported rather than guessed.
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_BSD = 12        # historic BSD DLT_RAW
LINKTYPE_RAW = 101           # LINKTYPE_RAW (pcap)
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229

LINK_TYPE_NAMES: dict[int, str] = {
    LINKTYPE_NULL: "NULL (BSD loopback)",
    LINKTYPE_ETHERNET: "EN10MB (Ethernet)",
    LINKTYPE_RAW_BSD: "RAW (BSD)",
    LINKTYPE_RAW: "RAW (IPv4/IPv6)",
    LINKTYPE_LINUX_SLL: "LINUX_SLL (cooked)",
    105: "IEEE802_11 (802.11)",
    127: "IEEE802_11_RADIOTAP",
    276: "LINUX_SLL2",
    LINKTYPE_IPV4: "IPV4",
    LINKTYPE_IPV6: "IPV6",
}

_RAW_LINK_TYPES = {LINKTYPE_RAW_BSD, LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6}

# Decode attempts are summarised, not enumerated: a 4M-frame capture must not
# grow a list with one entry per frame.
MAX_DECODE_FAILURES_REPORTED = 20


@dataclass
class ParserReport:
    """What the reader actually did with this capture.

    Mutated in place while frames stream, then folded into the run/coverage
    record. Keeping it a plain dataclass (not a return value) lets the caller
    stream frames and still learn the outcome.
    """

    declared_parser: str = "auto"
    parser_used: str = ""
    attempts: list[dict] = field(default_factory=list)
    capture_format: str = ""
    link_type_declared: int | None = None
    link_type_name: str = ""
    framing_used: str = ""
    frames_read: int = 0
    frames_decoded: int = 0
    frames_undecoded: int = 0
    decode_failure_count: int = 0
    decode_failures: list[dict] = field(default_factory=list)
    fallback_used: bool = False
    notes: list[str] = field(default_factory=list)

    def record_frame(self, decoded: bool, frame_index: int | None = None,
                     reason: str = "") -> None:
        self.frames_read += 1
        if decoded:
            self.frames_decoded += 1
            return
        self.frames_undecoded += 1
        self.decode_failure_count += 1
        if len(self.decode_failures) < MAX_DECODE_FAILURES_REPORTED:
            self.decode_failures.append({
                "frame": (frame_index + 1) if frame_index is not None else None,
                "reason": reason or "no IP/TCP/UDP decode",
            })

    def note(self, message: str) -> None:
        if message not in self.notes:
            self.notes.append(message)

    def decode_rate(self) -> float | None:
        if not self.frames_read:
            return None
        return self.frames_decoded / self.frames_read

    def to_dict(self) -> dict:
        return {
            "declared_parser": self.declared_parser,
            "parser_used": self.parser_used or None,
            "attempts": list(self.attempts),
            "capture_format": self.capture_format or None,
            "link_type_declared": self.link_type_declared,
            "link_type_name": self.link_type_name or None,
            "framing_used": self.framing_used or None,
            "frames_read": self.frames_read,
            "frames_decoded": self.frames_decoded,
            "frames_undecoded": self.frames_undecoded,
            "decode_rate": (None if self.decode_rate() is None
                            else round(self.decode_rate() or 0.0, 4)),
            "decode_failures": list(self.decode_failures),
            "decode_failure_count": self.decode_failure_count,
            "fallback_used": self.fallback_used,
            "notes": list(self.notes),
        }


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

    @property
    def frame_number(self) -> int:
        """One-based frame number as analyst tools (and Wireshark) show it."""
        return self.index + 1

    def decoded(self) -> bool:
        """True when this frame yielded an IP address and a known L4 decode."""
        return bool(self.src_ip and self.protocol_l4)

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


# ─── Capture header / link type sniffing ────────────────────────────────────

def sniff_capture_header(path: Path) -> tuple[str, int | None]:
    """Return (capture_format, link_type) from the capture header.

    Reads only the file header (and, for PCAPNG, the first interface
    description block). ``link_type`` is None when it cannot be determined.
    """
    try:
        with open(path, "rb") as f:
            head = f.read(64)
            if len(head) < 4:
                return ("unknown", None)
            magic = head[:4]
            # Classic PCAP: 4-byte magic, then 20 bytes of header,
            # network (link type) is the last 4 bytes (offset 20).
            if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
                endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
                if len(head) >= 24:
                    link_type = struct.unpack(endian + "I", head[20:24])[0]
                    return ("pcap", link_type)
                return ("pcap", None)
            if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
                endian = "<" if magic == b"\x4d\x3c\xb2\xa1" else ">"
                if len(head) >= 24:
                    link_type = struct.unpack(endian + "I", head[20:24])[0]
                    return ("pcap-ns", link_type)
                return ("pcap-ns", None)
            if magic == b"\x0a\x0d\x0d\x0a":
                f.seek(0)
                return ("pcapng", _pcapng_link_type(f))
            return ("unknown", None)
    except OSError as e:  # unreadable file
        logger.debug(f"capture header sniff failed: {e}")
        return ("unknown", None)


def _pcapng_link_type(f) -> int | None:
    """First Interface Description Block's link type, or None.

    Minimal block walk: block type (4), block length (4), body, block length.
    Stops at the first IDB (type 0x00000001) after the section header block.
    """
    while True:
        head = f.read(8)
        if len(head) < 8:
            return None
        try:
            block_type, block_len = struct.unpack("<II", head)
        except struct.error:
            return None
        if block_len < 12 or block_len > 16 * 1024 * 1024:
            return None
        body = f.read(block_len - 12)
        trailer = f.read(4)
        if len(trailer) < 4:
            return None
        if block_type == 0x00000001 and len(body) >= 2:  # IDB: linktype (2)
            return struct.unpack("<H", body[:2])[0]


def _link_type_name(link_type: int | None) -> str:
    if link_type is None:
        return "unknown"
    return LINK_TYPE_NAMES.get(link_type, f"linktype {link_type}")


def _decode_ip_dpkt(record: PacketRecord, ip: Any) -> bool:
    """Populate L3/L4 from a dpkt IPv4/IPv6 object. True if decoded."""
    try:
        if isinstance(ip, dpkt.ip.IP):
            record.src_ip = _ip_to_str(ip.src)
            record.dst_ip = _ip_to_str(ip.dst)
            record.ttl = ip.ttl
            record.protocol_l3 = "IP"
        elif isinstance(ip, dpkt.ip6.IP6):
            record.src_ip = _ip6_to_str(ip.src)
            record.dst_ip = _ip6_to_str(ip.dst)
            record.ttl = getattr(ip, "hlim", 0)
            record.protocol_l3 = "IPv6"
        else:
            return False
        _fill_l4_dpkt(record, ip.data)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as e:
        logger.debug(f"L3 decode error: {e}")
        return False
    return bool(record.src_ip and record.protocol_l4)


def _frame_to_ip_dpkt(buf: bytes, link_type: int | None) -> Any | None:
    """Strip the link header for ``link_type`` and return a dpkt IP object.

    ``None`` means the framing is unsupported or the bytes did not decode. The
    caller records the frame as undecoded and, when the capture declares a
    framing we cannot handle, reports it once as a coverage limitation.
    """
    if link_type is None:
        link_type = _guess_link_type(buf)

    if link_type == LINKTYPE_ETHERNET:
        eth = dpkt.ethernet.Ethernet(buf)
        return eth.data if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    if link_type in _RAW_LINK_TYPES or link_type == LINKTYPE_NULL:
        if link_type == LINKTYPE_NULL and len(buf) >= 4:
            # BSD loopback: 4-byte address family in host byte order.
            family = struct.unpack("<I", buf[:4])[0]
            if family not in (2, 24, 28, 30):
                family = struct.unpack(">I", buf[:4])[0]
            buf = buf[4:]
        return _raw_ip_dpkt(buf)
    if link_type == LINKTYPE_LINUX_SLL:
        # 16-byte cooked header; ethertype at bytes 14..15.
        if len(buf) < 16:
            return None
        ethertype = struct.unpack("!H", buf[14:16])[0]
        return _raw_ip_dpkt(buf[16:], ethertype)
    # Unknown framing: try Ethernet, then raw IP, so a usable decode is not
    # lost to a mislabelled header.
    try:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return eth.data
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        pass
    return _raw_ip_dpkt(buf)


def _raw_ip_dpkt(buf: bytes, ethertype: int | None = None) -> Any | None:
    """Decode ``buf`` as an IPv4/IPv6 packet (version nibble disambiguates)."""
    if not buf:
        return None
    if ethertype == 0x0800 or (ethertype is None and (buf[0] >> 4) == 4):
        try:
            return dpkt.ip.IP(buf)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            return None
    if ethertype == 0x86DD or (ethertype is None and (buf[0] >> 4) == 6):
        try:
            return dpkt.ip6.IP6(buf)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            return None
    return None


def _guess_link_type(buf: bytes) -> int:
    """Best-effort framing guess for an unknown declared link type."""
    if len(buf) >= 14:
        ethertype = struct.unpack("!H", buf[12:14])[0]
        if ethertype in (0x0800, 0x86DD, 0x0806):
            return LINKTYPE_ETHERNET
    if buf and (buf[0] >> 4) in (4, 6):
        return LINKTYPE_RAW
    return LINKTYPE_ETHERNET


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


def _iter_dpkt(filepath: Path, report: ParserReport | None = None) -> Iterator[PacketRecord]:
    """Yield PacketRecords from a PCAP/PCAPNG using dpkt (streaming fast path).

    Raises ValueError if the file cannot be parsed as a valid PCAP/PCAPNG.
    """
    link_type = report.link_type_declared if report is not None else None
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

        if report is not None:
            report.framing_used = _link_type_name(link_type)
            if link_type is not None and link_type not in (
                LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_NULL
            ) and link_type not in _RAW_LINK_TYPES:
                report.note(
                    f"declared link type {link_type} ({_link_type_name(link_type)}) "
                    "is not decoded directly; framing was inferred per frame"
                )

        for idx, (ts, buf) in enumerate(pcap):
            record = PacketRecord(index=idx, timestamp=ts, length=len(buf))
            try:
                ip = _frame_to_ip_dpkt(buf, link_type)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, struct.error) as e:
                logger.debug(f"Packet {idx} parse error: {e}")
                if report is not None:
                    report.record_frame(False, idx, f"link/IP decode failed: {e}")
                yield record
                continue

            if ip is not None and _decode_ip_dpkt(record, ip):
                if report is not None:
                    report.record_frame(True, idx)
                yield record
                continue

            # Not an IP frame (ARP, LLDP, ...). Keep the frame so frame counts
            # match the capture, and let the run report it as not decoded.
            if report is not None:
                reason = ("no IPv4/IPv6 layer" if ip is None
                          else "IP layer without a decoded TCP/UDP/ICMP payload")
                report.record_frame(False, idx, reason)
            yield record


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


def _iter_scapy(filepath: Path, report: ParserReport | None = None) -> Iterator[PacketRecord]:
    """Yield PacketRecords from a PCAP using scapy (streaming fallback path).

    Uses PcapReader (read-packet-at-a-time) instead of rdpcap (loads the whole
    file into memory) so a large capture does not OOM the process.
    (production-plan Phase 2.3)
    """
    with ScapyPcapReader(str(filepath)) as reader:
        if report is not None:
            report.framing_used = report.framing_used or "scapy PcapReader (declared link type)"
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

            if report is not None:
                decoded = record.decoded()
                report.record_frame(
                    decoded, idx,
                    "" if decoded else "scapy found no IP + TCP/UDP/ICMP layers",
                )
            yield record


def _parser_order(parser: str) -> list[str]:
    if parser == "auto":
        parser = "dpkt" if _USE_DPKT else "scapy"
    if parser == "dpkt" and _USE_DPKT:
        return ["dpkt", "scapy"]
    if parser == "scapy":
        return ["scapy"]
    return ["scapy"]


def iter_packet_records(filepath: str | Path, *, parser: str = "auto",
                        report: ParserReport | None = None) -> Iterator[PacketRecord]:
    """Stream PacketRecords from a PCAP/PCAPNG file, one at a time.

    Memory-bounded alternative to :func:`load_pcap`: the caller can process
    packets incrementally (identify protocol, fingerprint, accumulate bounded
    sessions) without ever holding the whole capture in memory. (Phase 2.3)

    Args:
        filepath: Path to the capture file.
        parser: "dpkt" (fast), "scapy" (full), or "auto" (dpkt if available).
        report: Optional ParserReport, filled in while frames stream. Pass one
            when the caller needs to know which decoder produced the result
            and how much of the capture decoded.

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

    capture_format, link_type = sniff_capture_header(path)
    if report is not None:
        report.declared_parser = parser
        report.capture_format = capture_format
        report.link_type_declared = link_type
        report.link_type_name = _link_type_name(link_type)

    parsers = _parser_order(parser)

    last_error: str | None = None
    for position, p in enumerate(parsers):
        attempt_start_frames = report.frames_read if report is not None else 0
        attempt = {"parser": p, "outcome": "unknown", "frames": 0}
        if report is not None:
            report.attempts.append(attempt)
        try:
            iterator = _iter_dpkt(path, report) if p == "dpkt" else _iter_scapy(path, report)
            produced = 0
            for record in iterator:
                produced += 1
                yield record
            if report is not None:
                report.parser_used = report.parser_used or p
                attempt["outcome"] = "ok"
                attempt["frames"] = produced
            return
        except ValueError as e:
            last_error = f"File is not a valid capture: {path.name}"
            if report is not None:
                try:
                    produced = report.frames_read - attempt_start_frames
                except Exception:  # pragma: no cover - defensive
                    produced = 0
                attempt["outcome"] = "failed"
                attempt["frames"] = produced
                attempt["error"] = str(e)
                if produced:
                    # Frames already handed to the caller cannot be retracted:
                    # falling back here would count part of the capture twice.
                    report.note(
                        f"{p} yielded {produced} frame(s) before failing; "
                        "not retrying a second parser (would double-count frames)"
                    )
                    raise
                if position + 1 < len(parsers):
                    report.fallback_used = True
            logger.debug(f"Parser {p} failed, trying next fallback")
            continue
        except Exception as e:
            last_error = str(e)
            if report is not None:
                produced = report.frames_read - attempt_start_frames
                attempt["outcome"] = "failed"
                attempt["frames"] = produced
                attempt["error"] = str(e)
                if produced:
                    report.note(
                        f"{p} yielded {produced} frame(s) before failing; "
                        "not retrying a second parser (would double-count frames)"
                    )
                    raise
                if position + 1 < len(parsers):
                    report.fallback_used = True
            logger.debug(f"Parser {p} failed with {e}, trying next fallback")
            continue

    raise ValueError(last_error or f"Failed to parse capture file: {path.name}")


def load_pcap(filepath: str | Path, *, parser: str = "auto",
              report: ParserReport | None = None) -> list[PacketRecord]:
    """Load a PCAP or PCAPNG file and return structured packet records (list).

    Eager counterpart to :func:`iter_packet_records`. Convenience for callers
    that want the whole list (hunt command, unit tests). Use
    ``iter_packet_records`` directly when memory bounding matters (analyze on
    large captures - see Phase 2.3).

    Args:
        filepath: Path to the capture file.
        parser: "dpkt" (fast), "scapy" (full), or "auto" (dpkt if available).
        report: Optional ParserReport, filled in while frames stream.

    Returns:
        List of PacketRecord objects.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the file format is unsupported.
    """
    records = list(iter_packet_records(filepath, parser=parser, report=report))
    logger.info(f"Loaded {len(records)} packets")
    return records
