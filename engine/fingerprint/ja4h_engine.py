"""JA4H HTTP client fingerprinting.

JA4H creates a fingerprint of HTTP client behavior based on headers,
header order, and values — useful for identifying C2 tools and clients.

Uses the official ja4plus.generate_ja4h() when available (it requires a scapy
packet, so we reconstruct a minimal one from the raw payload + 5-tuple).
Falls back to a local JA4H-style hash when ja4plus is unavailable.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

_HAS_JA4PLUS = False
try:
    import ja4plus
    _HAS_JA4PLUS = True
except ImportError:
    pass

_HAS_SCAPY = False
try:
    from scapy.all import IP as ScapyIP, TCP as ScapyTCP, Raw as ScapyRaw
    _HAS_SCAPY = True
except ImportError:
    pass


@dataclass
class HTTPFingerprint:
    """JA4H-style HTTP fingerprint result."""
    ja4h: str = ""
    method: str = ""
    http_version: str = ""
    header_count: int = 0
    header_order: list[str] = None
    cookie_present: bool = False
    user_agent: str = ""
    accepted_encodings: list[str] = None
    accepted_languages: list[str] = None
    source_ip: str = ""
    destination_ip: str = ""

    def __post_init__(self):
        if self.header_order is None:
            self.header_order = []
        if self.accepted_encodings is None:
            self.accepted_encodings = []
        if self.accepted_languages is None:
            self.accepted_languages = []

    def to_dict(self) -> dict:
        return {
            "ja4h": self.ja4h,
            "method": self.method,
            "http_version": self.http_version,
            "header_count": self.header_count,
            "header_order": self.header_order,
            "cookie_present": self.cookie_present,
            "user_agent": self.user_agent,
        }


def _extract_headers(payload: bytes) -> list[tuple[str, str]]:
    """Extract HTTP headers from raw payload."""
    try:
        header_section = payload.split(b"\r\n\r\n")[0]
        lines = header_section.split(b"\r\n")[1:]  # Skip request/response line
        headers = []
        for line in lines:
            if b":" in line:
                name, _, value = line.partition(b":")
                headers.append((name.decode("utf-8", errors="replace").strip(),
                               value.decode("utf-8", errors="replace").strip()))
        return headers
    except (IndexError, UnicodeDecodeError):
        return []


def _local_ja4h_hash(fp: HTTPFingerprint) -> str:
    """Local JA4H-style hash used when ja4plus is unavailable.

    Format: {method}{version}{cookie}{header_count}_{md5(header_order)[:12]}
    Not the official FoxIO JA4H string, but a stable fingerprint of the same
    behavioral surface. Clearly distinct from a real JA4H (prefixed `local_`).
    """
    method_code = {"GET": "g", "POST": "p", "PUT": "u", "DELETE": "d",
                   "PATCH": "t", "HEAD": "h", "OPTIONS": "o"}.get(fp.method, "x")
    version_code = "1" if "1.1" in fp.http_version else "2" if "2" in fp.http_version else "0"
    cookie_code = "c" if fp.cookie_present else "n"
    header_str = ",".join(fp.header_order)
    header_hash = hashlib.md5(header_str.encode()).hexdigest()[:12]
    return f"local_{method_code}{version_code}{cookie_code}{fp.header_count:02d}_{header_hash}"


def fingerprint_http(payload: bytes, *, src_ip: str = "", dst_ip: str = "",
                     src_port: int = 0, dst_port: int = 0) -> Optional[HTTPFingerprint]:
    """Extract JA4H-style fingerprint from HTTP request payload.

    Args:
        payload: Raw HTTP request bytes.
        src_ip, dst_ip, src_port, dst_port: Connection metadata (used to
            reconstruct a scapy packet for ja4plus).

    Returns:
        HTTPFingerprint if an HTTP request is detected, None otherwise.
    """
    if not payload:
        return None

    # Only fingerprint HTTP requests
    http_methods = [b"GET", b"POST", b"PUT", b"DELETE", b"PATCH", b"HEAD", b"OPTIONS"]
    is_request = any(payload.startswith(m + b" ") for m in http_methods)
    if not is_request:
        return None

    fp = HTTPFingerprint(source_ip=src_ip, destination_ip=dst_ip)

    try:
        first_line = payload.split(b"\r\n")[0].decode("utf-8", errors="replace")
        parts = first_line.split()
        if len(parts) >= 3:
            fp.method = parts[0]
            fp.http_version = parts[2] if parts[2].startswith("HTTP/") else "HTTP/1.1"
    except (IndexError, UnicodeDecodeError):
        pass

    headers = _extract_headers(payload)
    fp.header_count = len(headers)
    fp.header_order = [h[0].lower() for h in headers]

    for name, value in headers:
        name_lower = name.lower()
        if name_lower == "user-agent":
            fp.user_agent = value
        elif name_lower == "cookie":
            fp.cookie_present = True
        elif name_lower == "accept-encoding":
            fp.accepted_encodings = [e.strip() for e in value.split(",")]
        elif name_lower == "accept-language":
            fp.accepted_languages = [e.strip() for e in value.split(",")]

    # Official JA4H via ja4plus (reconstruct a scapy packet — generate_ja4h needs one)
    if _HAS_JA4PLUS and _HAS_SCAPY:
        try:
            pkt = (ScapyIP(src=src_ip or "0.0.0.0", dst=dst_ip or "0.0.0.0")
                   / ScapyTCP(sport=src_port, dport=dst_port)
                   / ScapyRaw(load=payload))
            ja4h = ja4plus.generate_ja4h(pkt)
            if ja4h:
                fp.ja4h = ja4h
                return fp
        except Exception as e:
            logger.debug(f"ja4plus generate_ja4h failed: {e}")

    # Fallback: local hash
    fp.ja4h = _local_ja4h_hash(fp)
    return fp


def fingerprint_stream(packets: list) -> list[HTTPFingerprint]:
    """Scan packets for HTTP requests and extract fingerprints."""
    fingerprints: list[HTTPFingerprint] = []

    for pkt in packets:
        if pkt.protocol_l4 != "TCP" or not pkt.raw_payload:
            continue
        fp = fingerprint_http(
            pkt.raw_payload,
            src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
            src_port=pkt.src_port, dst_port=pkt.dst_port,
        )
        if fp:
            fingerprints.append(fp)

    logger.info(f"Extracted {len(fingerprints)} HTTP fingerprints")
    return fingerprints