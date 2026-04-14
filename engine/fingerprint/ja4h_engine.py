"""JA4H HTTP client fingerprinting.

JA4H creates a fingerprint of HTTP client behavior based on headers,
header order, and values — useful for identifying C2 tools and clients.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


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


def fingerprint_http(payload: bytes, *, src_ip: str = "", dst_ip: str = "") -> Optional[HTTPFingerprint]:
    """Extract JA4H-style fingerprint from HTTP request payload.

    JA4H format: {method}{http_version}{cookie_flag}{header_count_hash}{header_order_hash}
    Simplified: we create a deterministic hash from header ordering and values.
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

    # Generate JA4H hash from header fingerprint
    method_code = {"GET": "g", "POST": "p", "PUT": "u", "DELETE": "d",
                   "PATCH": "t", "HEAD": "h", "OPTIONS": "o"}.get(fp.method, "x")
    version_code = "1" if "1.1" in fp.http_version else "2" if "2" in fp.http_version else "0"
    cookie_code = "c" if fp.cookie_present else "n"

    # Hash the header order for deterministic fingerprinting
    header_str = ",".join(fp.header_order)
    header_hash = hashlib.md5(header_str.encode()).hexdigest()[:12]

    fp.ja4h = f"{method_code}{version_code}{cookie_code}{fp.header_count:02d}_{header_hash}"

    return fp


def fingerprint_stream(packets: list) -> list[HTTPFingerprint]:
    """Scan packets for HTTP requests and extract fingerprints."""
    fingerprints: list[HTTPFingerprint] = []

    for pkt in packets:
        if pkt.protocol_l4 != "TCP" or not pkt.raw_payload:
            continue
        fp = fingerprint_http(pkt.raw_payload, src_ip=pkt.src_ip, dst_ip=pkt.dst_ip)
        if fp:
            fingerprints.append(fp)

    logger.info(f"Extracted {len(fingerprints)} HTTP fingerprints")
    return fingerprints