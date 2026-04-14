"""Protocol decoder — identify and decode application layers from raw payloads."""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Well-known protocol ports
_PORT_MAP = {
    80: "HTTP",
    443: "TLS",
    53: "DNS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    8080: "HTTP",
    8443: "TLS",
}

# SSH version pattern
_SSH_BANNER_RE = re.compile(rb"^SSH-[\d.]+-.+\r?\n")

# HTTP methods
_HTTP_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"PATCH", b"HEAD", b"OPTIONS", b"CONNECT", b"TRACE"}

# HTTP response pattern
_HTTP_RESPONSE_RE = re.compile(rb"^HTTP/[\d.]+\s\d{3}")


@dataclass
class TLSInfo:
    """Extracted TLS metadata."""
    sni: str = ""
    version: str = ""
    ja4_raw: str = ""
    is_client_hello: bool = False
    is_server_hello: bool = False
    cipher_suites: list = field(default_factory=list)


@dataclass
class DNSInfo:
    """Extracted DNS metadata."""
    query_name: str = ""
    query_type: str = ""
    response_code: str = ""
    answers: list = field(default_factory=list)
    is_query: bool = False
    is_response: bool = False


@dataclass
class HTTPInfo:
    """Extracted HTTP metadata."""
    method: str = ""
    url: str = ""
    status_code: int = 0
    host: str = ""
    user_agent: str = ""
    content_type: str = ""
    is_request: bool = False
    is_response: bool = False


@dataclass
class SSHInfo:
    """Extracted SSH metadata."""
    client_banner: str = ""
    server_banner: str = ""
    kex_algorithm: str = ""
    is_client: bool = False
    is_server: bool = False


@dataclass
class ICMPInfo:
    """Extracted ICMP metadata."""
    icmp_type: int = 0
    icmp_code: int = 0
    description: str = ""
    payload_entropy: float = 0.0
    tunnel_suspect: bool = False


@dataclass
class ProtocolResult:
    """Complete protocol decode result."""
    l7_protocol: str = ""
    tls: Optional[TLSInfo] = None
    dns: Optional[DNSInfo] = None
    http: Optional[HTTPInfo] = None
    ssh: Optional[SSHInfo] = None
    icmp: Optional[ICMPInfo] = None


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    import math
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def decode_tls(payload: bytes) -> Optional[TLSInfo]:
    """Decode TLS handshake from raw payload."""
    if len(payload) < 5:
        return None

    # TLS record: content_type(1) + version(2) + length(2)
    content_type = payload[0]
    if content_type not in (0x16, 0x14, 0x15, 0x17):
        return None

    info = TLSInfo()

    if content_type == 0x16 and len(payload) > 6:
        # Handshake
        hs_type = payload[5]
        if hs_type == 0x01:
            # Client Hello
            info.is_client_hello = True
            # Extract SNI from extensions
            try:
                # Simplified SNI extraction — walk past session ID and cipher suites
                offset = 6 + 4  # handshake header
                if len(payload) > offset + 34:
                    # Skip: version(2) + random(32)
                    offset += 34
                    # Session ID length
                    if offset < len(payload):
                        sid_len = payload[offset]
                        offset += 1 + sid_len
                    # Cipher suites length
                    if offset + 1 < len(payload):
                        cs_len = struct.unpack("!H", payload[offset:offset+2])[0]
                        offset += 2 + cs_len
                    # Compression methods length
                    if offset < len(payload):
                        comp_len = payload[offset]
                        offset += 1 + comp_len
                    # Extensions length
                    if offset + 1 < len(payload):
                        ext_len = struct.unpack("!H", payload[offset:offset+2])[0]
                        offset += 2
                        ext_end = offset + ext_len
                        # Walk extensions looking for SNI (0x0000)
                        while offset + 4 < ext_end:
                            ext_type = struct.unpack("!H", payload[offset:offset+2])[0]
                            ext_data_len = struct.unpack("!H", payload[offset+2:offset+4])[0]
                            if ext_type == 0x0000 and offset + 9 < len(payload):
                                # SNI list
                                sni_list_len = struct.unpack("!H", payload[offset+5:offset+7])[0]
                                sni_type = payload[offset+7]
                                sni_len = struct.unpack("!H", payload[offset+8:offset+10])[0]
                                if sni_type == 0 and offset + 10 + sni_len <= len(payload):
                                    info.sni = payload[offset+10:offset+10+sni_len].decode("utf-8", errors="replace")
                            offset += 4 + ext_data_len
            except (struct.error, IndexError) as e:
                logger.debug(f"SNI extraction failed: {e}")

        elif hs_type == 0x02:
            info.is_server_hello = True

    # TLS version from record layer
    if len(payload) >= 4:
        ver = struct.unpack("!H", payload[1:3])[0]
        version_map = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
        info.version = version_map.get(ver, f"0x{ver:04x}")

    return info


def decode_dns(payload: bytes) -> Optional[DNSInfo]:
    """Decode DNS message from raw payload."""
    if len(payload) < 12:
        return None

    # DNS header flags
    flags = struct.unpack("!H", payload[2:4])[0]
    qr = (flags >> 15) & 1
    rcode = flags & 0xF

    info = DNSInfo()
    info.is_query = qr == 0
    info.is_response = qr == 1

    rcode_map = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
    info.response_code = rcode_map.get(rcode, str(rcode))

    # Extract query name
    qdcount = struct.unpack("!H", payload[4:6])[0]
    if qdcount > 0 and len(payload) > 12:
        offset = 12
        labels = []
        while offset < len(payload) and payload[offset] != 0:
            label_len = payload[offset]
            offset += 1
            if offset + label_len > len(payload):
                break
            labels.append(payload[offset:offset+label_len].decode("utf-8", errors="replace"))
            offset += label_len
        info.query_name = ".".join(labels)
        if offset < len(payload) - 2:
            qtype = struct.unpack("!H", payload[offset+1:offset+3])[0]
            type_map = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
            info.query_type = type_map.get(qtype, str(qtype))

    return info


def decode_http(payload: bytes) -> Optional[HTTPInfo]:
    """Decode HTTP request or response from raw payload."""
    if not payload:
        return None

    info = HTTPInfo()

    # Check for HTTP request
    for method in _HTTP_METHODS:
        if payload.startswith(method + b" "):
            info.is_request = True
            info.method = method.decode()
            try:
                first_line = payload.split(b"\r\n")[0].decode("utf-8", errors="replace")
                parts = first_line.split(" ")
                if len(parts) >= 2:
                    info.url = parts[1]
            except (IndexError, UnicodeDecodeError):
                pass
            break

    # Check for HTTP response
    if not info.is_request and _HTTP_RESPONSE_RE.match(payload):
        info.is_response = True
        try:
            first_line = payload.split(b"\r\n")[0].decode("utf-8", errors="replace")
            parts = first_line.split(" ", 2)
            if len(parts) >= 2:
                info.status_code = int(parts[1])
        except (IndexError, ValueError):
            pass

    # Extract headers
    if info.is_request or info.is_response:
        try:
            headers = payload.split(b"\r\n\r\n")[0].split(b"\r\n")[1:]
            for h in headers:
                if h.lower().startswith(b"host:"):
                    info.host = h.split(b":", 1)[1].strip().decode("utf-8", errors="replace")
                elif h.lower().startswith(b"user-agent:"):
                    info.user_agent = h.split(b":", 1)[1].strip().decode("utf-8", errors="replace")
                elif h.lower().startswith(b"content-type:"):
                    info.content_type = h.split(b":", 1)[1].strip().decode("utf-8", errors="replace")
        except (IndexError, UnicodeDecodeError):
            pass

    if not info.is_request and not info.is_response:
        return None

    return info


def decode_ssh(payload: bytes) -> Optional[SSHInfo]:
    """Decode SSH protocol from raw payload."""
    if not payload:
        return None

    info = SSHInfo()

    if _SSH_BANNER_RE.match(payload):
        banner = payload.split(b"\r\n")[0].split(b"\n")[0].decode("utf-8", errors="replace")
        if "SSH-2.0" in banner or "SSH-1.99" in banner or "SSH-1." in banner:
            info.client_banner = banner
            info.is_client = True
            return info

    # SSH_MSG_KEXINIT (type 20)
    if len(payload) >= 6 and payload[5] == 20:
        info.is_server = True
        return info

    return None


def decode_icmp(payload: bytes, icmp_type: int = 0, icmp_code: int = 0) -> Optional[ICMPInfo]:
    """Decode ICMP and detect potential tunneling."""
    if not payload:
        return None

    info = ICMPInfo()
    info.icmp_type = icmp_type
    info.icmp_code = icmp_code

    type_map = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "Time Exceeded"}
    info.description = type_map.get(icmp_type, f"Type {icmp_type}")

    # Check for ICMP tunneling — high entropy payload is suspicious
    inner_data = payload[4:] if len(payload) > 4 else b""  # Skip ICMP header
    if inner_data:
        info.payload_entropy = _shannon_entropy(inner_data)
        # Normal ICMP echo has predictable patterns; high entropy = possible DNS/ICMP tunnel
        if info.payload_entropy > 7.0:
            info.tunnel_suspect = True

    return info


def identify_protocol(src_port: int, dst_port: int, payload: bytes,
                       l4_protocol: str = "TCP",
                       metadata: dict | None = None) -> ProtocolResult:
    """Identify and decode the application-layer protocol.

    Uses port-based heuristics + payload inspection for accurate identification.
    """
    result = ProtocolResult()
    meta = metadata or {}

    # Try payload-based detection first (more reliable)
    if l4_protocol == "TCP" and payload:
        # Check TLS
        if len(payload) >= 5 and payload[0] in (0x16, 0x14, 0x15, 0x17):
            result.l7_protocol = "TLS"
            result.tls = decode_tls(payload)
            return result

        # Check HTTP
        http = decode_http(payload)
        if http:
            result.l7_protocol = "HTTP"
            result.http = http
            return result

        # Check SSH
        ssh = decode_ssh(payload)
        if ssh:
            result.l7_protocol = "SSH"
            result.ssh = ssh
            return result

    if l4_protocol == "UDP" and payload:
        # Check DNS
        if len(payload) >= 12:
            dns = decode_dns(payload)
            if dns:
                result.l7_protocol = "DNS"
                result.dns = dns
                return result

    # Check ICMP with tunnel detection
    if l4_protocol == "ICMP":
        icmp_type = meta.get("icmp_type", 0)
        icmp_code = meta.get("icmp_code", 0)
        icmp = decode_icmp(payload, icmp_type, icmp_code)
        if icmp:
            result.l7_protocol = "ICMP"
            result.icmp = icmp
            return result

    # Fall back to port-based identification
    for port in (src_port, dst_port):
        if port in _PORT_MAP:
            proto = _PORT_MAP[port]
            # Don't mark as TLS on port 443 if payload inspection already failed
            if proto == "TLS" and payload and payload[0] not in (0x16, 0x14, 0x15, 0x17):
                continue
            result.l7_protocol = proto
            return result

    return result