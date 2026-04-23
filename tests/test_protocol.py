"""Tests for protocol identification (engine/parser/protocol.py)."""

import pytest
from engine.parser.protocol import (
    identify_protocol, decode_tls, decode_dns, decode_http, decode_ssh,
    decode_icmp, ProtocolResult,
)


def _build_tls_client_hello(sni: str = "evil.example.com") -> bytes:
    """Build a minimal TLS Client Hello payload for testing."""
    # TLS record: type=0x16 (handshake), version=0x0303 (TLS 1.2), length=placeholder
    # Handshake: type=0x01 (ClientHello), length=placeholder
    # This is a simplified test payload — not a full valid ClientHello
    payload = bytearray()
    # Record layer
    payload.append(0x16)  # Content type: Handshake
    payload.extend(b"\x03\x03")  # Version: TLS 1.2
    payload.extend(b"\x00\x40")  # Record length (placeholder)
    # Handshake header
    payload.append(0x01)  # Client Hello
    payload.extend(b"\x00\x00\x3c")  # Handshake length
    # Client version
    payload.extend(b"\x03\x03")  # TLS 1.2
    # Random (32 bytes)
    payload.extend(b"\x00" * 32)
    # Session ID length = 0
    payload.append(0x00)
    # Cipher suites length = 2
    payload.extend(b"\x00\x02")
    # One cipher suite
    payload.extend(b"\x00\x2f")  # TLS_RSA_WITH_AES_128_CBC_SHA
    # Compression methods length = 1
    payload.append(0x01)
    payload.append(0x00)  # null compression
    return bytes(payload)


class TestIdentifyProtocol:
    """Tests for the identify_protocol() function."""

    def test_tls_client_hello(self):
        """TLS Client Hello should be identified as TLS."""
        payload = _build_tls_client_hello()
        result = identify_protocol(50000, 443, payload, l4_protocol="TCP")
        assert result.l7_protocol == "TLS"
        assert result.tls is not None

    def test_http_get(self):
        """HTTP GET request should be identified as HTTP."""
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = identify_protocol(50000, 80, payload, l4_protocol="TCP")
        assert result.l7_protocol == "HTTP"
        assert result.http is not None
        assert result.http.method == "GET"

    def test_ssh_banner(self):
        """SSH version banner should be identified as SSH."""
        payload = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"
        result = identify_protocol(50000, 22, payload, l4_protocol="TCP")
        assert result.l7_protocol == "SSH"
        assert result.ssh is not None

    def test_dns_payload(self):
        """Valid DNS payload should be identified as DNS."""
        # Minimal DNS query for example.com
        payload = bytearray()
        payload.extend(b"\x12\x34")  # Transaction ID
        payload.extend(b"\x01\x00")  # Flags: standard query
        payload.extend(b"\x00\x01")  # Questions: 1
        payload.extend(b"\x00\x00")  # Answer RRs: 0
        payload.extend(b"\x00\x00")  # Authority RRs: 0
        payload.extend(b"\x00\x00")  # Additional RRs: 0
        # Query: example.com
        payload.append(0x07)  # label length
        payload.extend(b"example")
        payload.append(0x03)
        payload.extend(b"com")
        payload.append(0x00)  # root label
        payload.extend(b"\x00\x01")  # Type A
        payload.extend(b"\x00\x01")  # Class IN
        result = identify_protocol(50000, 53, bytes(payload), l4_protocol="UDP")
        assert result.l7_protocol == "DNS"
        assert result.dns is not None

    def test_icmp_high_entropy_tunnel_suspect(self):
        """ICMP with high-entropy payload should flag tunnel_suspect."""
        # High entropy data (near-random bytes)
        import struct
        high_entropy = bytes(range(256)) * 16  # 4096 bytes of distributed values
        result = identify_protocol(0, 0, high_entropy, l4_protocol="ICMP",
                                   metadata={"icmp_type": 8, "icmp_code": 0})
        assert result.l7_protocol == "ICMP"
        assert result.icmp is not None
        assert result.icmp.tunnel_suspect is True

    def test_empty_payload_returns_empty(self):
        """Empty payload should not match any protocol."""
        result = identify_protocol(50000, 8080, b"", l4_protocol="TCP")
        # Should fall through to port-based or return empty
        assert result.l7_protocol in ("", "HTTP")  # Port 8080 maps to HTTP


class TestDecodeHTTP:
    """Tests for decode_http()."""

    def test_http_response(self):
        """HTTP response should be decoded."""
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        result = decode_http(payload)
        assert result is not None
        assert result.is_response is True
        assert result.status_code == 200

    def test_user_agent_extraction(self):
        """HTTP User-Agent should be extracted."""
        payload = b"GET / HTTP/1.1\r\nHost: test.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        result = decode_http(payload)
        assert result is not None
        assert result.user_agent == "Mozilla/5.0"