"""Tests for protocol identification (engine/parser/protocol.py)."""

import struct

from engine.parser.protocol import (
    _parse_dns_name,
    decode_dns,
    decode_http,
    identify_protocol,
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


def _dns_query(name_labels, qtype=1, qclass=1, qdcount=1, flags=0x0100):
    """Build a minimal DNS query payload from a list of (label) strings."""
    buf = bytearray()
    buf.extend(b"\x12\x34")          # transaction id
    buf.extend(struct.pack("!H", flags))
    buf.extend(struct.pack("!H", qdcount))
    buf.extend(b"\x00\x00\x00\x00\x00\x00")  # an/ns/ar counts
    for _ in range(qdcount):
        for label in name_labels:
            encoded = label.encode("ascii")
            buf.append(len(encoded))
            buf.extend(encoded)
        buf.append(0x00)              # root terminator
        buf.extend(struct.pack("!H", qtype))
        buf.extend(struct.pack("!H", qclass))
    return bytes(buf)


class TestDecodeDNSValidation:
    """Regression tests for the DNS parser hardening (2026-06-23).

    Root bug: ``decode_dns`` used to accept ANY UDP payload >= 12 bytes as DNS,
    did not handle compression pointers (read 0xC0 as a 192-byte label), and did
    not validate label lengths or qtypes. On the real 4SICS ICS capture this
    mislabeled BACnet/SNMP/NetBIOS UDP as DNS and emitted garbage qtypes
    (17219, 49896) and binary domain names. These tests pin the fix.
    """

    def test_valid_query_parses(self):
        """A well-formed DNS A query must still parse."""
        payload = _dns_query(["example", "com"], qtype=1)
        r = decode_dns(payload)
        assert r is not None
        assert r.query_name == "example.com"
        assert r.query_type == "A"
        assert r.is_query is True

    def test_non_dns_udp_rejected(self):
        """Random UDP bytes (not DNS) must return None, not a garbage DNSInfo."""
        # Header bytes that yield qdcount=1 but a non-ASCII label.
        payload = b"\x00\x00\x01\x00\x00\x01" + b"\x00" * 6 + b"\x04\xff\xfe\xfd\xfc\x00\x00\x01\x00\x01"
        assert decode_dns(payload) is None

    def test_random_high_port_udp_not_labeled_dns(self):
        """Non-DNS UDP on a non-DNS port must not be classified as DNS."""
        payload = bytes(range(40))  # deterministic non-DNS bytes
        result = identify_protocol(47808, 47808, payload, l4_protocol="UDP")
        assert result.l7_protocol == ""

    def test_compression_pointer_followed(self):
        """A DNS name ending in a compression pointer must resolve the full name.

        Builds a buffer with 'example.com' at offset 12, then a name 'foo' +
        pointer to offset 12. Must yield 'foo.example.com', not the
        char-by-char garbage the pre-fix parser produced (it extend()ed the
        joined string, iterating characters).
        """
        buf = bytearray(b"\x00" * 12)
        buf.append(0x07)
        buf.extend(b"example")
        buf.append(0x03)
        buf.extend(b"com")
        buf.append(0x00)
        buf.append(0x03)
        buf.extend(b"foo")
        buf.append(0xC0)
        buf.append(0x0c)
        name, nxt = _parse_dns_name(bytes(buf), 25)
        assert name == "foo.example.com"
        assert nxt == 31

    def test_compression_pointer_loop_rejected(self):
        """A pointer that points to itself (infinite loop) must be rejected."""
        buf = bytearray(b"\x00" * 25)
        buf.append(0xC0)
        buf.append(0x19)  # 0x19 = 25 = self
        name, _ = _parse_dns_name(bytes(buf), 25)
        assert name is None

    def test_reserved_label_type_rejected(self):
        """A label length byte with top two bits = 01 or 10 (0x40-0xBF) is
        reserved by RFC 1035 and must be rejected as not-DNS."""
        # 0x40 as the first label length.
        payload = b"\x00\x00\x01\x00\x00\x01" + b"\x00" * 6 + b"\x40\x00\x00\x01\x00\x01"
        assert decode_dns(payload) is None

    def test_implausible_qtype_rejected(self):
        """A qtype in the thousands (17219, as seen on the 4SICS capture) is
        not a real DNS query type and must be rejected."""
        buf = bytearray(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        buf.append(0x07)
        buf.extend(b"example")
        buf.append(0x03)
        buf.extend(b"com")
        buf.append(0x00)
        buf.extend(struct.pack("!H", 17219))   # garbage qtype
        buf.extend(struct.pack("!H", 1))
        assert decode_dns(bytes(buf)) is None

    def test_huge_qdcount_rejected(self):
        """A qdcount in the thousands is not real DNS; reject it early."""
        payload = b"\x00\x00\x01\x00" + struct.pack("!H", 5000) + b"\x00" * 6
        assert decode_dns(payload) is None

    def test_truncated_name_rejected(self):
        """A label that runs past the buffer end is not valid DNS."""
        payload = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x20short"
        # label length 0x20=32 but only 5 bytes follow
        assert decode_dns(payload) is None

    def test_binary_label_bytes_rejected(self):
        """Label bytes with control/high bytes (not ASCII) mean this is not a
        hostname — reject so binary 'domain names' never reach reports."""
        payload = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x04\xff\xfe\xfd\xfc\x00\x00\x01\x00\x01"
        assert decode_dns(payload) is None
