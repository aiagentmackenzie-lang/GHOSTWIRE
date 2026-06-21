"""Tests for JA4+/JA4H/JA4SSH fingerprinting engines."""

from engine.fingerprint.ja4_engine import fingerprint_tls, fingerprint_stream, TLSFingerprint
from engine.fingerprint.ja4h_engine import fingerprint_http, fingerprint_stream as fingerprint_http_stream
from engine.fingerprint.ja4ssh_engine import fingerprint_ssh, fingerprint_stream as fingerprint_ssh_stream
from engine.parser.pcap_loader import PacketRecord
from engine.parser.protocol import decode_tls


def _make_tls_client_hello(sni: str = "evil.example.com") -> bytes:
    """Build a minimal TLS Client Hello payload for testing."""
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


def _make_http_get_request(ua: str = "Mozilla/5.0", host: str = "example.com") -> bytes:
    """Build a minimal HTTP GET request."""
    return f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n\r\n".encode()


def _make_ssh_banner(banner: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3") -> bytes:
    """Build an SSH version banner."""
    return (banner + "\r\n").encode()


class TestTLSFingerprint:
    """Tests for TLS fingerprint extraction."""

    def test_client_hello_detected(self):
        """TLS Client Hello should produce a fingerprint."""
        payload = _make_tls_client_hello()
        fp = fingerprint_tls(payload, src_ip="10.0.0.1", dst_ip="93.184.216.34",
                             src_port=50000, dst_port=443)
        assert fp is not None
        assert fp.is_client_hello is True

    def test_non_tls_returns_none(self):
        """Non-TLS payload should return None."""
        payload = b"GET / HTTP/1.1\r\n\r\n"
        fp = fingerprint_tls(payload)
        assert fp is None

    def test_short_payload_returns_none(self):
        """Payload shorter than 5 bytes should return None."""
        fp = fingerprint_tls(b"\x16\x03\x03")
        assert fp is None

    def test_tls_version_extraction(self):
        """Should extract TLS version from record layer."""
        payload = _make_tls_client_hello()
        fp = fingerprint_tls(payload)
        assert fp is not None
        assert fp.tls_version in ("TLS 1.2", "TLS 1.3", "0x0303")

    def test_fingerprint_stream_extracts_tls(self):
        """fingerprint_stream should extract TLS fingerprints from packets."""
        pkt = PacketRecord(
            index=0, timestamp=1.0, src_ip="10.0.0.1", dst_ip="93.184.216.34",
            src_port=50000, dst_port=443, protocol_l4="TCP",
            raw_payload=_make_tls_client_hello(), length=100,
        )
        fps = fingerprint_stream([pkt])
        assert len(fps) >= 1
        assert isinstance(fps[0], TLSFingerprint)

    def test_fingerprint_stream_ignores_non_tcp(self):
        """fingerprint_stream should skip non-TCP packets."""
        pkt = PacketRecord(
            index=0, timestamp=1.0, src_ip="10.0.0.1", dst_ip="93.184.216.34",
            src_port=50000, dst_port=443, protocol_l4="UDP",
            raw_payload=_make_tls_client_hello(), length=100,
        )
        fps = fingerprint_stream([pkt])
        assert len(fps) == 0


class TestSNIExtraction:
    """Regression tests for the off-by-one SNI bug (audit F-02).

    Before the fix, both decode_tls() and fingerprint_tls() used a record-header
    offset of 6 instead of 5, shifting every downstream offset by one and
    producing sni='' / garbage cipher_count / ext_count on any real ClientHello
    with an SNI extension. These tests build a real ClientHello with SNI and
    assert the field actually parses.
    """

    def test_decode_tls_extracts_sni(self, tls_client_hello_bytes):
        info = decode_tls(tls_client_hello_bytes)
        assert info is not None
        assert info.is_client_hello is True
        assert info.sni == "evil.example.com"

    def test_fingerprint_tls_extracts_sni(self, tls_client_hello_bytes):
        fp = fingerprint_tls(tls_client_hello_bytes, src_ip="10.0.0.1", dst_ip="93.184.216.34",
                             src_port=50000, dst_port=443)
        assert fp is not None
        assert fp.is_client_hello is True
        assert fp.sni == "evil.example.com"

    def test_fingerprint_tls_cipher_and_ext_counts(self, tls_client_hello_bytes):
        """cipher_count/ext_count must reflect the actual ClientHello, not garbage."""
        fp = fingerprint_tls(tls_client_hello_bytes)
        assert fp is not None
        assert fp.cipher_count == 1   # one cipher suite in the fixture
        assert fp.ext_count == 1       # one extension (SNI) in the fixture

    def test_fingerprint_tls_produces_ja4(self, tls_client_hello_bytes):
        """JA4 must be non-empty when ja4plus is available (audit F-01)."""
        fp = fingerprint_tls(tls_client_hello_bytes)
        assert fp is not None
        assert fp.ja4, "JA4 must be populated via ja4plus integration"
        assert fp.ja4.startswith("t")  # TLS-over-TCP marker

    def test_fingerprint_tls_produces_ja3(self, tls_client_hello_bytes):
        """JA3 fallback must be a 32-char hex hash (spec-compliant)."""
        fp = fingerprint_tls(tls_client_hello_bytes)
        assert fp is not None
        assert len(fp.ja3_hash) == 32
        int(fp.ja3_hash, 16)  # must be valid hex


class TestHTTPFingerprint:
    """Tests for HTTP/JA4H fingerprint extraction."""

    def test_get_request_fingerprinted(self):
        """HTTP GET should produce a fingerprint."""
        payload = _make_http_get_request()
        fp = fingerprint_http(payload, src_ip="10.0.0.1")
        assert fp is not None
        assert fp.method == "GET"
        assert fp.user_agent == "Mozilla/5.0"
        assert fp.ja4h.startswith("g")

    def test_post_request_fingerprinted(self):
        """HTTP POST should produce a fingerprint."""
        payload = b"POST /api HTTP/1.1\r\nHost: test.com\r\nContent-Length: 0\r\n\r\n"
        fp = fingerprint_http(payload)
        assert fp is not None
        assert fp.method == "POST"

    def test_http_response_not_fingerprinted(self):
        """HTTP responses should return None (only request fingerprinting)."""
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        fp = fingerprint_http(payload)
        assert fp is None

    def test_empty_payload_returns_none(self):
        """Empty payload should return None."""
        assert fingerprint_http(b"") is None

    def test_cookie_flag_set(self):
        """HTTP request with Cookie should set cookie_present."""
        payload = b"GET / HTTP/1.1\r\nHost: test.com\r\nCookie: session=abc\r\n\r\n"
        fp = fingerprint_http(payload)
        assert fp is not None
        assert fp.cookie_present is True

    def test_fingerprint_http_stream(self):
        """fingerprint_stream should extract HTTP fingerprints from packets."""
        pkt = PacketRecord(
            index=0, timestamp=1.0, src_ip="10.0.0.1", dst_ip="93.184.216.34",
            src_port=50000, dst_port=80, protocol_l4="TCP",
            raw_payload=_make_http_get_request(), length=100,
        )
        fps = fingerprint_http_stream([pkt])
        assert len(fps) >= 1


class TestSSHFingerprint:
    """Tests for SSH fingerprint extraction."""

    def test_ssh_banner_fingerprinted(self):
        """SSH banner should produce a fingerprint."""
        payload = _make_ssh_banner()
        fp = fingerprint_ssh(payload, src_ip="10.0.0.1")
        assert fp is not None
        assert fp.is_client is True
        assert fp.ssh_version == "2.0"
        assert "OpenSSH" in fp.client_software

    def test_paramiko_banner_detected(self):
        """Paramiko banner should be detected."""
        payload = _make_ssh_banner("SSH-2.0-Paramiko_3.4.0")
        fp = fingerprint_ssh(payload)
        assert fp is not None
        assert "Paramiko" in fp.client_software

    def test_non_ssh_returns_none(self):
        """Non-SSH payload should return None."""
        payload = b"GET / HTTP/1.1\r\n\r\n"
        fp = fingerprint_ssh(payload)
        assert fp is None

    def test_empty_payload_returns_none(self):
        """Empty payload should return None."""
        assert fingerprint_ssh(b"") is None

    def test_ssh_stream_extracts(self):
        """fingerprint_stream should extract SSH fingerprints from packets."""
        pkt = PacketRecord(
            index=0, timestamp=1.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=50000, dst_port=22, protocol_l4="TCP",
            raw_payload=_make_ssh_banner(), length=100,
        )
        fps = fingerprint_ssh_stream([pkt])
        assert len(fps) >= 1