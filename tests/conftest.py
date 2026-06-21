"""Shared pytest fixtures for GHOSTWIRE.

Every fixture builds a PCAP in-memory with scapy (already a runtime dep) and
writes it to a tmp file. This makes the suite self-contained: `git clone &&
pip install -e . && pytest` works with zero binary fixtures committed. The
old `samples/*.pcap` files (gitignored) are no longer required by CI.

Fixtures:
    beacon_pcap  — TCP session, 25 packets at a steady 60s interval to an
                   external IP. Produces a textbook C2 beacon (jitter ~0).
    tls_pcap     — One TCP packet carrying a TLS ClientHello with an SNI
                   extension. Produces exactly one TLS fingerprint with a
                   populated SNI.
    dns_pcap     — One UDP/DNS packet querying a long high-entropy subdomain
                   over TXT. Produces a DNS tunneling threat.
    mixed_pcap   — beacon_pcap + tls_pcap + dns_pcap concatenated, for
                   end-to-end `analyze` integration tests.
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

# scapy writes raw-IP packets with DLT_RAW, which dpkt's Ethernet reader can't
# frame. Wrapping in Ether() yields a standard Ethernet-encapsulated PCAP that
# both the dpkt fast-path and the scapy fallback parse correctly.
_ETHER_SRC = "00:11:22:33:44:55"
_ETHER_DST = "66:77:88:99:aa:bb"


# ─── Builders ───────────────────────────────────────────────────────────────

def _build_beacon_packets():
    """25 unidirectional TCP packets at a steady 60s interval → jitter ≈ 0."""
    pkts = []
    for i in range(25):
        pkt = (
            Ether(src=_ETHER_SRC, dst=_ETHER_DST)
            / IP(src="192.168.1.50", dst="185.220.101.34", ttl=64)
            / TCP(sport=49152, dport=443, flags="PA", seq=i * 100, ack=1)
            / Raw(load=bytes([0x41 + (i % 26)] * 80))
        )
        pkt.time = float(i * 60.0)  # 0, 60, 120, ... 1440 seconds
        pkts.append(pkt)
    return pkts


def _build_tls_client_hello(sni: str = "evil.example.com") -> bytes:
    """Build a valid TLS 1.2 ClientHello with a single SNI extension."""
    sni_bytes = sni.encode()
    # SNI extension: server_name_list_len(2) + type(1) + len(2) + name
    sni_entry = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    extensions_block = struct.pack("!H", len(ext)) + ext

    ch = bytearray()
    ch.append(0x01)                       # handshake type: ClientHello
    ch.extend(b"\x00\x00\x00")            # 3-byte handshake length (placeholder)
    ch.extend(b"\x03\x03")                # client version: TLS 1.2
    ch.extend(b"\x00" * 32)              # random
    ch.append(0x00)                       # session ID length = 0
    ch.extend(b"\x00\x02")               # cipher suites length = 2
    ch.extend(b"\x00\x2f")               # TLS_RSA_WITH_AES_128_CBC_SHA
    ch.append(0x01)                       # compression methods length = 1
    ch.append(0x00)                       # null compression
    ch.extend(extensions_block)
    hs_len = len(ch) - 4
    ch[1:4] = struct.pack("!I", hs_len)[1:]  # backfill handshake length

    record = bytearray()
    record.append(0x16)                   # content type: Handshake
    record.extend(b"\x03\x03")            # record version: TLS 1.2
    record.extend(struct.pack("!H", len(ch)))
    record.extend(ch)
    return bytes(record)


def _build_tls_packets():
    """One TCP packet carrying the ClientHello (client → server)."""
    hello = _build_tls_client_hello("evil.example.com")
    pkt = (
        Ether(src=_ETHER_SRC, dst=_ETHER_DST)
        / IP(src="192.168.1.50", dst="93.184.216.34", ttl=64)
        / TCP(sport=49152, dport=443, flags="PA", seq=1, ack=1)
        / Raw(load=hello)
    )
    pkt.time = 1.0
    return [pkt]


def _build_dns_query(domain: str, qtype: int) -> bytes:
    """Build a minimal DNS query message for `domain` with query type `qtype`."""
    msg = bytearray()
    msg.extend(b"\x12\x34")   # transaction ID
    msg.extend(b"\x01\x00")   # flags: standard query
    msg.extend(b"\x00\x01")   # QDCOUNT = 1
    msg.extend(b"\x00\x00")   # ANCOUNT
    msg.extend(b"\x00\x00")   # NSCOUNT
    msg.extend(b"\x00\x00")   # ARCOUNT
    for label in domain.split("."):
        msg.append(len(label))
        msg.extend(label.encode())
    msg.append(0x00)          # root label
    msg.extend(struct.pack("!H", qtype))   # QTYPE
    msg.extend(b"\x00\x01")   # QCLASS = IN
    return bytes(msg)


def _build_dns_packets():
    """One UDP/DNS TXT query for a long high-entropy subdomain."""
    # 32-char hex subdomain → DNS tunneling signal (long label + TXT type)
    domain = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4.evil.com"
    payload = _build_dns_query(domain, qtype=16)  # 16 = TXT
    pkt = (
        Ether(src=_ETHER_SRC, dst=_ETHER_DST)
        / IP(src="192.168.1.50", dst="8.8.8.8", ttl=64)
        / UDP(sport=33333, dport=53)
        / Raw(load=payload)
    )
    pkt.time = 1.0
    return [pkt]


# ─── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture
def beacon_pcap(tmp_path) -> str:
    p = tmp_path / "beacon.pcap"
    wrpcap(str(p), _build_beacon_packets())
    return str(p)


@pytest.fixture
def tls_pcap(tmp_path) -> str:
    p = tmp_path / "tls.pcap"
    wrpcap(str(p), _build_tls_packets())
    return str(p)


@pytest.fixture
def dns_pcap(tmp_path) -> str:
    p = tmp_path / "dns.pcap"
    wrpcap(str(p), _build_dns_packets())
    return str(p)


@pytest.fixture
def mixed_pcap(tmp_path) -> str:
    p = tmp_path / "mixed.pcap"
    wrpcap(str(p), _build_beacon_packets() + _build_tls_packets() + _build_dns_packets())
    return str(p)


# Exposed for unit tests that want raw bytes without touching disk
@pytest.fixture
def tls_client_hello_bytes() -> bytes:
    return _build_tls_client_hello("evil.example.com")