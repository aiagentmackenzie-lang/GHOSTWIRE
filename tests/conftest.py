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
from scapy.all import IP, TCP, UDP, Ether, IPv6, Raw, wrpcap

# scapy writes raw-IP packets with DLT_RAW, which dpkt's Ethernet reader can't
# frame. Wrapping in Ether() yields a standard Ethernet-encapsulated PCAP that
# both the dpkt fast-path and the scapy fallback parse correctly.
_ETHER_SRC = "00:11:22:33:44:55"
_ETHER_DST = "66:77:88:99:aa:bb"


# ─── Builders ───────────────────────────────────────────────────────────────

def _build_beacon_packets():
    """A realistic C2 beacon: request/response pairs at a steady 60s interval.

    - 25 intervals (50 packets): small 24-byte encrypted request > ~300-byte
      response, 0.5s apart within a pair, 60s between pairs.
    - Random payloads > high Shannon entropy (> 7.5) → entropy_score.
    - Volume ratio ~0.07 → volume_score 0.6 (asymmetric).
    - Inter-arrival (response→next-request) = 59.5s with zero variance →
      jitter ≈ 0 → jitter_score 0.95.
    - duration 1440s, 50 packets, ~0.035 pkt/s → regularity_score 0.7.
    Composite beacon score ≈ 0.75 → HIGH, which exercises the strong-beacon
    floor in the composite scorer (audit H-04).
    """
    import os
    pkts = []
    # Contiguous sequence numbers per direction (a sparse sequence space would
    # look like a capture gap to the reassembler — see coverage.stream_gaps).
    client_seq = 0
    server_seq = 0
    for i in range(25):
        t = float(i * 60.0)
        # Client → server: small encrypted request (24 random bytes)
        req = (
            Ether(src=_ETHER_SRC, dst=_ETHER_DST)
            / IP(src="192.168.1.50", dst="185.220.101.34", ttl=64)
            / TCP(sport=49152, dport=443, flags="PA",
                  seq=client_seq, ack=server_seq)
            / Raw(load=os.urandom(24))
        )
        req.time = t
        client_seq += 24
        # Server → client: larger response (300 random bytes)
        resp = (
            Ether(src=_ETHER_DST, dst=_ETHER_SRC)
            / IP(src="185.220.101.34", dst="192.168.1.50", ttl=64)
            / TCP(sport=443, dport=49152, flags="PA",
                  seq=server_seq, ack=client_seq)
            / Raw(load=os.urandom(300))
        )
        resp.time = t + 0.5
        server_seq += 300
        pkts.extend([req, resp])
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


def _build_c2_http_packets():
    """One TCP/HTTP GET carrying a Cobalt Strike default User-Agent.

    Uses an exact, documented CS default UA so match_http fires a real
    cobalt_strike C2 match end-to-end (Phase 2 gate).
    """
    ua = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0)"
    req = f"GET /__init.gif HTTP/1.1\r\nHost: c2.evil.example\r\nUser-Agent: {ua}\r\n\r\n".encode()
    pkt = (
        Ether(src=_ETHER_SRC, dst=_ETHER_DST)
        / IP(src="192.168.1.50", dst="185.220.101.34", ttl=64)
        / TCP(sport=49152, dport=80, flags="PA", seq=1, ack=1)
        / Raw(load=req)
    )
    pkt.time = 1.0
    return [pkt]


def _build_benign_browsing_packets():
    """30 sessions of normal browsing — the benign false-positive corpus.

    Designed so the full pipeline returns ZERO beacons / c2_matches / dns_threats
    (production-plan Phase 1.5 + Phase 4.1). Realistic, not threshold-gamed:
      - 25 short HTTPS connections (3-5 packets each, < min_packets=10 -> never
        scored for beaconing) to well-known CDN IPs with benign SNIs. The
        minimal ClientHello's JA4 (1 cipher / 1 ext) does not match any C2
        JA4 prefix in the database.
      - 3 longer HTTP browsing sessions (15-18 packets) with genuinely bursty
        human timing: rapid request/response pairs (<1s, filtered out of
        beacon-IAT calc) separated by high-variance long pauses drawn from
        [15,45,90,180,300,480,600]s. The >1s IATs have std/mean ~0.8 ->
        jitter_score 0.1, and regularity requires iat_jitter<0.5 so it does
        not fire. Real Chrome UA (not in the C2 UA corpus). Balanced
        request/response volume -> volume_score 0.
      - 2 benign DNS A queries (qtype=1) to short well-known SLDs
        (example.com, www.google.com) -> entropy <3.2, not hex, short label ->
        no DGA; A record (not TXT/NULL) -> no tunneling.
    """
    import random
    rng = random.Random(20260622)  # deterministic for reproducible CI

    BENIGN_HOSTS = [
        # (dst_ip, sni) - well-known CDNs / sites, none in the C2 corpus.
        ("93.184.216.34", "example.com"),
        ("151.101.1.69", "cdn.jsdelivr.net"),
        ("104.16.123.96", "cloudflare.com"),
        ("172.217.16.164", "www.google.com"),
        ("151.101.0.81", "fonts.googleapis.com"),
        ("199.27.79.172", "stackoverflow.com"),
    ]
    CHROME_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                 "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    LONG_PAUSES = [15, 45, 90, 180, 300, 480, 600]
    pkts = []
    t = 0.0
    base_port = 40000

    # 25 short TLS connections (3-5 packets each).
    for i in range(25):
        ip, sni = BENIGN_HOSTS[i % len(BENIGN_HOSTS)]
        sport = base_port + i
        n = rng.randint(3, 5)
        hello = _build_tls_client_hello(sni)
        p = (Ether(src=_ETHER_SRC, dst=_ETHER_DST)
             / IP(src="192.168.1.50", dst=ip, ttl=64)
             / TCP(sport=sport, dport=443, flags="PA", seq=1, ack=1)
             / Raw(load=hello))
        p.time = t
        pkts.append(p)
        for _ in range(n - 1):
            t += 0.1 + rng.random() * 0.4
            resp = (Ether(src=_ETHER_DST, dst=_ETHER_SRC)
                    / IP(src=ip, dst="192.168.1.50", ttl=64)
                    / TCP(sport=443, dport=sport, flags="PA", seq=1, ack=1)
                    / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nok"))
            resp.time = t
            pkts.append(resp)
        t += rng.choice([15, 45, 90, 180, 300])

    # 3 longer HTTP browsing sessions (15-18 packets, bursty human timing).
    for i in range(3):
        ip = BENIGN_HOSTS[i][0]
        sport = 50000 + i
        n = rng.randint(15, 18)
        seq = 1
        for k in range(n // 2):
            req = (f"GET /page{k} HTTP/1.1\r\nHost: brows{i}.example\r\n"
                   f"User-Agent: {CHROME_UA}\r\n\r\n").encode()
            p = (Ether(src=_ETHER_SRC, dst=_ETHER_DST)
                 / IP(src="192.168.1.50", dst=ip, ttl=64)
                 / TCP(sport=sport, dport=80, flags="PA", seq=seq, ack=1)
                 / Raw(load=req))
            p.time = t
            pkts.append(p)
            seq += len(req)
            t += 0.2 + rng.random() * 0.3
            body = (f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                    f"<html><body>page {k}</body></html>").encode()
            resp = (Ether(src=_ETHER_DST, dst=_ETHER_SRC)
                    / IP(src=ip, dst="192.168.1.50", ttl=64)
                    / TCP(sport=80, dport=sport, flags="PA", seq=1, ack=seq)
                    / Raw(load=body))
            resp.time = t
            pkts.append(resp)
            t += rng.choice(LONG_PAUSES)

    # 2 benign DNS A queries (qtype=1) to short well-known SLDs.
    for domain in ("example.com", "www.google.com"):
        payload = _build_dns_query(domain, qtype=1)  # 1 = A record
        p = (Ether(src=_ETHER_SRC, dst=_ETHER_DST)
             / IP(src="192.168.1.50", dst="8.8.8.8", ttl=64)
             / UDP(sport=33333, dport=53)
             / Raw(load=payload))
        p.time = t
        pkts.append(p)
        t += 5.0

    pkts.sort(key=lambda p: float(p.time))
    return pkts


def _build_ipv6_beacon_packets():
    """A C2 beacon over IPv6 to an external address (2001:db8:dead::beef).

    25 request/response pairs at a steady 60s interval — same shape as the
    IPv4 beacon but exercising the IPv6 parse path (dpkt.ip6.IP6 / scapy IPv6)
    and IPv6 private-range detection in hunt._is_private_ip. The destination is
    global-scope (not fc00::/7 / fe80::/10 / ::1), so it should be classified
    external and the beacon flagged. (production-plan Phase 2.1)
    """
    import os
    pkts = []
    client_seq = 0
    server_seq = 0
    for i in range(25):
        ts = float(i * 60.0)
        req = (
            Ether(src=_ETHER_SRC, dst=_ETHER_DST)
            / IPv6(src="fd00::50", dst="2001:db8:dead::beef", hlim=64)
            / TCP(sport=49152, dport=443, flags="PA",
                  seq=client_seq, ack=server_seq)
            / Raw(load=os.urandom(24))
        )
        req.time = ts
        client_seq += 24
        resp = (
            Ether(src=_ETHER_DST, dst=_ETHER_SRC)
            / IPv6(src="2001:db8:dead::beef", dst="fd00::50", hlim=64)
            / TCP(sport=443, dport=49152, flags="PA",
                  seq=server_seq, ack=client_seq)
            / Raw(load=os.urandom(300))
        )
        resp.time = ts + 0.5
        server_seq += 300
        pkts.extend([req, resp])
    return pkts


def _build_ipv6_dns_packets():
    """A benign-looking but long-label TXT DNS query over IPv6 transport.

    The DNS query itself is the tunneling signal (long hex subdomain + TXT); the
    IPv6 transport (client fd00::50 -> resolver 2001:4860:4860::8888) exercises
    the IPv6 UDP parse path. Should produce a DNS threat. (Phase 2.1)
    """
    domain = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4.evil6.com"
    payload = _build_dns_query(domain, qtype=16)  # 16 = TXT
    pkt = (
        Ether(src=_ETHER_SRC, dst=_ETHER_DST)
        / IPv6(src="fd00::50", dst="2001:4860:4860::8888", hlim=64)
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


@pytest.fixture
def c2_http_pcap(tmp_path) -> str:
    p = tmp_path / "c2_http.pcap"
    wrpcap(str(p), _build_c2_http_packets())
    return str(p)


@pytest.fixture
def http_pcap(tmp_path) -> str:
    """Alias for the HTTP-only control used throughout the Wave 1 tests."""
    p = tmp_path / "http.pcap"
    wrpcap(str(p), _build_c2_http_packets())
    return str(p)


@pytest.fixture
def benign_pcap(tmp_path) -> str:
    """30 sessions of normal browsing — must produce ZERO detections.

    The headline false-positive guard (production-plan Phase 1.5 / 4.1):
    beacons_detected == 0, c2_matches == 0, dns_threats == 0.
    """
    p = tmp_path / "benign_browsing.pcap"
    wrpcap(str(p), _build_benign_browsing_packets())
    return str(p)


@pytest.fixture
def ipv6_beacon_pcap(tmp_path) -> str:
    p = tmp_path / "ipv6_beacon.pcap"
    wrpcap(str(p), _build_ipv6_beacon_packets())
    return str(p)


@pytest.fixture
def ipv6_dns_pcap(tmp_path) -> str:
    p = tmp_path / "ipv6_dns.pcap"
    wrpcap(str(p), _build_ipv6_dns_packets())
    return str(p)


def _build_split_tls_packets():
    """A TLS ClientHello split across TWO TCP segments (Phase 2.2 gate).

    The ClientHello bytes are split at byte offset 30 across two packets with
    contiguous TCP sequence numbers (seq=1 len=30, then seq=31). Per-packet
    fingerprint_stream sees only fragments (neither starts a complete record)
    and returns nothing; after sequence-ordered reassembly the session's
    client_payload is the whole record and fingerprint_sessions extracts ja4 + sni.
    """
    hello = _build_tls_client_hello("evil.example.com")
    split = 30
    seg1 = hello[:split]
    seg2 = hello[split:]
    p1 = (Ether(src=_ETHER_SRC, dst=_ETHER_DST)
          / IP(src="192.168.1.50", dst="93.184.216.34", ttl=64)
          / TCP(sport=49152, dport=443, flags="PA", seq=1, ack=1)
          / Raw(load=seg1))
    p1.time = 1.0
    p2 = (Ether(src=_ETHER_SRC, dst=_ETHER_DST)
          / IP(src="192.168.1.50", dst="93.184.216.34", ttl=64)
          / TCP(sport=49152, dport=443, flags="PA", seq=1 + split, ack=1)
          / Raw(load=seg2))
    p2.time = 1.001
    return [p1, p2]


@pytest.fixture
def split_tls_pcap(tmp_path) -> str:
    p = tmp_path / "split_tls.pcap"
    wrpcap(str(p), _build_split_tls_packets())
    return str(p)


# Exposed for unit tests that want raw bytes without touching disk
@pytest.fixture
def tls_client_hello_bytes() -> bytes:
    return _build_tls_client_hello("evil.example.com")


# ─── Wave 1 acceptance fixtures ─────────────────────────────────────────────
#
# These express the evidence distinctions the earlier suite missed: a DNS query
# with no TCP session, two conversations that share a client address, a
# duplicated TCP segment, a capture that lost 19 bytes mid-record, a reversed
# file order, and a capture that begins on the server side.

def _build_benign_http_packets(sport: int = 50000, dst: str = "203.0.113.10",
                               ua: str = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0",
                               ts: float = 1.0):
    """One ordinary HTTP request — the negative control for a UA rule match."""
    req = (f"GET /index.html HTTP/1.1\r\nHost: benign.example\r\n"
           f"User-Agent: {ua}\r\n\r\n").encode()
    pkt = (
        Ether(src=_ETHER_SRC, dst=_ETHER_DST)
        / IP(src="192.168.1.50", dst=dst, ttl=64)
        / TCP(sport=sport, dport=80, flags="PA", seq=1, ack=1)
        / Raw(load=req)
    )
    pkt.time = ts
    return [pkt]


def _build_duplicate_first_segment_packets():
    """The split ClientHello with the first 30-byte segment sent twice.

    TShark marks the repeat and recovers one handshake. GHOSTWIRE must keep one
    fingerprint, count 107 captured payload bytes (30 + 30 + 47) and 77 distinct
    stream bytes.
    """
    seg1, seg2 = _build_split_tls_packets()
    return [seg1, seg1, seg2]


def _build_truncated_hello_packets():
    """First segment truncated from 30 to 11 captured bytes (19 bytes lost).

    The original first-frame payload length was 30, so the receiver knows 19
    bytes are missing between sequence 12 and 31. TShark emits no complete
    ClientHello; GHOSTWIRE must expose two disjoint ranges and 19 missing bytes
    instead of concatenating across the hole.
    """
    import copy
    seg1, seg2 = _build_split_tls_packets()
    truncated = copy.deepcopy(seg1)
    truncated[Raw].load = bytes(seg1[Raw].load)[:11]
    truncated.time = 1.0
    # The captured length shrinks; the IP total length still claims the
    # original, which is exactly how a snaplen-limited capture looks.
    return [truncated, seg2]


def _build_reversed_split_packets():
    """The split handshake written in reverse file order, timestamps preserved.

    The capture still spans 1 ms. The stream bytes are contiguous, so payload
    reconstruction is fine; the *timing* is not in file order and must be
    reported as an ordering anomaly with a positive span.
    """
    seg1, seg2 = _build_split_tls_packets()
    return [seg2, seg1]


@pytest.fixture
def dns_plus_http_pcap(tmp_path) -> str:
    """The HTTP fixture appended after a DNS query to a different destination.

    The DNS query is not evidence about the HTTP conversation: the HTTP session
    score must stay 0.315.
    """
    p = tmp_path / "dns_plus_http.pcap"
    wrpcap(str(p), _build_dns_packets() + _build_c2_http_packets())
    return str(p)


@pytest.fixture
def http_with_shared_client_pcap(tmp_path) -> str:
    """Two HTTP conversations from the same client address.

    Only the first carries the C2 User-Agent. The second must gain no match,
    no finding and no score contribution.
    """
    p = tmp_path / "two_http_sessions.pcap"
    wrpcap(str(p), _build_c2_http_packets() + _build_benign_http_packets(ts=2.0))
    return str(p)


@pytest.fixture
def duplicate_segment_pcap(tmp_path) -> str:
    p = tmp_path / "duplicate_segment.pcap"
    wrpcap(str(p), _build_duplicate_first_segment_packets())
    return str(p)


@pytest.fixture
def truncated_hello_pcap(tmp_path) -> str:
    p = tmp_path / "truncated_hello.pcap"
    wrpcap(str(p), _build_truncated_hello_packets())
    return str(p)


@pytest.fixture
def reversed_order_pcap(tmp_path) -> str:
    p = tmp_path / "reversed_order.pcap"
    wrpcap(str(p), _build_reversed_split_packets())
    return str(p)


@pytest.fixture
def complete_hello_pcap(tmp_path) -> str:
    p = tmp_path / "complete_hello.pcap"
    wrpcap(str(p), _build_tls_packets())
    return str(p)


# ─── Independent reference capture (Wireshark tls13-rfc8446) ────────────────

_REFERENCE_FIXTURE = Path(__file__).parent / "fixtures" / "wireshark_tls13_rfc8446.json"


def _reference_frames() -> dict:
    import json
    return json.loads(_REFERENCE_FIXTURE.read_text())["frames"]


def _reference_packet(frame_no: int, ts: float | None = None):
    meta = _reference_frames()[str(frame_no)]
    pkt = (
        Ether(src=_ETHER_SRC, dst=_ETHER_DST)
        / IP(src=meta["src"], dst=meta["dst"], ttl=64)
        / TCP(sport=meta["sport"], dport=meta["dport"], flags="PA",
              seq=meta["seq"], ack=1)
        / Raw(load=bytes.fromhex(meta["payload"]))
    )
    pkt.time = meta["ts"] if ts is None else ts
    return pkt


@pytest.fixture
def wireshark_tls13_client_hellos_pcap(tmp_path) -> str:
    """Wireshark frames 1 and 7: two ClientHellos in separate TCP streams.

    Independent of this project's fixture builder. Expected JA3 values are
    published next to the pinned upstream commit; see
    ``tests/test_fingerprint_ja3.py``.
    """
    p = tmp_path / "wireshark_tls13_client_hellos.pcap"
    wrpcap(str(p), [_reference_packet(1), _reference_packet(7)])
    return str(p)


@pytest.fixture
def server_first_pcap(tmp_path) -> str:
    """Upstream frames 2–6: recording begins on the server side.

    Frame 1 of the excerpt is a ServerHello from 10.9.0.2:443. There is no
    ClientHello in the excerpt, so no client handshake may be invented.
    """
    p = tmp_path / "server_first.pcap"
    wrpcap(str(p), [_reference_packet(n) for n in (2, 3, 4, 5, 6)])
    return str(p)
