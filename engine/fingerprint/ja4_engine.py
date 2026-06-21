"""JA4+ TLS fingerprinting engine.

Uses the ja4plus library for JA4/JA4S fingerprint extraction from TLS
handshakes. Falls back to a spec-compliant manual JA3 hash when ja4plus is
unavailable.

ja4plus API notes (verified against installed ja4plus 0.4):
  - generate_ja4(tls_info: dict) -> str|None      # dict from parse_tls_handshake
  - generate_ja4s(packet: scapy) -> str|None      # needs a scapy packet
  - ja4plus.utils.tls_utils.parse_tls_handshake(raw_bytes) -> dict|None

So JA4 (Client Hello) is driven through the dict API, and JA4S (Server Hello)
through a reconstructed scapy packet. The manual JA3 fallback parses
supported_groups (0x000a) and ec_point_formats (0x000b) so its hash matches
the standard JA3 format (TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats).
"""

from __future__ import annotations

import hashlib
import logging
import struct
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# ─── Optional dependencies ────────────────────────────────────────────────
_HAS_JA4PLUS = False
try:
    import ja4plus
    from ja4plus.utils.tls_utils import parse_tls_handshake
    _HAS_JA4PLUS = True
except ImportError:
    logger.warning("ja4plus not installed — JA4+ fingerprinting will use JA3 fallback")

_HAS_SCAPY = False
try:
    from scapy.all import IP as ScapyIP, TCP as ScapyTCP, Raw as ScapyRaw
    _HAS_SCAPY = True
except ImportError:
    pass  # JA4S path degrades; JA4 dict path still works


@dataclass
class TLSFingerprint:
    """TLS fingerprint result."""
    ja4: str = ""
    ja4s: str = ""
    ja3_hash: str = ""  # Fallback / supplementary
    sni: str = ""
    tls_version: str = ""
    cipher_count: int = 0
    ext_count: int = 0
    is_client_hello: bool = False
    is_server_hello: bool = False
    source_ip: str = ""
    destination_ip: str = ""
    source_port: int = 0
    destination_port: int = 0

    def to_dict(self) -> dict:
        return {
            "ja4": self.ja4,
            "ja4s": self.ja4s,
            "ja3_hash": self.ja3_hash,
            "sni": self.sni,
            "tls_version": self.tls_version,
            "cipher_count": self.cipher_count,
            "ext_count": self.ext_count,
            "direction": "client_hello" if self.is_client_hello else "server_hello" if self.is_server_hello else "unknown",
        }


# ─── Manual parsing helpers (used by JA3 fallback + SNI when ja4plus absent) ──

def _walk_client_hello(payload: bytes) -> Optional[dict]:
    """Parse a TLS ClientHello into structured fields.

    Offsets (TLS record = content_type(1) + version(2) + length(2) = 5 bytes;
    handshake header = type(1) + length(3) = 4 bytes; ClientHello body starts
    at byte 9). Returns None if not a parseable ClientHello.

    Returns dict with: version, ciphers, extensions, supported_groups,
    ec_point_formats, sni.
    """
    if len(payload) < 9 or payload[0] != 0x16 or payload[5] != 0x01:
        return None

    try:
        offset = 5 + 4  # record header (5) + handshake header (4) = ClientHello body
        # Client version (2) + random (32)
        ch_version = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2 + 32
        # Session ID
        if offset >= len(payload):
            return None
        sid_len = payload[offset]
        offset += 1 + sid_len
        # Cipher suites
        if offset + 1 >= len(payload):
            return None
        cs_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2
        ciphers: list[int] = []
        for _ in range(cs_len // 2):
            if offset + 1 >= len(payload):
                break
            ciphers.append(struct.unpack("!H", payload[offset:offset + 2])[0])
            offset += 2
        # Compression methods
        if offset >= len(payload):
            return None
        comp_len = payload[offset]
        offset += 1 + comp_len
        # Extensions
        extensions: list[int] = []
        supported_groups: list[int] = []
        ec_point_formats: list[int] = []
        sni = ""
        if offset + 1 < len(payload):
            ext_total = struct.unpack("!H", payload[offset:offset + 2])[0]
            offset += 2
            ext_end = min(offset + ext_total, len(payload))
            while offset + 4 <= ext_end:
                ext_type = struct.unpack("!H", payload[offset:offset + 2])[0]
                ext_len = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
                ext_data_start = offset + 4
                ext_data_end = ext_data_start + ext_len
                extensions.append(ext_type)

                if ext_type == 0x0000 and ext_data_end <= len(payload):
                    # SNI: server_name_list_len(2) + type(1) + len(2) + name
                    if ext_len >= 5:
                        sni_type = payload[ext_data_start + 2]
                        sni_len = struct.unpack("!H", payload[ext_data_start + 3:ext_data_start + 5])[0]
                        if sni_type == 0 and ext_data_start + 5 + sni_len <= ext_data_end:
                            sni = payload[ext_data_start + 5:ext_data_start + 5 + sni_len].decode("utf-8", errors="replace")
                elif ext_type == 0x000a and ext_data_end <= len(payload):
                    # supported_groups: list_len(2) + group IDs (2 bytes each)
                    if ext_len >= 2:
                        glist_len = struct.unpack("!H", payload[ext_data_start:ext_data_start + 2])[0]
                        goff = ext_data_start + 2
                        gend = min(ext_data_start + 2 + glist_len, ext_data_end)
                        while goff + 2 <= gend:
                            supported_groups.append(struct.unpack("!H", payload[goff:goff + 2])[0])
                            goff += 2
                elif ext_type == 0x000b and ext_data_end <= len(payload):
                    # ec_point_formats: list_len(1) + format IDs (1 byte each)
                    if ext_len >= 1:
                        flist_len = payload[ext_data_start]
                        foff = ext_data_start + 1
                        fend = min(ext_data_start + 1 + flist_len, ext_data_end)
                        while foff < fend:
                            ec_point_formats.append(payload[foff])
                            foff += 1

                offset = ext_data_end

        return {
            "version": ch_version,
            "ciphers": ciphers,
            "extensions": extensions,
            "supported_groups": supported_groups,
            "ec_point_formats": ec_point_formats,
            "sni": sni,
        }
    except (struct.error, IndexError) as e:
        logger.debug(f"ClientHello parse failed: {e}")
        return None


def _compute_ja3(parsed: dict) -> str:
    """Compute a spec-compliant JA3 hash.

    JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
    All five fields are populated from the parsed ClientHello, so the hash
    matches the format published in JA3er / public datasets.
    """
    full = f"{parsed['version']},{','.join(str(c) for c in parsed['ciphers'])},{','.join(str(e) for e in parsed['extensions'])},{','.join(str(g) for g in parsed['supported_groups'])},{','.join(str(f) for f in parsed['ec_point_formats'])}"
    return hashlib.md5(full.encode()).hexdigest()


def _scapy_packet_from_payload(payload: bytes, src_ip: str, dst_ip: str,
                               src_port: int, dst_port: int):
    """Reconstruct a minimal scapy IP/TCP packet carrying `payload`.

    Used for ja4plus APIs that require a scapy packet (generate_ja4s).
    """
    if not _HAS_SCAPY:
        return None
    try:
        return ScapyIP(src=src_ip or "0.0.0.0", dst=dst_ip or "0.0.0.0") / \
               ScapyTCP(sport=src_port, dport=dst_port) / ScapyRaw(load=payload)
    except Exception as e:
        logger.debug(f"scapy packet reconstruction failed: {e}")
        return None


def fingerprint_tls(payload: bytes, *, src_ip: str = "", dst_ip: str = "",
                     src_port: int = 0, dst_port: int = 0) -> Optional[TLSFingerprint]:
    """Extract JA4+/JA3 fingerprints from a TLS handshake payload.

    Args:
        payload: Raw TLS record bytes.
        src_ip, dst_ip, src_port, dst_port: Connection metadata.

    Returns:
        TLSFingerprint if a TLS handshake is detected, None otherwise.
    """
    if len(payload) < 5 or payload[0] != 0x16:
        return None  # Not a TLS handshake record

    fp = TLSFingerprint(
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=src_port,
        destination_port=dst_port,
    )

    # Record-layer version (always available, even without full parsing)
    if len(payload) >= 3:
        ver = struct.unpack("!H", payload[1:3])[0]
        version_map = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
        fp.tls_version = version_map.get(ver, f"0x{ver:04x}")

    handshake_type = payload[5] if len(payload) > 5 else 0

    # ── Client Hello: JA4 via dict API ──
    if handshake_type == 0x01:
        fp.is_client_hello = True

        if _HAS_JA4PLUS:
            try:
                info = parse_tls_handshake(payload)
                if info and info.get("type") == "client_hello":
                    ja4 = ja4plus.generate_ja4(info)
                    if ja4:
                        fp.ja4 = ja4
                    fp.sni = info.get("sni") or ""
                    fp.cipher_count = len(info.get("ciphers", []))
                    fp.ext_count = len(info.get("extensions", []))
                    if info.get("supported_versions"):
                        non_grease = [v for v in info["supported_versions"] if v < 0x0a0a or v > 0x0a0a]
                        sv = max(non_grease) if non_grease else info.get("version", ver)
                        fp.tls_version = version_map.get(sv, fp.tls_version)
            except Exception as e:
                logger.debug(f"ja4plus generate_ja4 failed: {e}")

        # JA3 fallback / supplement (always compute so JA3-based C2 DB matching works)
        parsed = _walk_client_hello(payload)
        if parsed:
            if not fp.sni:
                fp.sni = parsed["sni"]
            if not fp.cipher_count:
                fp.cipher_count = len(parsed["ciphers"])
            if not fp.ext_count:
                fp.ext_count = len(parsed["extensions"])
            fp.ja3_hash = _compute_ja3(parsed)

        return fp

    # ── Server Hello: JA4S via scapy packet ──
    if handshake_type == 0x02:
        fp.is_server_hello = True

        if _HAS_JA4PLUS and _HAS_SCAPY:
            pkt = _scapy_packet_from_payload(payload, src_ip, dst_ip, src_port, dst_port)
            if pkt is not None:
                try:
                    ja4s = ja4plus.generate_ja4s(pkt)
                    if ja4s:
                        fp.ja4s = ja4s
                except Exception as e:
                    logger.debug(f"ja4plus generate_ja4s failed: {e}")

        return fp

    # Other handshake types — record version only
    return fp


def fingerprint_stream(packets: list) -> list[TLSFingerprint]:
    """Scan a list of packet records for TLS handshakes and extract fingerprints.

    Args:
        packets: List of PacketRecord objects.

    Returns:
        List of TLSFingerprint objects found.
    """
    fingerprints: list[TLSFingerprint] = []

    for pkt in packets:
        if pkt.protocol_l4 != "TCP" or not pkt.raw_payload:
            continue

        if len(pkt.raw_payload) >= 5 and pkt.raw_payload[0] == 0x16:
            fp = fingerprint_tls(
                pkt.raw_payload,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
            )
            if fp:
                fingerprints.append(fp)

    logger.info(f"Extracted {len(fingerprints)} TLS fingerprints")
    return fingerprints