"""JA4+ TLS fingerprinting engine.

Uses the ja4plus library for JA4/JA4S fingerprint extraction from TLS handshakes.
Falls back to manual JA3-style hashing if ja4plus is unavailable.
"""

from __future__ import annotations

import hashlib
import logging
import struct
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Try importing ja4plus
_HAS_JA4PLUS = False
try:
    import ja4plus
    _HAS_JA4PLUS = True
except ImportError:
    logger.warning("ja4plus not installed — JA4+ fingerprinting will use fallback mode")


@dataclass
class TLSFingerprint:
    """TLS fingerprint result."""
    ja4: str = ""
    ja4s: str = ""
    ja3_hash: str = ""  # Fallback
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


def _compute_ja3(payload: bytes) -> str:
    """Compute JA3 hash as fallback when ja4plus is not available.

    JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
    """
    try:
        if len(payload) < 44:
            return ""

        offset = 5 + 4  # TLS record header + handshake header

        # TLS version from ClientHello
        ch_version = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2 + 32  # version + random

        # Session ID
        if offset >= len(payload):
            return ""
        sid_len = payload[offset]
        offset += 1 + sid_len

        # Cipher suites
        if offset + 1 >= len(payload):
            return ""
        cs_len = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            if offset + 1 < len(payload):
                ciphers.append(struct.unpack("!H", payload[offset:offset+2])[0])
                offset += 2

        # Compression methods
        if offset >= len(payload):
            return ""
        comp_len = payload[offset]
        offset += 1 + comp_len

        # Extensions
        extensions = []
        if offset + 1 < len(payload):
            ext_total_len = struct.unpack("!H", payload[offset:offset+2])[0]
            offset += 2
            ext_end = offset + ext_total_len
            while offset + 3 < ext_end and offset + 3 < len(payload):
                ext_type = struct.unpack("!H", payload[offset:offset+2])[0]
                ext_data_len = struct.unpack("!H", payload[offset+2:offset+4])[0]
                extensions.append(ext_type)
                offset += 4 + ext_data_len

        # Build JA3 string
        ja3_str = f"{ch_version},{','.join(str(c) for c in ciphers)},{','.join(str(e) for e in extensions)},,,"
        return hashlib.md5(ja3_str.encode()).hexdigest()

    except (struct.error, IndexError) as e:
        logger.debug(f"JA3 computation failed: {e}")
        return ""


def fingerprint_tls(payload: bytes, *, src_ip: str = "", dst_ip: str = "",
                     src_port: int = 0, dst_port: int = 0) -> Optional[TLSFingerprint]:
    """Extract JA4+/JA3 fingerprints from a TLS handshake payload.

    Args:
        payload: Raw TLS record bytes.
        src_ip, dst_ip, src_port, dst_port: Connection metadata.

    Returns:
        TLSFingerprint if TLS handshake detected, None otherwise.
    """
    if len(payload) < 5 or payload[0] != 0x16:
        return None  # Not a TLS handshake

    fp = TLSFingerprint(
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=src_port,
        destination_port=dst_port,
    )

    # Try ja4plus first
    if _HAS_JA4PLUS:
        try:
            result = ja4plus.fingerprint_tls(payload)
            if result:
                if hasattr(result, "ja4"):
                    fp.ja4 = result.ja4 or ""
                if hasattr(result, "ja4s"):
                    fp.ja4s = result.ja4s or ""
                fp.is_client_hello = getattr(result, "is_client_hello", False)
                fp.is_server_hello = getattr(result, "is_server_hello", False)
                return fp
        except Exception as e:
            logger.debug(f"ja4plus failed, falling back: {e}")

    # Fallback: manual extraction
    if len(payload) > 5:
        hs_type = payload[5]
        if hs_type == 0x01:  # Client Hello
            fp.is_client_hello = True
            fp.ja3_hash = _compute_ja3(payload)
        elif hs_type == 0x02:  # Server Hello
            fp.is_server_hello = True

    # Extract version from record layer
    if len(payload) >= 3:
        ver = struct.unpack("!H", payload[1:3])[0]
        version_map = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
        fp.tls_version = version_map.get(ver, f"0x{ver:04x}")

    # Extract SNI
    if fp.is_client_hello:
        try:
            offset = 6 + 4 + 2 + 32  # handshake + version + random
            if offset < len(payload):
                sid_len = payload[offset]
                offset += 1 + sid_len
            if offset + 1 < len(payload):
                cs_len = struct.unpack("!H", payload[offset:offset+2])[0]
                fp.cipher_count = cs_len // 2
                offset += 2 + cs_len
            if offset < len(payload):
                comp_len = payload[offset]
                offset += 1 + comp_len
            if offset + 1 < len(payload):
                ext_total = struct.unpack("!H", payload[offset:offset+2])[0]
                fp.ext_count = 0
                offset += 2
                ext_end = offset + ext_total
                while offset + 4 < ext_end and offset + 4 < len(payload):
                    ext_type = struct.unpack("!H", payload[offset:offset+2])[0]
                    ext_len = struct.unpack("!H", payload[offset+2:offset+4])[0]
                    fp.ext_count += 1
                    if ext_type == 0x0000 and offset + 10 < len(payload):  # SNI
                        sni_type = payload[offset + 7]
                        sni_len = struct.unpack("!H", payload[offset+8:offset+10])[0]
                        if sni_type == 0 and offset + 10 + sni_len <= len(payload):
                            fp.sni = payload[offset+10:offset+10+sni_len].decode("utf-8", errors="replace")
                    offset += 4 + ext_len
        except (struct.error, IndexError):
            pass

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

        # Quick check for TLS handshake
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