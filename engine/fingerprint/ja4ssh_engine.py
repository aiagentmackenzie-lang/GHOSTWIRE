"""JA4SSH SSH fingerprinting.

JA4SSH fingerprints SSH client behavior from the key exchange and
banner exchange phases — useful for identifying SSH-based C2 tunnels.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

_SSH_BANNER_RE = re.compile(rb"^SSH-(\d+\.\d+)-(.+)\r?\n")

# SSH packet types
_SSH_MSG_KEXINIT = 20
_SSH_MSG_NEWKEYS = 21


@dataclass
class SSHFingerprint:
    """JA4SSH-style SSH fingerprint result."""
    ja4ssh: str = ""
    client_banner: str = ""
    server_banner: str = ""
    ssh_version: str = ""
    client_software: str = ""
    kex_algorithms: list[str] = None
    host_key_algorithms: list[str] = None
    encryption_algorithms: list[str] = None
    mac_algorithms: list[str] = None
    compression_algorithms: list[str] = None
    source_ip: str = ""
    destination_ip: str = ""
    is_client: bool = False

    def __post_init__(self):
        if self.kex_algorithms is None:
            self.kex_algorithms = []
        if self.host_key_algorithms is None:
            self.host_key_algorithms = []
        if self.encryption_algorithms is None:
            self.encryption_algorithms = []
        if self.mac_algorithms is None:
            self.mac_algorithms = []
        if self.compression_algorithms is None:
            self.compression_algorithms = []

    def to_dict(self) -> dict:
        return {
            "ja4ssh": self.ja4ssh,
            "client_banner": self.client_banner,
            "ssh_version": self.ssh_version,
            "client_software": self.client_software,
            "kex_count": len(self.kex_algorithms),
            "host_key_count": len(self.host_key_algorithms),
            "enc_count": len(self.encryption_algorithms),
        }


def _parse_kexinit(payload: bytes) -> Optional[dict]:
    """Parse SSH_MSG_KEXINIT packet to extract algorithm lists."""
    if len(payload) < 6:
        return None

    try:
        # SSH packet: packet_length(4) + padding_length(1) + msg_code(1) + ...
        msg_type = payload[5]
        if msg_type != _SSH_MSG_KEXINIT:
            return None

        offset = 6 + 16  # Skip msg_type + cookie (16 bytes)
        algorithms = {}
        algo_names = [
            "kex_algorithms", "server_host_key_algorithms",
            "encryption_algorithms_client_to_server", "encryption_algorithms_server_to_client",
            "mac_algorithms_client_to_server", "mac_algorithms_server_to_client",
            "compression_algorithms_client_to_server", "compression_algorithms_server_to_client",
            "languages_client_to_server", "languages_server_to_client",
        ]

        for name in algo_names:
            if offset + 3 >= len(payload):
                break
            name_len = int.from_bytes(payload[offset:offset+4], "big")
            offset += 4
            if offset + name_len > len(payload):
                break
            algo_list = payload[offset:offset+name_len].decode("utf-8", errors="replace").split(",")
            algorithms[name] = algo_list
            offset += name_len

        return algorithms

    except (IndexError, UnicodeDecodeError) as e:
        logger.debug(f"KEXINIT parse failed: {e}")
        return None


def fingerprint_ssh(payload: bytes, *, src_ip: str = "", dst_ip: str = "") -> Optional[SSHFingerprint]:
    """Extract SSH fingerprint from raw payload.

    Checks for SSH banner exchange and KEXINIT algorithm lists.
    """
    if not payload:
        return None

    fp = SSHFingerprint(source_ip=src_ip, destination_ip=dst_ip)

    # Check for SSH banner
    banner_match = _SSH_BANNER_RE.match(payload)
    if banner_match:
        fp.is_client = True
        fp.ssh_version = banner_match.group(1).decode("utf-8", errors="replace")
        fp.client_software = banner_match.group(2).decode("utf-8", errors="replace").strip()
        fp.client_banner = f"SSH-{fp.ssh_version}-{fp.client_software}"

        # Simple hash from banner for fingerprint
        banner_hash = hashlib.md5(fp.client_banner.encode()).hexdigest()[:12]
        fp.ja4ssh = f"ssh{fp.ssh_version.replace('.', '')}_{banner_hash}"
        return fp

    # Check for KEXINIT
    if len(payload) > 5 and payload[5] == _SSH_MSG_KEXINIT:
        fp.is_client = False
        algorithms = _parse_kexinit(payload)
        if algorithms:
            fp.kex_algorithms = algorithms.get("kex_algorithms", [])
            fp.host_key_algorithms = algorithms.get("server_host_key_algorithms", [])
            fp.encryption_algorithms = algorithms.get("encryption_algorithms_client_to_server", [])
            fp.mac_algorithms = algorithms.get("mac_algorithms_client_to_server", [])
            fp.compression_algorithms = algorithms.get("compression_algorithms_client_to_server", [])

            # Build fingerprint hash from algorithm order
            algo_str = ",".join(fp.kex_algorithms[:5]) + "," + ",".join(fp.encryption_algorithms[:3])
            algo_hash = hashlib.md5(algo_str.encode()).hexdigest()[:12]
            fp.ja4ssh = f"ssh_kex_{algo_hash}"

        return fp

    return None


def fingerprint_stream(packets: list) -> list[SSHFingerprint]:
    """Scan packets for SSH traffic and extract fingerprints."""
    fingerprints: list[SSHFingerprint] = []

    for pkt in packets:
        if pkt.protocol_l4 != "TCP" or not pkt.raw_payload:
            continue
        # Only check port 22 or SSH-looking payloads
        if pkt.src_port == 22 or pkt.dst_port == 22 or pkt.raw_payload.startswith(b"SSH-"):
            fp = fingerprint_ssh(pkt.raw_payload, src_ip=pkt.src_ip, dst_ip=pkt.dst_ip)
            if fp:
                fingerprints.append(fp)

    logger.info(f"Extracted {len(fingerprints)} SSH fingerprints")
    return fingerprints