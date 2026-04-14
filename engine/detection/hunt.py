"""Hunt Mode — interactive threat hunting with Python queries against parsed PCAP data."""

from __future__ import annotations

import json
import logging
from typing import Callable, Any

from engine.parser.pcap_loader import PacketRecord
from engine.parser.session import TCPSession

logger = logging.getLogger(__name__)

# Built-in hunt queries
BUILTIN_QUERIES: dict[str, dict] = {
    "suspicious_beacons": {
        "name": "Find Suspicious Beacons",
        "description": "Sessions with low jitter and consistent timing — likely C2",
        "category": "c2",
    },
    "cobalt_strike": {
        "name": "Find Cobalt Strike Beacons",
        "description": "Sessions matching Cobalt Strike JA4+ fingerprints or user agents",
        "category": "c2",
    },
    "dns_tunneling": {
        "name": "Find DNS Tunneling",
        "description": "DNS queries with high-entropy subdomains or unusual record types",
        "category": "dns",
    },
    "data_exfil": {
        "name": "Find Data Exfiltration",
        "description": "Sessions with large outbound data transfers",
        "category": "exfiltration",
    },
    "lateral_movement": {
        "name": "Find Lateral Movement",
        "description": "Internal-to-internal connections on suspicious ports",
        "category": "lateral",
    },
    "encrypted_c2": {
        "name": "Find Encrypted C2",
        "description": "TLS sessions to suspicious destinations with high entropy payloads",
        "category": "c2",
    },
}


def hunt_suspicious_beacons(sessions: list[TCPSession]) -> list[dict]:
    """Find sessions with beacon-like timing patterns."""
    results = []
    for s in sessions:
        if s.packet_count < 10:
            continue
        if not s.inter_arrival_times:
            continue

        import math
        iats = [i for i in s.inter_arrival_times if i > 1.0]
        if len(iats) < 3:
            continue

        mean = sum(iats) / len(iats)
        std = math.sqrt(sum((x - mean) ** 2 for x in iats) / len(iats))
        jitter = std / mean if mean > 0 else 0

        if jitter < 0.3 and s.duration > 60:
            results.append({
                "session_id": s.session_id,
                "jitter": round(jitter, 3),
                "iat_mean": round(mean, 1),
                "duration": round(s.duration, 1),
                "packets": s.packet_count,
                "protocol": s.protocol_l7,
                "reason": f"Low jitter ({jitter:.3f}) with sustained duration ({s.duration:.0f}s)",
            })

    return results


def hunt_cobalt_strike(sessions: list[TCPSession], packets: list[PacketRecord]) -> list[dict]:
    """Find sessions potentially using Cobalt Strike."""
    results = []

    # Check for CS user agents in HTTP traffic
    cs_user_agents = [
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0)",
        "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1)",
        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)",
    ]

    for pkt in packets:
        if pkt.protocol_l4 != "TCP" or not pkt.raw_payload:
            continue
        payload_str = pkt.raw_payload[:512].decode("utf-8", errors="replace")
        for ua in cs_user_agents:
            if ua in payload_str:
                results.append({
                    "source": f"{pkt.src_ip}:{pkt.src_port}",
                    "destination": f"{pkt.dst_ip}:{pkt.dst_port}",
                    "user_agent": ua,
                    "reason": f"Cobalt Strike default User-Agent detected",
                })

    # Check for CS default beacon interval (60s)
    for s in sessions:
        if s.packet_count < 10 or not s.inter_arrival_times:
            continue
        iats = [i for i in s.inter_arrival_times if i > 1.0]
        if not iats:
            continue
        mean = sum(iats) / len(iats)
        if 55 < mean < 65:  # ~60s interval = CS default
            results.append({
                "session_id": s.session_id,
                "interval": round(mean, 1),
                "reason": f"~60s beacon interval (Cobalt Strike default)",
            })

    return results


def hunt_dns_tunneling(packets: list[PacketRecord]) -> list[dict]:
    """Find DNS queries that may be tunneling data."""
    results = []

    for pkt in packets:
        if pkt.protocol_l7 != "DNS" or not pkt.raw_payload:
            continue

        proto = pkt.metadata.get("protocol_result", {}).get("dns")
        if not proto:
            continue

        domain = proto.get("query_name", "")
        qtype = proto.get("query_type", "A")

        # Unusual query types
        if qtype in ("TXT", "NULL", "ANY"):
            results.append({
                "source": f"{pkt.src_ip}:{pkt.src_port}",
                "domain": domain,
                "query_type": qtype,
                "reason": f"Unusual DNS query type: {qtype}",
            })

        # Long subdomain (data encoding)
        if domain:
            first_label = domain.split(".")[0]
            if len(first_label) > 20:
                import math
                freq: dict[str, int] = {}
                for c in first_label.lower():
                    freq[c] = freq.get(c, 0) + 1
                length = len(first_label)
                entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
                results.append({
                    "source": f"{pkt.src_ip}:{pkt.src_port}",
                    "domain": domain,
                    "subdomain_length": len(first_label),
                    "entropy": round(entropy, 2),
                    "reason": f"Long high-entropy subdomain ({len(first_label)} chars, entropy {entropy:.2f})",
                })

    return results


def hunt_data_exfil(sessions: list[TCPSession]) -> list[dict]:
    """Find sessions with large outbound data transfers."""
    results = []

    for s in sessions:
        if s.src_to_dst_bytes > 1_000_000:  # > 1MB outbound
            mb = s.src_to_dst_bytes / 1_000_000
            results.append({
                "session_id": s.session_id,
                "bytes_out": f"{mb:.1f} MB",
                "bytes_in": f"{s.dst_to_src_bytes / 1000:.1f} KB",
                "duration": f"{s.duration:.0f}s",
                "protocol": s.protocol_l7,
                "reason": f"Large outbound transfer ({mb:.1f} MB) — possible data exfiltration",
            })

    return results


def hunt_lateral_movement(sessions: list[TCPSession]) -> list[dict]:
    """Find internal-to-internal connections on suspicious ports."""
    suspicious_ports = {22, 23, 445, 3389, 5985, 5986, 513, 514, 25}
    private_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                        "172.30.", "172.31.", "192.168.")

    results = []
    for s in sessions:
        src_private = any(s.src_ip.startswith(p) for p in private_prefixes)
        dst_private = any(s.dst_ip.startswith(p) for p in private_prefixes)

        if src_private and dst_private:
            if s.dst_port in suspicious_ports or s.src_port in suspicious_ports:
                results.append({
                    "session_id": s.session_id,
                    "source": f"{s.src_ip}:{s.src_port}",
                    "destination": f"{s.dst_ip}:{s.dst_port}",
                    "protocol": s.protocol_l7,
                    "reason": f"Internal lateral movement on port {s.dst_port}",
                })

    return results


def hunt_encrypted_c2(sessions: list[TCPSession]) -> list[dict]:
    """Find TLS sessions to external IPs with high-entropy payloads."""
    private_prefixes = ("10.", "172.16.", "192.168.")
    results = []

    for s in sessions:
        dst_external = not any(s.dst_ip.startswith(p) for p in private_prefixes)
        if not dst_external:
            continue
        if s.protocol_l7 != "TLS" and s.dst_port not in (443, 8443):
            continue

        # Check payload entropy
        import math
        payload = s.client_payload[:4096] + s.server_payload[:4096]
        if not payload:
            continue

        freq: dict[int, int] = {}
        for b in payload:
            freq[b] = freq.get(b, 0) + 1
        length = len(payload)
        entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())

        if entropy > 7.5:
            results.append({
                "session_id": s.session_id,
                "destination": f"{s.dst_ip}:{s.dst_port}",
                "entropy": round(entropy, 2),
                "duration": f"{s.duration:.0f}s",
                "reason": f"Encrypted channel to external IP (entropy {entropy:.2f})",
            })

    return results


# Query execution mapping
QUERY_EXECUTORS: dict[str, Callable] = {
    "suspicious_beacons": hunt_suspicious_beacons,
    "cobalt_strike": hunt_cobalt_strike,
    "dns_tunneling": hunt_dns_tunneling,
    "data_exfil": hunt_data_exfil,
    "lateral_movement": hunt_lateral_movement,
    "encrypted_c2": hunt_encrypted_c2,
}


def run_hunt(query_name: str, sessions: list[TCPSession],
             packets: list[PacketRecord]) -> list[dict]:
    """Execute a hunt query by name.

    Args:
        query_name: One of the builtin query names
        sessions: Reconstructed TCP sessions
        packets: Raw packet records

    Returns:
        List of hunt result dicts
    """
    executor = QUERY_EXECUTORS.get(query_name)
    if not executor:
        logger.error(f"Unknown hunt query: {query_name}")
        return []

    logger.info(f"Running hunt query: {query_name}")

    # Some queries need sessions, some need packets, some need both
    import inspect
    sig = inspect.signature(executor)
    if len(sig.parameters) == 1:
        if "packets" in sig.parameters:
            return executor(packets)
        else:
            return executor(sessions)
    else:
        return executor(sessions, packets)


def run_all_hunts(sessions: list[TCPSession], packets: list[PacketRecord]) -> dict[str, list[dict]]:
    """Run all builtin hunt queries.

    Returns:
        Dict mapping query name to results list.
    """
    all_results: dict[str, list[dict]] = {}

    for name, meta in BUILTIN_QUERIES.items():
        results = run_hunt(name, sessions, packets)
        if results:
            all_results[name] = results
            logger.info(f"Hunt '{name}': {len(results)} findings")

    return all_results