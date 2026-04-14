"""STIX 2.1 IOC export — industry standard threat intelligence sharing format."""

from __future__ import annotations

import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


def _stix_id(obj_type: str) -> str:
    """Generate a STIX 2.1 compliant ID."""
    return f"{obj_type}--{uuid.uuid4()}"


def _now() -> str:
    """ISO 8601 timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def build_stix_bundle(
    iocs: list[dict],
    description: str = "GHOSTWIRE automated analysis",
    source_file: str = "",
) -> dict:
    """Build a STIX 2.1 Bundle from GHOSTWIRE IOC data.

    Args:
        iocs: List of IOC dicts with keys: type, value, confidence, threat_type, mitre_techniques
        description: Bundle description
        source_file: Original PCAP file path

    Returns:
        STIX 2.1 Bundle as dict (serializable to JSON)
    """
    objects: list[dict] = []
    created = _now()

    # Author identity
    author_id = _stix_id("identity")
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": author_id,
        "created": created,
        "modified": created,
        "name": "GHOSTWIRE",
        "identity_class": "software",
        "description": "GHOSTWIRE Network Forensics Engine",
    })

    # Indicator objects for each IOC
    for ioc in iocs:
        ioc_type = ioc.get("type", "")
        value = ioc.get("value", "")
        confidence = ioc.get("confidence", 0)
        threat_type = ioc.get("threat_type", "unknown")
        mitre_techniques = ioc.get("mitre_techniques", [])

        if not value:
            continue

        indicator_id = _stix_id("indicator")

        # Build STIX pattern based on IOC type
        if ioc_type == "ipv4-addr" or _looks_like_ip(value):
            pattern = f"[ipv4-addr:value = '{value}']"
        elif ioc_type == "domain-name" or _looks_like_domain(value):
            pattern = f"[domain-name:value = '{value}']"
        elif ioc_type == "url":
            pattern = f"[url:value = '{value}']"
        elif ioc_type == "file-hash":
            pattern = f"[file:hashes.'SHA-256' = '{value}']"
        elif "ja4" in ioc_type.lower() or "ja3" in ioc_type.lower():
            pattern = f"[x-ghostwire-tls-fingerprint:value = '{value}']"
        else:
            pattern = f"[x-ghostwire-ioc:value = '{value}']"

        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created_by_ref": author_id,
            "created": created,
            "modified": created,
            "name": f"GHOSTWIRE: {threat_type} - {value}",
            "description": ioc.get("description", f"Detected {threat_type}: {value}"),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": created,
            "confidence": min(int(confidence * 100), 100),
            "labels": [threat_type],
        }
        objects.append(indicator)

        # MITRE ATT&CK attack patterns
        for tech_id in mitre_techniques:
            attack_id = _stix_id("attack-pattern")
            objects.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": attack_id,
                "created_by_ref": author_id,
                "created": created,
                "modified": created,
                "name": _mitre_name(tech_id),
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": tech_id,
                    "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}",
                }],
            })

            # Relationship: indicator indicates attack pattern
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": _stix_id("relationship"),
                "created_by_ref": author_id,
                "created": created,
                "modified": created,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": attack_id,
            })

    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": objects,
    }

    if source_file:
        bundle["description"] = f"GHOSTWIRE analysis of {source_file}"

    logger.info(f"Built STIX 2.1 bundle with {len(objects)} objects")
    return bundle


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _looks_like_domain(value: str) -> bool:
    return "." in value and not _looks_like_ip(value) and "/" not in value


def _mitre_name(tech_id: str) -> str:
    """Map MITRE technique IDs to human-readable names."""
    mitre_map = {
        "T1071.001": "Application Layer Protocol: Web Protocols",
        "T1071.004": "Application Layer Protocol: DNS",
        "T1573.001": "Encrypted Channel: Symmetric Cryptography",
        "T1573.002": "Encrypted Channel: Asymmetric Cryptography",
        "T1571": "Non-Standard Port",
        "T1059.001": "Command and Scripting Interpreter: PowerShell",
        "T1021.001": "Remote Services: Remote Desktop Protocol",
        "T1021.004": "Remote Services: SSH",
        "T1095": "Non-Application Layer Protocol",
        "T1041": "Exfiltration Over C2 Channel",
        "T1048": "Exfiltration Over Alternative Protocol",
        "T1001": "Data Obfuscation",
        "T1568": "Dynamic Resolution",
        "T1568.002": "Dynamic Resolution: Domain Generation Algorithms",
    }
    return mitre_map.get(tech_id, f"MITRE ATT&CK {tech_id}")


def export_stix(bundle: dict, filepath: str) -> None:
    """Write STIX bundle to JSON file."""
    with open(filepath, "w") as f:
        json.dump(bundle, f, indent=2)
    logger.info(f"STIX bundle exported to {filepath}")


def iocs_from_analysis(analysis: dict) -> list[dict]:
    """Convert GHOSTWIRE analysis results into IOC dicts for STIX export."""
    iocs: list[dict] = []

    for threat in analysis.get("threats", []):
        target = threat.get("target", "")

        # Extract IPs from session target
        parts = target.split("-")
        for part in parts:
            ip_port = part.split(":")
            if len(ip_port) >= 1 and _looks_like_ip(ip_port[0]):
                iocs.append({
                    "type": "ipv4-addr",
                    "value": ip_port[0],
                    "confidence": threat.get("overall_score", 0),
                    "threat_type": "c2_communication",
                    "mitre_techniques": threat.get("mitre_techniques", []),
                    "description": threat.get("summary", ""),
                })

        # Extract domains from DNS threats
        for dns in threat.get("dns_threats", []):
            domain = dns.get("domain", "")
            if domain:
                iocs.append({
                    "type": "domain-name",
                    "value": domain,
                    "confidence": dns.get("score", 0),
                    "threat_type": dns.get("threat_type", "dns_threat"),
                    "mitre_techniques": threat.get("mitre_techniques", []),
                    "description": f"DNS {dns.get('threat_type', 'threat')}: {domain}",
                })

        # Extract C2 matches as fingerprint IOCs
        for c2 in threat.get("c2_matches", []):
            iocs.append({
                "type": "x-ghostwire-c2-fingerprint",
                "value": c2.get("matched_value", ""),
                "confidence": c2.get("confidence", 0),
                "threat_type": "c2_tool",
                "mitre_techniques": c2.get("mitre_techniques", []),
                "description": f"Known C2 tool: {c2.get('tool_name', 'unknown')}",
            })

    return iocs