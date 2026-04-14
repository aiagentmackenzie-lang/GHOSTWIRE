"""MITRE ATT&CK mapping — map detections to tactics and techniques."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ATT&CK tactic ordering (enterprise)
TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Technique to tactic mapping
TECHNIQUE_MAP: dict[str, dict] = {
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "C2 communication over HTTP/HTTPS",
    },
    "T1071.004": {
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "description": "C2 communication over DNS",
    },
    "T1573.001": {
        "name": "Encrypted Channel: Symmetric Cryptography",
        "tactic": "Command and Control",
        "description": "Encrypted C2 using symmetric ciphers",
    },
    "T1573.002": {
        "name": "Encrypted Channel: Asymmetric Cryptography",
        "tactic": "Command and Control",
        "description": "Encrypted C2 using asymmetric ciphers (TLS)",
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "PowerShell execution via C2",
    },
    "T1021.001": {
        "name": "Remote Services: RDP",
        "tactic": "Lateral Movement",
        "description": "Remote Desktop Protocol lateral movement",
    },
    "T1021.004": {
        "name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
        "description": "SSH lateral movement or C2 tunneling",
    },
    "T1571": {
        "name": "Non-Standard Port",
        "tactic": "Command and Control",
        "description": "C2 communication on non-standard ports",
    },
    "T1095": {
        "name": "Non-Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "C2 over TCP/UDP without application-layer protocol",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Data exfiltration over existing C2 connection",
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Data exfiltration over DNS/ICMP",
    },
    "T1001": {
        "name": "Data Obfuscation",
        "tactic": "Command and Control",
        "description": "Obfuscated C2 communication",
    },
    "T1568": {
        "name": "Dynamic Resolution",
        "tactic": "Command and Control",
        "description": "Dynamic resolution (fast flux, DGA)",
    },
    "T1568.002": {
        "name": "Dynamic Resolution: Domain Generation Algorithms",
        "tactic": "Command and Control",
        "description": "DGA-generated domains for C2",
    },
}


@dataclass
class AttackMapping:
    """MITRE ATT&CK mapping for a detection."""
    technique_id: str
    technique_name: str
    tactic: str
    tactic_order: int = 0
    description: str = ""
    confidence: float = 0.0
    evidence: str = ""
    url: str = ""

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "tactic_order": self.tactic_order,
            "description": self.description,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "url": self.url or f"https://attack.mitre.org/techniques/{self.technique_id.replace('.', '/')}",
        }


def map_techniques(technique_ids: list[str], evidence: str = "", confidence: float = 0.0) -> list[AttackMapping]:
    """Map technique IDs to full ATT&CK details.

    Args:
        technique_ids: List of MITRE technique IDs (e.g. ["T1071.001"])
        evidence: What was detected that maps to these techniques
        confidence: Detection confidence (0.0-1.0)

    Returns:
        List of AttackMapping objects sorted by tactic order.
    """
    mappings: list[AttackMapping] = []

    for tech_id in technique_ids:
        info = TECHNIQUE_MAP.get(tech_id, {})
        tactic = info.get("tactic", "Unknown")
        tactic_order = TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else 99

        mappings.append(AttackMapping(
            technique_id=tech_id,
            technique_name=info.get("name", f"Technique {tech_id}"),
            tactic=tactic,
            tactic_order=tactic_order,
            description=info.get("description", ""),
            confidence=confidence,
            evidence=evidence,
        ))

    # Sort by tactic order
    mappings.sort(key=lambda m: m.tactic_order)
    return mappings


def map_analysis_to_attack(analysis: dict) -> list[AttackMapping]:
    """Map an entire GHOSTWIRE analysis result to MITRE ATT&CK.

    Extracts all technique IDs from threats and creates structured mappings.
    """
    all_techniques: dict[str, AttackMapping] = {}

    for threat in analysis.get("threats", []):
        for tech_id in threat.get("mitre_techniques", []):
            if tech_id not in all_techniques:
                mappings = map_techniques(
                    [tech_id],
                    evidence=threat.get("summary", ""),
                    confidence=threat.get("overall_score", 0.0),
                )
                if mappings:
                    all_techniques[tech_id] = mappings[0]

    return sorted(all_techniques.values(), key=lambda m: m.tactic_order)