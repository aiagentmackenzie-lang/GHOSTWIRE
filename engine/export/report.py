"""Report generator — Markdown and text reports from GHOSTWIRE analysis."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from engine.export.mitre_map import map_analysis_to_attack

logger = logging.getLogger(__name__)


def generate_markdown_report(analysis: dict) -> str:
    """Generate a Markdown threat analysis report.

    Args:
        analysis: GHOSTWIRE analysis JSON dict.

    Returns:
        Markdown string.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    threats = analysis.get("threats", [])

    lines: list[str] = []

    # Header
    lines.append("# GHOSTWIRE Network Forensics Report")
    lines.append("")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Version:** {analysis.get('ghostwire_version', 'unknown')}")
    lines.append(f"**Source File:** `{analysis.get('file', 'N/A')}`")
    lines.append(f"**Analysis Time:** {analysis.get('analysis_time', 0):.2f}s")
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    crit = sum(1 for t in threats if t.get("confidence") == "CRITICAL")
    high = sum(1 for t in threats if t.get("confidence") == "HIGH")
    med = sum(1 for t in threats if t.get("confidence") == "MEDIUM")
    low = sum(1 for t in threats if t.get("confidence") in ("LOW", "NEGLIGIBLE"))

    if crit + high > 0:
        lines.append(f"⚠️ **CRITICAL: {crit + high} high-confidence threats detected** requiring immediate investigation.")
    elif med > 0:
        lines.append(f"🔍 **{med} medium-confidence threats detected** — further investigation recommended.")
    else:
        lines.append("✅ No significant threats detected in this capture.")

    lines.append("")
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|-------|")
    lines.append(f"| CRITICAL | {crit} |")
    lines.append(f"| HIGH | {high} |")
    lines.append(f"| MEDIUM | {med} |")
    lines.append(f"| LOW | {low} |")
    lines.append("")

    # Overview Stats
    lines.append("## Capture Overview")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total Packets | {analysis.get('packets_total', 0):,} |")
    lines.append(f"| TCP Sessions | {analysis.get('sessions_total', 0):,} |")
    lines.append(f"| TLS Fingerprints | {analysis.get('tls_fingerprints', 0):,} |")
    lines.append(f"| HTTP Fingerprints | {analysis.get('http_fingerprints', 0):,} |")
    lines.append(f"| SSH Fingerprints | {analysis.get('ssh_fingerprints', 0):,} |")
    lines.append(f"| C2 Matches | {analysis.get('c2_matches', 0):,} |")
    lines.append(f"| Beacons Detected | {analysis.get('beacons_detected', 0):,} |")
    lines.append(f"| DNS Threats | {analysis.get('dns_threats', 0):,} |")
    lines.append("")

    # Threat Details
    if threats:
        lines.append("## Threat Details")
        lines.append("")

        for i, t in enumerate(threats, 1):
            confidence = t.get("confidence", "UNKNOWN")
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(confidence, "⚪")

            lines.append(f"### {emoji} Threat #{i} — {confidence}")
            lines.append("")
            lines.append(f"**Target:** `{t.get('target', 'N/A')}`")
            lines.append(f"**Score:** {t.get('overall_score', 0):.3f}")
            lines.append(f"**Summary:** {t.get('summary', 'N/A')}")
            lines.append("")

            if t.get("beacon_score"):
                lines.append(f"**Beacon Score:** {t['beacon_score']:.1%}")
                lines.append("")

            # IOCs
            if t.get("iocs"):
                lines.append("**Indicators of Compromise:**")
                for ioc in t["iocs"]:
                    lines.append(f"- `{ioc}`")
                lines.append("")

            # C2 Matches
            if t.get("c2_matches"):
                lines.append("**C2 Tool Matches:**")
                for c2 in t["c2_matches"]:
                    lines.append(f"- **{c2.get('tool_name', 'unknown')}** (confidence: {c2.get('confidence', 0):.0%}, via {c2.get('match_type', 'unknown')})")
                lines.append("")

            # DNS Threats
            if t.get("dns_threats"):
                lines.append("**DNS Threats:**")
                for dns in t["dns_threats"]:
                    lines.append(f"- `{dns.get('domain', '')}` — {dns.get('threat_type', '')} (score: {dns.get('score', 0):.2f})")
                lines.append("")

    # MITRE ATT&CK
    attack_mappings = map_analysis_to_attack(analysis)
    if attack_mappings:
        lines.append("## MITRE ATT&CK Mapping")
        lines.append("")
        lines.append("| Tactic | Technique | ID | Confidence |")
        lines.append("|--------|-----------|----|------------|")
        for m in attack_mappings:
            lines.append(f"| {m.tactic} | {m.technique_name} | {m.technique_id} | {m.confidence:.0%} |")
        lines.append("")

    # Recommendations
    lines.append("## Recommendations")
    lines.append("")
    if crit + high > 0:
        lines.append("1. **Immediate:** Investigate all CRITICAL and HIGH confidence threats")
        lines.append("2. **Block** identified C2 IP addresses at the firewall")
        lines.append("3. **Hunt** for lateral movement from compromised hosts")
        lines.append("4. **Review** DNS logs for DGA domain resolution attempts")
    elif med > 0:
        lines.append("1. **Review** medium-confidence threats for false positives")
        lines.append("2. **Monitor** flagged sessions for behavioral changes")
        lines.append("3. **Correlate** with endpoint detection data")
    else:
        lines.append("1. No immediate action required")
        lines.append("2. Archive this report for baseline comparison")
    lines.append("")

    # Footer
    lines.append("---")
    lines.append(f"*Report generated by GHOSTWIRE v{analysis.get('ghostwire_version', 'unknown')}*")
    lines.append(f"*The wire remembers everything.*")

    return "\n".join(lines)


def generate_text_report(analysis: dict) -> str:
    """Generate a plain-text summary report."""
    threats = analysis.get("threats", [])
    high_threats = [t for t in threats if t.get("confidence") in ("CRITICAL", "HIGH")]

    lines = [
        "GHOSTWIRE ANALYSIS REPORT",
        "=" * 40,
        f"File: {analysis.get('file', 'N/A')}",
        f"Packets: {analysis.get('packets_total', 0):,}",
        f"Sessions: {analysis.get('sessions_total', 0):,}",
        f"Threats: {len(threats)} ({len(high_threats)} high confidence)",
        "",
    ]

    for t in threats[:10]:
        conf = t.get("confidence", "?")
        score = t.get("overall_score", 0)
        lines.append(f"  [{conf}] {t.get('target', '?')} (score: {score:.2f})")
        lines.append(f"         {t.get('summary', '')}")
        if t.get("iocs"):
            lines.append(f"         IOCs: {', '.join(t.get('iocs', [])[:3])}")
        lines.append("")

    return "\n".join(lines)


def save_report(content: str, filepath: str) -> None:
    """Write report content to file."""
    with open(filepath, "w") as f:
        f.write(content)
    logger.info(f"Report saved to {filepath}")