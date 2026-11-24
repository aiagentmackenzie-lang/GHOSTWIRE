"""Report generator — Markdown and text reports from a GHOSTWIRE analysis.

A report has to distinguish three outcomes that used to look identical:

* a complete analysis in which no configured rule matched,
* a result filtered by the session threshold (findings exist, no session row
  qualifies),
* a partial or unsupported decode where "no findings" means "not examined".

Both renderers read the same versioned result the CLI prints as JSON, and fall
back to the legacy ``threats``-only shape when handed an older dict (so reports
generated from a saved 0.2.x summary still render, with missing detail marked).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from engine.export.mitre_map import map_analysis_to_attack

logger = logging.getLogger(__name__)

_COVERAGE_LABEL = {
    "complete": "Complete",
    "partial": "Partial",
    "unsupported_decode": "Unsupported decode",
    "empty": "Empty",
}


def _elapsed(analysis: dict) -> float | None:
    """Measured elapsed time, or None when the result never recorded one.

    A measured zero is a measurement ("< 1 ms"), not missing data: the old bug
    was a hard-coded zero on every report, which is why a *missing* key — not a
    zero value — is what maps to "unavailable".
    """
    value = analysis.get("analysis_time")
    report_meta = analysis.get("report") or {}
    if value is None and report_meta.get("elapsed_seconds") is not None:
        value = report_meta["elapsed_seconds"]
    if value is None:
        return None
    return float(value)


def _fmt_elapsed(analysis: dict) -> str:
    elapsed = _elapsed(analysis)
    return "unavailable" if elapsed is None else f"{elapsed:.3f}s"


def _coverage(analysis: dict) -> dict:
    return analysis.get("coverage") or {}


def _findings(analysis: dict) -> list[dict]:
    return analysis.get("findings") or []


def _run(analysis: dict) -> dict:
    return analysis.get("run") or {}


def _capture(analysis: dict) -> dict:
    return _run(analysis).get("capture") or {}


def _selection(analysis: dict) -> dict:
    return analysis.get("selection") or {}


def _observation_index(analysis: dict) -> dict[str, dict]:
    return {o.get("observation_id"): o for o in analysis.get("observations", [])}


def _finding_frame(finding: dict, observations: dict[str, dict]) -> str:
    frames: list[int] = []
    for oid in finding.get("observation_ids", []):
        obs = observations.get(oid)
        if not obs:
            continue
        frame = obs.get("frame")
        if frame and frame not in frames:
            frames.append(frame)
    if frames:
        return ", ".join(str(f) for f in sorted(frames))
    if finding.get("scope") == "conversation":
        return "stream"
    return "unavailable"


def _executive_summary(analysis: dict) -> str:
    coverage = _coverage(analysis)
    status = coverage.get("status")
    findings = _findings(analysis)
    threats = analysis.get("threats") or []
    summary = analysis.get("summary")

    if status == "unsupported_decode":
        return ("⚠️ **The capture could not be decoded.** Frames were read but none "
                "produced a usable IP/TCP/UDP decode, so a zero finding count here "
                "must not be read as an absence of malicious traffic.")
    if status == "empty":
        return "ℹ️ The capture contains no frames; there is nothing to analyse."

    if findings:
        dns = [f for f in findings if f.get("kind") == "dns"]
        conv = [f for f in findings if f.get("kind") != "dns"]
        crit = sum(1 for t in threats if t.get("confidence") == "CRITICAL")
        high = sum(1 for t in threats if t.get("confidence") == "HIGH")
        med = sum(1 for t in threats if t.get("confidence") == "MEDIUM")
        parts = [f"**{len(findings)} finding(s) recorded** "
                 f"({len(dns)} standalone DNS, {len(conv)} conversation-linked)."]
        if crit or high:
            parts.append(f"{crit + high} conversation(s) at HIGH or above require investigation.")
        elif med:
            parts.append(f"{med} conversation(s) at MEDIUM — further investigation recommended.")
        elif conv:
            parts.append("No conversation reached the MEDIUM band on the current weights.")
        if status == "partial":
            parts.append("Coverage was partial; see the coverage section before drawing conclusions.")
        return " ".join(parts)

    if status == "partial":
        return ("⚠️ **Partial analysis with no rule matches.** Some frames or stream bytes "
                "were lost, so this is not equivalent to a complete clean result.")
    if summary:
        return f"✅ {summary}"
    if threats:
        return f"{len(threats)} conversation(s) above the report threshold."
    return "✅ No significant threats detected in this capture."


def generate_markdown_report(analysis: dict) -> str:
    """Generate a Markdown threat analysis report.

    Args:
        analysis: GHOSTWIRE analysis dict (versioned result, or a legacy
            ``threats``-only summary).

    Returns:
        Markdown string.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    threats = analysis.get("threats", [])
    findings = _findings(analysis)
    observations = _observation_index(analysis)
    coverage = _coverage(analysis)
    capture = _capture(analysis)
    run = _run(analysis)
    selection = _selection(analysis)
    settings = run.get("settings") or {}
    versions = run.get("versions") or {}

    lines: list[str] = []

    # Header
    lines.append("# GHOSTWIRE Network Forensics Report")
    lines.append("")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Version:** {analysis.get('ghostwire_version', 'unknown')}")
    if analysis.get("schema_version"):
        lines.append(f"**Result schema:** {analysis['schema_version']}")
    lines.append(f"**Source File:** `{analysis.get('file', 'N/A')}`")
    sha = analysis.get("capture_sha256") or capture.get("sha256")
    lines.append(f"**Capture SHA-256:** `{sha or 'unavailable'}`")
    lines.append(f"**Analysis Time:** {_fmt_elapsed(analysis)}")
    if capture:
        lines.append(
            f"**Decoder:** parser `{capture.get('parser_used') or 'unavailable'}`"
            + (" (fallback)" if capture.get("parser_fallback") else "")
            + f" · link type `{capture.get('link_type_name') or 'unknown'}`"
        )
        lines.append(
            f"**Frames:** {capture.get('frames_read', 0)} read, "
            f"{capture.get('frames_decoded', 0)} decoded"
        )
        if capture.get("duration_seconds") is not None:
            lines.append(f"**Observed time span:** {capture['duration_seconds']:.3f}s")
        if capture.get("ordering_anomalies"):
            lines.append(
                f"**Ordering anomalies:** {capture['ordering_anomalies']} "
                "(timestamps went backwards in file order; spans use the observed bounds)"
            )
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(_executive_summary(analysis))
    lines.append("")

    crit = sum(1 for t in threats if t.get("confidence") == "CRITICAL")
    high = sum(1 for t in threats if t.get("confidence") == "HIGH")
    med = sum(1 for t in threats if t.get("confidence") == "MEDIUM")
    low = sum(1 for t in threats if t.get("confidence") in ("LOW", "NEGLIGIBLE"))
    lines.append("| Severity | Conversations |")
    lines.append("|----------|---------------|")
    lines.append(f"| CRITICAL | {crit} |")
    lines.append(f"| HIGH | {high} |")
    lines.append(f"| MEDIUM | {med} |")
    lines.append(f"| LOW / NEGLIGIBLE | {low} |")
    lines.append("")

    # Coverage — what the engine could and could not examine.
    if coverage:
        lines.append("## Coverage")
        lines.append("")
        status = coverage.get("status", "unknown")
        lines.append(f"**Status:** {_COVERAGE_LABEL.get(status, status)} — "
                     f"{coverage.get('label', '')}")
        lines.append("")
        if coverage.get("reasons"):
            for reason in coverage["reasons"]:
                lines.append(f"- {reason}")
        if coverage.get("limits"):
            for limit in coverage["limits"]:
                lines.append(f"- limit: {limit}")
        lines.append("")
        lines.append("| Coverage metric | Value |")
        lines.append("|-----------------|-------|")
        for key, label in (
            ("frames_read", "Frames read"),
            ("frames_decoded", "Frames decoded"),
            ("frames_undecoded", "Frames not decoded"),
            ("sessions_total", "TCP sessions"),
            ("sessions_dropped", "Conversations dropped at cap"),
            ("stream_gaps", "Stream gaps"),
            ("stream_missing_bytes", "Missing stream bytes"),
            ("payloads_capped", "Directions head-capped"),
        ):
            if key in coverage:
                lines.append(f"| {label} | {coverage[key]} |")
        lines.append("")

    # Overview Stats
    lines.append("## Capture Overview")
    lines.append("")
    lines.append("| Metric | Value | Counting unit |")
    lines.append("|--------|-------|---------------|")
    rows = [
        ("Total Packets", analysis.get("packets_total", 0), "frames read from the capture"),
        ("TCP Sessions", analysis.get("sessions_total", 0), "reconstructed 5-tuples"),
        ("TLS Fingerprints", analysis.get("tls_fingerprints", 0), "handshake records fingerprinted"),
        ("HTTP Fingerprints", analysis.get("http_fingerprints", 0), "HTTP requests fingerprinted"),
        ("SSH Fingerprints", analysis.get("ssh_fingerprints", 0), "SSH banners fingerprinted"),
        ("Rule Matches", analysis.get("c2_matches", 0), "distinct (tool, subject) rule matches"),
        ("Beacons Detected", analysis.get("beacons_detected", 0), "conversations above the beacon threshold"),
        ("DNS Findings", analysis.get("dns_threats", 0), "standalone DNS findings (not sessions)"),
        ("Findings", len(findings), "rule interpretations of an observed subject"),
    ]
    for label, value, unit in rows:
        lines.append(f"| {label} | {value:,} | {unit} |")
    lines.append("")

    # Selection: explain an empty or short list.
    if selection:
        counts = selection.get("counts") or {}
        filt = selection.get("filter") or {}
        trunc = selection.get("truncation") or {}
        lines.append("### Selection")
        lines.append("")
        lines.append(selection.get("explanation", ""))
        lines.append("")
        lines.append("| Selection counter | Value |")
        lines.append("|-------------------|-------|")
        for key in (
            "sessions_total", "sessions_scored", "sessions_eligible",
            "sessions_returned", "findings_total", "findings_returned",
            "dns_findings", "conversation_findings",
        ):
            if key in counts:
                lines.append(f"| `{key}` | {counts[key]} |")
        if "min_score" in filt:
            lines.append(f"| session threshold `min_score` | {filt['min_score']} |")
        if trunc:
            lines.append(
                f"| truncation | sessions limit {trunc.get('sessions_limit')}, "
                f"truncated: {trunc.get('sessions_truncated')} |"
            )
        lines.append("")

    # Findings — the evidence, before any session-score filter.
    if findings:
        lines.append("## Findings")
        lines.append("")
        for i, finding in enumerate(findings, 1):
            subject = finding.get("subject") or {}
            rule = finding.get("rule") or {}
            lines.append(f"### Finding {i} — {finding.get('kind', 'finding')}")
            lines.append("")
            lines.append(f"**Finding ID:** `{finding.get('finding_id')}`")
            lines.append(f"**Subject:** `{subject.get('value', '')}` "
                         f"({subject.get('type', 'unknown')})")
            lines.append(f"**Frame(s):** {_finding_frame(finding, observations)}")
            lines.append(f"**Rule:** `{rule.get('id')}` revision {rule.get('revision')} "
                         f"({finding.get('match_method')}) — {rule.get('source')}")
            lines.append(f"**Score:** {finding.get('score')} on `{finding.get('score_scale')}` "
                         "(a rule output, not a probability of compromise)")
            if finding.get("conversation_id"):
                lines.append(f"**Conversation:** `{finding.get('conversation_id')}` "
                             f"({finding.get('conversation_basis')})")
            else:
                lines.append("**Conversation:** none — this finding stands on its own "
                             "and is not filtered by a session score")
            lines.append("")

            # Observed values
            obs_list = [observations[i] for i in finding.get("observation_ids", [])
                        if i in observations]
            if obs_list:
                lines.append("**Observed evidence:**")
                lines.append("")
                lines.append("| Frame | Time | Transport | Direction | Field | Observed value |")
                lines.append("|-------|------|-----------|-----------|-------|----------------|")
                for obs in obs_list[:10]:
                    src = obs.get("src") or {}
                    dst = obs.get("dst") or {}
                    direction = (f"{src.get('ip')}:{src.get('port')} → "
                                 f"{dst.get('ip')}:{dst.get('port')} "
                                 f"({obs.get('direction')})")
                    value = str(obs.get("value", "")).replace("|", "\\|")
                    lines.append(
                        f"| {obs.get('frame')} | {obs.get('timestamp')} | "
                        f"{obs.get('transport')} | {direction} | "
                        f"`{obs.get('field')}` | `{value}` |"
                    )
                lines.append("")
                for obs in obs_list[:10]:
                    stream = obs.get("stream")
                    if stream:
                        lines.append(
                            f"- Stream evidence for frame {obs.get('frame')}: "
                            f"direction `{stream.get('direction')}`, "
                            f"captured payload {stream.get('captured_payload_bytes')} bytes, "
                            f"distinct stream bytes {stream.get('distinct_stream_bytes')}, "
                            f"gaps {len(stream.get('gaps') or [])} "
                            f"({stream.get('missing_bytes')} missing bytes)"
                        )
                if len(obs_list) > 10:
                    lines.append(f"- … {len(obs_list) - 10} further observation(s) in the JSON result")
                lines.append("")

            if finding.get("reasons"):
                lines.append("**Why the rule fired:**")
                for reason in finding["reasons"]:
                    contribution = reason.get("contribution")
                    contribution_txt = ("—" if contribution is None
                                        else f"contributes {contribution} ({reason.get('scale')})")
                    lines.append(f"- `{reason.get('code')}`: {reason.get('detail')} — {contribution_txt}")
                lines.append("")

            if finding.get("tool_inference"):
                inference = finding["tool_inference"]
                lines.append(f"**Inference:** tool `{inference.get('tool')}` "
                             f"(confidence {inference.get('confidence')}). "
                             f"{inference.get('caveat', '')}")
                lines.append("")

            lines.append(f"**Summary:** {finding.get('summary', '')}")
            lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        if coverage.get("status") in ("partial", "unsupported_decode"):
            lines.append("_No configured rule matched the decoded traffic. Because coverage "
                         "was not complete, this is not an all-clear._")
        else:
            lines.append("_No configured rule matched this capture._")
        lines.append("")

    # Threat Details (conversation assessments)
    if threats:
        lines.append("## Threat Details")
        lines.append("")
        for i, t in enumerate(threats, 1):
            confidence = t.get("confidence", "UNKNOWN")
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(confidence, "⚪")
            lines.append(f"### {emoji} Conversation #{i} — {confidence}")
            lines.append("")
            lines.append(f"**Target:** `{t.get('target', 'N/A')}`")
            lines.append(f"**Score:** {t.get('overall_score', 0):.3f} "
                         f"on `{t.get('score_scale', 'weighted_composite_0_1')}`")
            endpoints = t.get("endpoints") or {}
            if endpoints:
                src = endpoints.get("src") or {}
                dst = endpoints.get("dst") or {}
                lines.append(f"**Observed direction:** `{src.get('ip')}:{src.get('port')}` → "
                             f"`{dst.get('ip')}:{dst.get('port')}` "
                             f"(client side: {t.get('client_side', 'unknown')}; "
                             f"{t.get('role_basis', 'role basis unavailable')})")
            lines.append(f"**Summary:** {t.get('summary', 'N/A')}")
            lines.append("")

            if t.get("components"):
                lines.append("**Score derivation:**")
                lines.append("")
                lines.append("| Input | Value | Weight | Contribution | Finding |")
                lines.append("|-------|-------|--------|--------------|---------|")
                for component in t["components"]:
                    lines.append(
                        f"| {component.get('source')} | {component.get('value')} | "
                        f"{component.get('weight')} | {component.get('contribution')} | "
                        f"`{component.get('finding_id') or '—'}` |"
                    )
                lines.append("")

            if t.get("iocs"):
                lines.append("**Indicators of interest (observed values, not verdicts):**")
                for ioc in t["iocs"]:
                    lines.append(f"- `{ioc}`")
                lines.append("")

    # MITRE ATT&CK
    attack_mappings = map_analysis_to_attack(analysis)
    if attack_mappings:
        lines.append("## MITRE ATT&CK Mapping")
        lines.append("")
        lines.append("Mapped from the rules that matched; the frame alone establishes only "
                     "the observed request/query.")
        lines.append("")
        lines.append("| Tactic | Technique | ID | Confidence |")
        lines.append("|--------|-----------|----|------------|")
        for m in attack_mappings:
            lines.append(f"| {m.tactic} | {m.technique_name} | {m.technique_id} | {m.confidence:.0%} |")
        lines.append("")

    # Rules and versions
    if versions or settings:
        lines.append("## Effective Configuration")
        lines.append("")
        lines.append("| Setting | Value |")
        lines.append("|---------|-------|")
        for key in ("min_score", "min_packets", "max_payload_bytes", "max_sessions",
                    "max_returned_sessions", "retained_packets"):
            if key in settings:
                lines.append(f"| `{key}` | {settings[key]} |")
        for key in ("engine", "result_schema", "ja3_algorithm", "ja4_engine", "c2_rules"):
            if key in versions:
                lines.append(f"| `{key}` | {versions[key]} |")
        lines.append("")
        if versions.get("ja3_algorithm_notes"):
            note = versions["ja3_algorithm_notes"].get(versions.get("ja3_algorithm", ""))
            if note:
                lines.append(f"JA3 algorithm: {note}. Values produced by an older revision "
                             "must be compared with that revision, not this one.")
                lines.append("")

    # Recommendations
    lines.append("## Recommendations")
    lines.append("")
    if crit + high > 0:
        lines.append("1. **Investigate** the conversations above, starting from the frame "
                     "references in each finding")
        lines.append("2. **Verify** the rule match against the observed value before acting on a "
                     "tool attribution")
        lines.append("3. **Correlate** with endpoint and DNS logs for the same time window")
    elif med > 0:
        lines.append("1. **Review** medium-severity conversations for false positives")
        lines.append("2. **Correlate** with endpoint detection data")
    elif findings:
        lines.append("1. Findings exist below the session threshold; review them directly")
        lines.append("2. Re-run with a lower `--min-score` to list the conversations")
    elif coverage.get("status") in ("partial", "unsupported_decode"):
        lines.append("1. Re-capture with the full frame (or a supported link type) before "
                     "concluding the capture is clean")
        lines.append("2. Verify the declared link type and parser against the source")
    else:
        lines.append("1. No immediate action required for this capture")
        lines.append("2. Archive this report as a baseline for comparison")
    lines.append("")

    # Footer
    lines.append("---")
    lines.append(f"*Report generated by GHOSTWIRE v{analysis.get('ghostwire_version', 'unknown')}*")
    lines.append("*The wire remembers everything.*")

    return "\n".join(lines)


def generate_text_report(analysis: dict) -> str:
    """Generate a plain-text summary report (same evidence, terse layout)."""
    threats = analysis.get("threats", [])
    findings = _findings(analysis)
    observations = _observation_index(analysis)
    coverage = _coverage(analysis)
    capture = _capture(analysis)
    selection = _selection(analysis)
    high_threats = [t for t in threats if t.get("confidence") in ("CRITICAL", "HIGH")]

    lines = [
        "GHOSTWIRE ANALYSIS REPORT",
        "=" * 40,
        f"Version: {analysis.get('ghostwire_version', 'unknown')}",
        f"File: {analysis.get('file', 'N/A')}",
        f"Capture SHA-256: {analysis.get('capture_sha256') or capture.get('sha256') or 'unavailable'}",
        f"Parser: {capture.get('parser_used') or 'unavailable'}"
        + (" (fallback)" if capture.get("parser_fallback") else ""),
        f"Coverage: {coverage.get('status', 'unknown')}",
    ]
    for reason in coverage.get("reasons") or []:
        lines.append(f"  ! {reason}")
    lines.extend([
        f"Packets: {analysis.get('packets_total', 0):,} "
        f"({capture.get('frames_decoded', '?')} decoded)",
        f"Sessions: {analysis.get('sessions_total', 0):,}",
        f"Findings: {len(findings)} "
        f"(session rows returned: {len(threats)}, high confidence: {len(high_threats)})",
        "",
    ])

    if findings:
        lines.append("FINDINGS")
        lines.append("-" * 40)
        for finding in findings[:20]:
            subject = finding.get("subject") or {}
            rule = finding.get("rule") or {}
            lines.append(
                f"  [{finding.get('kind')}] frame {_finding_frame(finding, observations)} "
                f"{subject.get('value')}"
            )
            lines.append(
                f"    rule {rule.get('id')} r{rule.get('revision')} · "
                f"score {finding.get('score')} ({finding.get('score_scale')})"
            )
            for reason in (finding.get("reasons") or [])[:3]:
                lines.append(f"    - {reason.get('detail')}")
            lines.append(f"    {finding.get('summary', '')}")
            lines.append("")
        if len(findings) > 20:
            lines.append(f"  ... {len(findings) - 20} further finding(s) in the JSON result")
            lines.append("")
    else:
        lines.append("No configured rule matched the decoded traffic.")
        if coverage.get("status") in ("partial", "unsupported_decode"):
            lines.append("Coverage was not complete - this is not an all-clear.")
        lines.append("")

    if threats:
        lines.append("CONVERSATIONS")
        lines.append("-" * 40)
        for t in threats[:10]:
            conf = t.get("confidence", "?")
            score = t.get("overall_score", 0)
            lines.append(f"  [{conf}] {t.get('target', '?')} (score: {score:.3f})")
            lines.append(f"         {t.get('summary', '')}")
            if t.get("iocs"):
                lines.append(f"         Observed: {', '.join(t.get('iocs', [])[:3])}")
            lines.append("")

    if selection.get("explanation"):
        lines.append("SELECTION")
        lines.append("-" * 40)
        lines.append(f"  {selection['explanation']}")
        lines.append("")

    return "\n".join(lines)


def save_report(content: str, filepath: str) -> None:
    """Write report content to file."""
    with open(filepath, "w") as f:
        f.write(content)
    logger.info(f"Report saved to {filepath}")
