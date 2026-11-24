"""Analysis pipeline — one evidence path shared by every entry point.

``run_analysis`` streams a capture once, then builds the versioned result:

* ``run``           — capture digest, decoder facts, effective settings, versions
* ``coverage``      — complete / partial / unsupported decode / empty, with reasons
* ``observations``  — every observed field value with frame, time and endpoints
* ``findings``      — one rule interpretation per subject, referencing observations
* ``conversations`` — session scores whose components name the findings that fed them
* ``selection``     — counting units, filter and truncation

The pipeline deliberately keeps DNS findings outside TCP conversations. A DNS
query is a UDP message; joining it to a TCP session because the addresses or
timestamps are close is not evidence, and it changed an HTTP conversation's
score from 0.315 to 0.565 in the audit. HTTP/TLS/SSH findings, by contrast, are
attached to the conversation that supplied the matched field — identified by
its 5-tuple, not by a shared address.

Scoring weights are untouched: beacon 0.40, C2 0.35, DNS 0.25.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from engine import __version__
from engine.detection.beacon import BeaconScore, detect_beacons
from engine.detection.dns_threats import DNSThreat, analyze_dns
from engine.detection.scorer import (
    SCORE_WEIGHTS,
    SEVERITY_BANDS,
    ThreatScore,
    score_session,
)
from engine.evidence import (
    C2_MATCH_RULES,
    ConversationAssessment,
    Coverage,
    Endpoint,
    Finding,
    Observation,
    Reason,
    Run,
    Selection,
    StreamEvidence,
    conversation_id,
    coverage_summary,
    derive_coverage,
    rule_info,
)
from engine.evidence import (
    finding_id as make_finding_id,
)
from engine.evidence import (
    observation_id as make_observation_id,
)
from engine.evidence import (
    run_id as make_run_id,
)
from engine.fingerprint.c2_database import C2Match, feed_inventory, match_all
from engine.fingerprint.ja4_engine import (
    JA3_ALGORITHM,
    JA3_ALGORITHM_REVISIONS,
    TLSFingerprint,
    fingerprint_sessions,
    ja4_engine_version,
)
from engine.fingerprint.ja4h_engine import HTTPFingerprint
from engine.fingerprint.ja4h_engine import fingerprint_stream as http_fingerprint_stream
from engine.fingerprint.ja4ssh_engine import fingerprint_stream as ssh_fingerprint_stream
from engine.parser.pcap_loader import ParserReport, iter_packet_records
from engine.parser.protocol import identify_protocol
from engine.parser.session import SessionAccumulator, TCPSession, _make_session_key

logger = logging.getLogger(__name__)

#: Maximum conversation rows written to ``threats`` (historical cap, now
#: reported explicitly in ``selection.truncation``).
MAX_RETURNED_SESSIONS = 50
#: Maximum findings written. Findings are cheap; this only bounds pathological
#: captures and is reported when it bites.
MAX_RETURNED_FINDINGS = 500
#: Observations retained per finding (first N frames; total is recorded).
MAX_OBSERVATIONS_PER_FINDING = 20


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _feed_version() -> str:
    inventory = feed_inventory()
    if not inventory:
        return "builtin-only"
    h = hashlib.sha256()
    for entry in sorted(inventory, key=lambda e: (e["tool"], e["match_type"], e["value"])):
        h.update(repr(sorted(entry.items())).encode())
    return f"feeds-{h.hexdigest()[:12]}-{len(inventory)}entries"


# ─── Result container ───────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    """Everything one run produced, in contract form."""
    run: Run
    coverage: Coverage
    observations: list[Observation]
    findings: list[Finding]
    conversations: list[ConversationAssessment]
    threat_scores: list[ThreatScore]
    sessions: list[TCPSession] = field(default_factory=list)
    tls_fps: list[TLSFingerprint] = field(default_factory=list)
    http_fps: list[HTTPFingerprint] = field(default_factory=list)
    ssh_fps: list = field(default_factory=list)
    beacons: list[BeaconScore] = field(default_factory=list)
    packets: list = field(default_factory=list)
    packets_total: int = 0
    protocol_counts: dict[str, int] = field(default_factory=dict)
    elapsed_seconds: float = 0.0
    settings: dict = field(default_factory=dict)
    selection: Selection = field(default_factory=Selection)
    dns_threats: list[DNSThreat] = field(default_factory=list)
    summary: str = ""
    warnings: list[str] = field(default_factory=list)

    # ── Convenience views used by reports/tests ────────────────────────────
    def findings_by_kind(self, kind: str) -> list[Finding]:
        return [f for f in self.findings if f.kind == kind]

    def observation_map(self) -> dict[str, Observation]:
        return {o.observation_id: o for o in self.observations}

    def _legacy_counts(self) -> dict:
        distinct_c2 = {
            (f.tool_inference.get("tool"), f.match_method, f.subject_value)
            for f in self.findings
            if f.tool_inference
        }
        return {
            "packets_total": self.packets_total,
            "sessions_total": len(self.sessions),
            "tls_fingerprints": len(self.tls_fps),
            "http_fingerprints": len(self.http_fps),
            "ssh_fingerprints": len(self.ssh_fps),
            "beacons_detected": len(self.beacons),
            "dns_threats": len(self.findings_by_kind("dns")),
            "c2_matches": len(distinct_c2),
        }

    def legacy_dict(self) -> dict:
        """Internal dict shape consumed by ``engine.cli._full_analysis``.

        Kept because it holds live objects (sessions, fingerprints), which the
        versioned JSON cannot.
        """
        return {
            "packets": self.packets,
            "packets_total": self.packets_total,
            "protocol_counts": self.protocol_counts,
            "sessions": self.sessions,
            "tls_fps": self.tls_fps,
            "http_fps": self.http_fps,
            "ssh_fps": self.ssh_fps,
            "beacons": self.beacons,
            "dns_threats_all": [t.to_dict() for t in self.dns_threats],
            "threat_scores": self.threat_scores,
            "findings": [f.to_dict() for f in self.findings],
            "observations": [o.to_dict() for o in self.observations],
            "conversations": [c.to_dict() for c in self.conversations],
            "run": self.run.to_dict(),
            "coverage": self.coverage.to_dict(),
            "selection": self.selection.to_dict(),
            "analysis_time": round(self.elapsed_seconds, 3),
            "summary": self.summary,
            "settings": dict(self.settings),
        }

    def to_output(self) -> dict:
        """Versioned, JSON-serialisable result.

        Keeps every 0.2.x top-level field (``ghostwire_version``, ``file``,
        ``packets_total``, ..., ``threats``) so an older client keeps working,
        and adds the evidence contract under ``schema_version``/``run``/
        ``coverage``/``findings``/``observations``/``selection``.
        """
        counts = self._legacy_counts()
        output = {
            "schema_version": self.run.schema_version,
            "ghostwire_version": __version__,
            "file": self.run.capture.get("path", ""),
            "analysis_time": round(self.elapsed_seconds, 3),
            "capture_sha256": self.run.capture.get("sha256", ""),
            **counts,
            "protocol_counts": dict(self.protocol_counts),
            "packets_decoded": self.coverage.frames_decoded,
            "run": self.run.to_dict(),
            "coverage": self.coverage.to_dict(),
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "observations": [o.to_dict() for o in self.observations],
            "conversations": [c.to_dict() for c in self.conversations],
            "threats": [t.to_dict() for t in self.threat_scores],
            "dns_findings": [f.to_dict() for f in self.findings_by_kind("dns")],
            "selection": self.selection.to_dict(),
        }
        if self.warnings:
            output["warnings"] = list(self.warnings)
        return output


# ─── Observations ───────────────────────────────────────────────────────────

def _endpoint(ip: str, port: int, role: str) -> Endpoint:
    return Endpoint(ip=ip or "", port=port or 0, role=role)


def _dns_observations(capture_sha: str, pkt, dns_info: dict,
                     occurrence: int) -> list[Observation]:
    """Build observations for one DNS message (query name + query type)."""
    is_query = bool(dns_info.get("is_query"))
    is_response = bool(dns_info.get("is_response"))
    src_role = "client" if is_query else "server" if is_response else "unknown"
    dst_role = "server" if is_query else "client" if is_response else "unknown"
    src = _endpoint(pkt.src_ip, pkt.src_port, src_role)
    dst = _endpoint(pkt.dst_ip, pkt.dst_port, dst_role)
    frame = pkt.frame_number
    note = ("query" if is_query else "response" if is_response else "unclassified DNS message")
    qtype = str(dns_info.get("query_type", "") or "")
    name = str(dns_info.get("query_name", "") or "")

    obs: list[Observation] = []
    if name:
        obs.append(Observation(
            observation_id=make_observation_id(capture_sha, frame, "dns.query_name", name, occurrence),
            kind="packet", frame=frame, frames=[frame], timestamp=pkt.timestamp,
            transport=pkt.protocol_l4 or "UDP", src=src, dst=dst,
            direction="src_to_dst", field_name="dns.query_name", value=name,
            note=f"{qtype} {note}".strip(),
        ))
    if qtype:
        obs.append(Observation(
            observation_id=make_observation_id(capture_sha, frame, "dns.query_type", qtype, occurrence),
            kind="packet", frame=frame, frames=[frame], timestamp=pkt.timestamp,
            transport=pkt.protocol_l4 or "UDP", src=src, dst=dst,
            direction="src_to_dst", field_name="dns.query_type", value=qtype,
            note=note,
        ))
    return obs


def _http_observation(capture_sha: str, pkt, fp: HTTPFingerprint,
                      session_key: str) -> Observation | None:
    """HTTP header observation, anchored to a one-based frame."""
    if not fp.user_agent:
        return None
    from engine.fingerprint.c2_database import _normalize_ua
    frame = pkt.frame_number
    return Observation(
        observation_id=make_observation_id(
            capture_sha, frame, "http.header.user-agent", fp.user_agent, 1),
        kind="packet", frame=frame, frames=[frame], timestamp=pkt.timestamp,
        transport="TCP",
        src=_endpoint(pkt.src_ip, pkt.src_port, "client"),
        dst=_endpoint(pkt.dst_ip, pkt.dst_port, "server"),
        direction="src_to_dst",
        field_name="http.header.user-agent",
        value=fp.user_agent,
        normalized_value=_normalize_ua(fp.user_agent),
        note=f"HTTP request line carried the header; session {session_key}",
    )


def _ssh_observation(capture_sha: str, pkt, fp) -> Observation | None:
    banner = fp.client_banner or fp.server_banner
    if not banner:
        return None
    field_name = "ssh.client_banner" if fp.client_banner else "ssh.server_banner"
    frame = pkt.frame_number
    return Observation(
        observation_id=make_observation_id(capture_sha, frame, field_name, banner, 1),
        kind="packet", frame=frame, frames=[frame], timestamp=pkt.timestamp,
        transport="TCP",
        src=_endpoint(pkt.src_ip, pkt.src_port, "client" if fp.is_client else "server"),
        dst=_endpoint(pkt.dst_ip, pkt.dst_port, "server" if fp.is_client else "client"),
        direction="src_to_dst",
        field_name=field_name,
        value=banner,
    )


def _frames_for_sequence(session: TCPSession, direction: str,
                         seq_start: int, seq_end: int) -> tuple[list[int], list[dict], list[dict]]:
    """Map a stream byte range to supporting frames, ranges and gaps.

    ``seq_start``/``seq_end`` are absolute TCP sequence numbers (the record's
    position in the reconstructed stream plus the stream's first sequence).
    Returns (frames, supporting_ranges, gaps_inside_the_needed_range).
    """
    reassembly = (session.src_reassembly if direction == "src_to_dst"
                  else session.dst_reassembly)
    if not reassembly.ranges:
        return ([], [], [])
    base = reassembly.ranges[0].start
    lo, hi = base + seq_start, base + seq_end
    covering: list[dict] = []
    frames: list[int] = []
    for r in reassembly.ranges:
        if r.end <= lo or r.start >= hi:
            continue
        covering.append(r.to_dict())
        for f in r.frames:
            if f not in frames:
                frames.append(f)
    gaps = [g.to_dict() for g in reassembly.gaps if g.start < hi and g.end > lo]
    return (sorted(frames), covering, gaps)


def _stream_evidence(session: TCPSession, direction: str,
                     frames: list[int], covering: list[dict],
                     gaps: list[dict]) -> StreamEvidence:
    reassembly = (session.src_reassembly if direction == "src_to_dst"
                  else session.dst_reassembly)
    return StreamEvidence(
        session_id=session.session_id,
        direction=direction,
        seq_ranges=covering,
        gaps=gaps,
        captured_payload_bytes=reassembly.captured_payload_bytes,
        distinct_stream_bytes=reassembly.distinct_stream_bytes,
        stored_bytes=len(reassembly.payload),
        capped=reassembly.capped,
        role_basis=session.role_basis,
    )


def _tls_observations(capture_sha: str, fp: TLSFingerprint, session: TCPSession,
                      match: C2Match) -> tuple[list[Observation], list[str]]:
    """Observations for a TLS rule match: the matched fingerprint + the SNI."""
    direction = fp.stream_direction or ("src_to_dst" if session.client_side == "src"
                                       else "dst_to_src")
    seq_start = fp.record_offset
    seq_end = fp.record_offset + (fp.record_length or 0)
    frames, covering, gaps = _frames_for_sequence(session, direction, seq_start, seq_end)
    stream = _stream_evidence(session, direction, frames, covering, gaps)
    reassembly = (session.src_reassembly if direction == "src_to_dst"
                  else session.dst_reassembly)
    record_time = reassembly.timestamp_at(fp.record_offset)

    field_name = "tls.client_hello.ja3" if match.match_type == "ja3" else \
                 "tls.client_hello.ja4" if match.match_type == "ja4" else \
                 "tls.client_hello.fingerprint"
    value = match.matched_value
    obs = [Observation(
        observation_id=make_observation_id(capture_sha, frames[0] if frames else 0,
                                           field_name, value, 1),
        kind="stream", frame=frames[0] if frames else 0, frames=frames,
        timestamp=record_time, transport="TCP",
        src=_endpoint(fp.source_ip, fp.source_port, "client"),
        dst=_endpoint(fp.destination_ip, fp.destination_port, "server"),
        direction=direction,
        field_name=field_name, value=value,
        normalized_value=fp.sni or "",
        stream=stream,
        note=(f"{'ClientHello' if fp.is_client_hello else 'ServerHello'}; "
              f"sequence bytes {seq_start}..{seq_end} of the reconstructed stream; "
              f"role basis: {session.role_basis}"),
    )]

    ids = [obs[0].observation_id]
    if fp.sni:
        sni_obs = Observation(
            observation_id=make_observation_id(capture_sha, frames[0] if frames else 0,
                                               "tls.client_hello.sni", fp.sni, 1),
            kind="stream", frame=frames[0] if frames else 0, frames=frames,
            timestamp=record_time, transport="TCP",
            src=_endpoint(fp.source_ip, fp.source_port, "client"),
            dst=_endpoint(fp.destination_ip, fp.destination_port, "server"),
            direction=direction,
            field_name="tls.client_hello.sni", value=fp.sni,
            stream=stream,
            note="server name carried by the same ClientHello record",
        )
        obs.append(sni_obs)
        ids.append(sni_obs.observation_id)
    return obs, ids


def _beacon_observation(capture_sha: str, session: TCPSession,
                        beacon: BeaconScore) -> Observation:
    frames: list[int] = []
    for reassembly in (session.src_reassembly, session.dst_reassembly):
        for r in reassembly.ranges[:1]:
            for f in r.frames:
                if f not in frames:
                    frames.append(f)
    frames = sorted(frames)[:MAX_OBSERVATIONS_PER_FINDING]
    stream = _stream_evidence(session, "src_to_dst", frames,
                              [r.to_dict() for r in session.src_reassembly.ranges[:1]],
                              [g.to_dict() for g in session.src_reassembly.gaps])
    value = (f"iat_mean={beacon.iat_mean:.3f}s; jitter={beacon.iat_jitter:.3f}; "
             f"packets={beacon.packet_count}; duration={beacon.duration:.3f}s")
    return Observation(
        observation_id=make_observation_id(capture_sha, frames[0] if frames else 0,
                                           "tcp.timing", value, 1),
        kind="conversation", frame=frames[0] if frames else 0, frames=frames,
        timestamp=session.start_time, transport="TCP",
        src=_endpoint(session.src_ip, session.src_port,
                      "client" if session.client_side == "src" else "unknown"),
        dst=_endpoint(session.dst_ip, session.dst_port,
                      "server" if session.client_side == "src" else "unknown"),
        direction="observed",
        field_name="tcp.timing", value=value,
        stream=stream,
        note=("statistical assessment of the conversation; the frames listed are the "
              "stream ranges the timing was computed from, not every packet"),
    )


# ─── Finding construction ───────────────────────────────────────────────────

def _dns_finding(capture_sha: str, threat: DNSThreat,
                 observations: list[Observation]) -> Finding:
    rule_id = threat.rule_id or "dns.tunneling_heuristic"
    info = rule_info(rule_id)
    obs_ids = [o.observation_id for o in observations]
    reasons = [
        Reason(
            code=r.get("code", "dns.reason"),
            detail=r.get("detail", ""),
            contribution=r.get("contribution"),
            scale=r.get("scale", "rule_score_0_1"),
            observation_id=obs_ids[0] if obs_ids else "",
        )
        for r in threat.reason_details
    ]
    if not reasons:
        reasons = [Reason(code="dns.rule", detail=text,
                          contribution=None, scale="rule_score_0_1",
                          observation_id=obs_ids[0] if obs_ids else "")
                   for text in threat.reasons]
    return Finding(
        finding_id=make_finding_id(rule_id, info["revision"], "domain",
                                   threat.domain, obs_ids),
        kind="dns",
        rule_id=rule_id,
        rule_revision=info["revision"],
        subject_type="domain",
        subject_value=threat.domain,
        scope="packet",
        match_method=info["match_method"],
        score=threat.score,
        score_scale="rule_score_0_1",
        reasons=reasons,
        observation_ids=obs_ids,
        conversation_id=None,
        conversation_basis=None,
        tool_inference=None,
        mitre_techniques=["T1071.004"] if threat.threat_type == "tunneling" else ["T1568.002"],
        provenance={
            "engine_version": __version__,
            "query_type": threat.query_type,
            "threat_type": threat.threat_type,
            "messages_observed": threat.observation_count,
            "capture_sha256": capture_sha,
        },
        summary=(f"DNS query matched a {threat.threat_type.replace('_', ' ')} heuristic "
                 f"({len(reasons)} reason{'s' if len(reasons) != 1 else ''})"),
    )


def _c2_finding(capture_sha: str, match: C2Match, observations: list[Observation],
                subject_type: str, subject_value: str,
                conv_id: str | None, conv_basis: str | None,
                observation_label: str) -> Finding:
    rule_id = match.rule_id or C2_MATCH_RULES.get(match.match_type, "c2.http_user_agent_exact")
    info = rule_info(rule_id)
    obs_ids = [o.observation_id for o in observations]
    reason = Reason(
        code=f"c2.{match.match_type}_match",
        detail=(f"{observation_label} matched a {match.tool_name} rule "
                f"(weight {match.confidence:.2f}, {info['match_method']})"),
        contribution=match.confidence,
        scale="rule_weight_0_1",
        observation_id=obs_ids[0] if obs_ids else "",
    )
    provenance = {
        "engine_version": __version__,
        "capture_sha256": capture_sha,
        "rule_source": match.source,
        "match_type": match.match_type,
        "confidence_source": "built-in rule" if "built-in" in match.source.lower() else "feed",
    }
    return Finding(
        finding_id=make_finding_id(rule_id, info["revision"], subject_type,
                                   subject_value, obs_ids),
        kind=("http_header" if match.match_type == "http_pattern"
              else "ssh_banner" if match.match_type in ("ja4ssh", "banner")
              else "tls_fingerprint"),
        rule_id=rule_id,
        rule_revision=info["revision"],
        subject_type=subject_type,
        subject_value=subject_value,
        scope="conversation" if conv_id else "packet",
        match_method=info["match_method"],
        score=match.confidence,
        score_scale="rule_weight_0_1",
        reasons=[reason],
        observation_ids=obs_ids,
        conversation_id=conv_id,
        conversation_basis=conv_basis,
        tool_inference={
            "tool": match.tool_name,
            "confidence": round(match.confidence, 4),
            "basis": match.description,
            "caveat": ("This is a rule match on an observed field. It does not by "
                       "itself confirm that either endpoint is malicious."),
        },
        mitre_techniques=list(match.mitre_techniques),
        provenance=provenance,
        summary=(f"{observation_label} matched a {match.tool_name} rule "
                 f"(tool attribution is an inference, not a confirmation)"),
    )


def _beacon_finding(capture_sha: str, session: TCPSession, beacon: BeaconScore,
                    observations: list[Observation]) -> Finding:
    info = rule_info("beacon.timing_heuristic")
    obs_ids = [o.observation_id for o in observations]
    reasons = [
        Reason(code="beacon.timing", detail=text,
               contribution=None, scale="rule_score_0_1",
               observation_id=obs_ids[0] if obs_ids else "")
        for text in (beacon.reasons or ["beacon score above threshold"])
    ]
    return Finding(
        finding_id=make_finding_id("beacon.timing_heuristic", info["revision"],
                                   "conversation", session.session_id, obs_ids),
        kind="beacon",
        rule_id="beacon.timing_heuristic",
        rule_revision=info["revision"],
        subject_type="conversation",
        subject_value=session.session_id,
        scope="conversation",
        match_method=info["match_method"],
        score=beacon.overall_score,
        score_scale="rule_score_0_1",
        reasons=reasons,
        observation_ids=obs_ids,
        conversation_id=None,
        conversation_basis="the conversation's own packets supplied the timing",
        mitre_techniques=["T1071"],
        provenance={
            "engine_version": __version__,
            "capture_sha256": capture_sha,
            "components": {
                "jitter": beacon.jitter_score,
                "volume": beacon.volume_score,
                "regularity": beacon.regularity_score,
                "entropy": beacon.entropy_score,
            },
        },
        summary=f"Beacon timing heuristic fired (score {beacon.overall_score:.2f})",
    )


# ─── Pipeline ───────────────────────────────────────────────────────────────

def _resolve_settings(min_score: float, min_packets: int,
                      max_payload_bytes: int | None,
                      max_sessions: int | None, keep_packets: bool) -> dict:
    payload_cap = (max_payload_bytes if max_payload_bytes is not None
                   else int(os.environ.get("GHOSTWIRE_MAX_PAYLOAD_BYTES", 16 * 1024)))
    session_cap = (max_sessions if max_sessions is not None
                   else int(os.environ.get("GHOSTWIRE_MAX_SESSIONS", 20_000)))
    return {
        "min_score": round(float(min_score), 6),
        "min_packets": int(min_packets),
        "max_payload_bytes": payload_cap,
        "max_sessions": session_cap,
        "max_returned_sessions": MAX_RETURNED_SESSIONS,
        "max_returned_findings": MAX_RETURNED_FINDINGS,
        "max_observations_per_finding": MAX_OBSERVATIONS_PER_FINDING,
        "retained_packets": bool(keep_packets),
        "session_timeout_seconds": 300.0,
        "score_weights": dict(SCORE_WEIGHTS),
        "severity_bands": [{"label": label, "min_score": lower}
                           for label, lower in SEVERITY_BANDS],
    }


def run_analysis(pcap_file: str | Path, *, parser: str = "auto",
                 min_packets: int = 10, min_score: float = 0.25,
                 keep_packets: bool = False,
                 max_payload_bytes: int | None = None,
                 max_sessions: int | None = None) -> AnalysisResult:
    """Analyse one capture and return the versioned evidence result."""
    started = time.perf_counter()
    settings = _resolve_settings(min_score, min_packets, max_payload_bytes,
                                 max_sessions, keep_packets)
    capture_sha = sha256_file(pcap_file)
    report = ParserReport()
    accumulator = SessionAccumulator(
        max_payload_bytes=settings["max_payload_bytes"],
        max_sessions=settings["max_sessions"],
    )

    packets: list = []
    packets_total = 0
    protocol_counts: dict[str, int] = {}
    time_min: float | None = None
    time_max: float | None = None
    ordering_anomalies = 0
    last_timestamp: float | None = None

    # Observations collected during the stream, keyed for dedupe.
    dns_observations: dict[tuple[str, str], list[Observation]] = {}
    dns_message_count: dict[tuple[str, str], int] = {}
    dns_threat_by_domain: dict[tuple[str, str], DNSThreat] = {}
    # Grouped by (session, observed value) so a repeated header produces one
    # finding with several supporting frames, not one finding per packet.
    http_observations: dict[tuple[str, str], list[Observation]] = {}
    http_fingerprint_by_key: dict[tuple[str, str], HTTPFingerprint] = {}
    ssh_observations: dict[tuple[str, str], list[Observation]] = {}
    ssh_fingerprint_by_key: dict[tuple[str, str], object] = {}

    for pkt in iter_packet_records(pcap_file, parser=parser, report=report):
        packets_total += 1
        if time_min is None or pkt.timestamp < time_min:
            time_min = pkt.timestamp
        if time_max is None or pkt.timestamp > time_max:
            time_max = pkt.timestamp
        if last_timestamp is not None and pkt.timestamp < last_timestamp:
            ordering_anomalies += 1
        last_timestamp = pkt.timestamp

        if pkt.raw_payload:
            protocol_result = identify_protocol(
                pkt.src_port, pkt.dst_port, pkt.raw_payload,
                pkt.protocol_l4, pkt.metadata,
            )
            if protocol_result.l7_protocol:
                pkt.protocol_l7 = protocol_result.l7_protocol
                payload_dict = {
                    "tls": _asdict(protocol_result.tls) if protocol_result.tls else None,
                    "dns": _asdict(protocol_result.dns) if protocol_result.dns else None,
                    "http": _asdict(protocol_result.http) if protocol_result.http else None,
                    "ssh": _asdict(protocol_result.ssh) if protocol_result.ssh else None,
                    "icmp": _asdict(protocol_result.icmp) if protocol_result.icmp else None,
                }
                pkt.metadata["protocol_result"] = payload_dict
                dns_info = payload_dict.get("dns")
                if dns_info and dns_info.get("query_name"):
                    key = (dns_info["query_name"], str(dns_info.get("query_type", "A")))
                    dns_message_count[key] = dns_message_count.get(key, 0) + 1
                    bucket = dns_observations.setdefault(key, [])
                    # Bounded evidence retention: the first few messages are
                    # addressable by frame; the total is kept for the analyst.
                    if len(bucket) < MAX_OBSERVATIONS_PER_FINDING * 2:
                        bucket.extend(_dns_observations(
                            capture_sha, pkt, dns_info, dns_message_count[key]))

        # Per-packet HTTP/SSH fingerprinting (the header lives in one segment).
        if pkt.protocol_l4 == "TCP" and pkt.raw_payload:
            session_key = _make_session_key(pkt.src_ip, pkt.src_port,
                                            pkt.dst_ip, pkt.dst_port)
            for http_fp in http_fingerprint_stream([pkt]):
                obs = _http_observation(capture_sha, pkt, http_fp, session_key)
                if obs is not None:
                    http_key = (session_key, http_fp.user_agent)
                    http_fingerprint_by_key.setdefault(http_key, http_fp)
                    bucket_http = http_observations.setdefault(http_key, [])
                    if len(bucket_http) < MAX_OBSERVATIONS_PER_FINDING:
                        bucket_http.append(obs)
            for ssh_fp in ssh_fingerprint_stream([pkt]):
                obs = _ssh_observation(capture_sha, pkt, ssh_fp)
                if obs is not None:
                    banner = (getattr(ssh_fp, "client_banner", "")
                              or getattr(ssh_fp, "server_banner", ""))
                    ssh_key = (session_key, banner)
                    ssh_fingerprint_by_key.setdefault(ssh_key, ssh_fp)
                    bucket_ssh = ssh_observations.setdefault(ssh_key, [])
                    if len(bucket_ssh) < MAX_OBSERVATIONS_PER_FINDING:
                        bucket_ssh.append(obs)

        # Count protocols AFTER L7 identification so the breakdown reports the
        # decoded protocol (DNS, HTTP, TLS), not the transport it arrived on.
        # One packet, one unit: the denominator is the frame count.
        _proto = pkt.protocol_l7 or pkt.protocol_l4 or "Other"
        protocol_counts[_proto] = protocol_counts.get(_proto, 0) + 1

        accumulator.feed(pkt)
        if keep_packets:
            packets.append(pkt)

    sessions = accumulator.build()
    tls_fps = fingerprint_sessions(sessions)
    beacons = detect_beacons(sessions, min_packets=min_packets)
    beacon_by_session = {b.session_id: b for b in beacons}
    session_by_id = {s.session_id: s for s in sessions}

    observations: list[Observation] = []
    findings: list[Finding] = []
    session_findings: dict[str, list[Finding]] = {}
    session_matches: dict[str, list[C2Match]] = {}

    def _register(obs: list[Observation], finding: Finding,
                  session_key: str | None = None) -> None:
        if len(finding.observation_ids) > MAX_OBSERVATIONS_PER_FINDING:
            keep = MAX_OBSERVATIONS_PER_FINDING
            finding.provenance["observations_withheld"] = (
                len(finding.observation_ids) - keep
            )
            finding.observation_ids = finding.observation_ids[:keep]
        observations.extend(obs)
        findings.append(finding)
        if session_key:
            session_findings.setdefault(session_key, []).append(finding)

    # ── DNS findings (standalone; never attached to a TCP conversation) ────
    for (name, qtype), obs_bucket in dns_observations.items():
        if not name or not obs_bucket:
            continue
        for threat in analyze_dns(name, qtype,
                                  response_code=_response_code_for(obs_bucket)):
            key = (name, threat.threat_type)
            if key not in dns_threat_by_domain:
                dns_threat_by_domain[key] = threat
                threat.observation_count = dns_message_count.get((name, qtype), 0)
            finding = _dns_finding(capture_sha, threat, obs_bucket)
            if any(f.finding_id == finding.finding_id for f in findings):
                continue
            _register(list(obs_bucket), finding)

    # ── HTTP header findings (attached to the supplying conversation) ──────
    for (session_key, user_agent), obs_bucket in http_observations.items():
        http_fp = http_fingerprint_by_key[(session_key, user_agent)]
        matches = match_all(user_agent=http_fp.user_agent)
        for match in matches:
            conv = conversation_id(capture_sha, session_key)
            finding = _c2_finding(
                capture_sha, match, obs_bucket, "http_header", http_fp.user_agent,
                conv, f"same 5-tuple supplied the header ({session_key})",
                "HTTP User-Agent",
            )
            if any(f.finding_id == finding.finding_id for f in findings):
                continue
            _register(list(obs_bucket), finding, session_key)
            session_matches.setdefault(session_key, []).append(match)

    # ── SSH banner findings ────────────────────────────────────────────────
    for (session_key, banner), obs_bucket in ssh_observations.items():
        ssh_entry = ssh_fingerprint_by_key[(session_key, banner)]
        matches = match_all(ssh_banner=getattr(ssh_entry, "client_banner", ""),
                            ssh_software=getattr(ssh_entry, "client_software", ""))
        for match in matches:
            conv = conversation_id(capture_sha, session_key)
            finding = _c2_finding(
                capture_sha, match, obs_bucket, "ssh_banner",
                getattr(ssh_entry, "client_banner", ""), conv,
                f"same 5-tuple supplied the banner ({session_key})",
                "SSH client banner",
            )
            if any(f.finding_id == finding.finding_id for f in findings):
                continue
            _register(list(obs_bucket), finding, session_key)
            session_matches.setdefault(session_key, []).append(match)

    # ── TLS fingerprint findings ───────────────────────────────────────────
    for tls_fp in tls_fps:
        session = session_by_id.get(tls_fp.session_id)
        if session is None:
            continue
        matches = match_all(ja4=tls_fp.ja4, ja3=tls_fp.ja3_hash)
        for match in matches:
            obs_list, obs_ids = _tls_observations(capture_sha, tls_fp, session, match)
            conv = conversation_id(capture_sha, session.session_id)
            subject_value = (tls_fp.ja3_hash if match.match_type == "ja3"
                             else tls_fp.ja4 if match.match_type == "ja4"
                             else tls_fp.ja4s or tls_fp.ja4 or tls_fp.ja3_hash)
            label = ("TLS JA3" if match.match_type == "ja3"
                     else "TLS JA4" if match.match_type == "ja4"
                     else "TLS fingerprint")
            finding = _c2_finding(
                capture_sha, match, obs_list, f"tls_{match.match_type}",
                subject_value, conv,
                f"same 5-tuple supplied the handshake ({session.session_id})",
                label,
            )
            finding.observation_ids = obs_ids
            finding.provenance["ja3_algorithm"] = JA3_ALGORITHM
            finding.provenance["ja4_engine"] = tls_fp.ja4_engine
            if any(f.finding_id == finding.finding_id for f in findings):
                continue
            _register(obs_list, finding, session.session_id)
            session_matches.setdefault(session.session_id, []).append(match)

    # ── Beacon findings ────────────────────────────────────────────────────
    beacon_finding_by_session: dict[str, Finding] = {}
    for beacon_score in beacons:
        session = session_by_id.get(beacon_score.session_id)
        if session is None:
            continue
        obs = _beacon_observation(capture_sha, session, beacon_score)
        finding = _beacon_finding(capture_sha, session, beacon_score, [obs])
        _register([obs], finding, session.session_id)
        beacon_finding_by_session[session.session_id] = finding

    # ── Conversation assessments (session-scoped evidence only) ────────────
    conversations: list[ConversationAssessment] = []
    threat_scores: list[ThreatScore] = []
    for session in sessions:
        sid = session.session_id
        scoped_findings = session_findings.get(sid, [])
        if not scoped_findings:
            continue
        matches = session_matches.get(sid, [])
        deduped: dict[tuple, C2Match] = {}
        for m in matches:
            match_key = (m.tool_name, m.match_type, m.matched_value)
            if match_key not in deduped or m.confidence > deduped[match_key].confidence:
                deduped[match_key] = m
        c2 = list(deduped.values())
        c2_finding_ids = [f.finding_id for f in scoped_findings
                          if f.tool_inference is not None]
        session_beacon = beacon_by_session.get(sid)
        beacon_finding = beacon_finding_by_session.get(sid)

        score = score_session(
            sid,
            beacon=session_beacon,
            c2_matches=c2,
            dns_threats=[],  # DNS is never capture-wide attribution
            c2_finding_ids=c2_finding_ids,
            beacon_finding_id=beacon_finding.finding_id if beacon_finding else None,
        )
        score.endpoints = {
            "src": session.endpoint_dict("src"),
            "dst": session.endpoint_dict("dst"),
        }
        score.client_side = session.client_side
        score.role_basis = session.role_basis

        # Prose is derived from the same findings as the structured list.
        summaries = []
        for f in sorted(scoped_findings, key=lambda x: (x.kind, x.finding_id)):
            summaries.append(f.summary)
        score.summary = "; ".join(dict.fromkeys(summaries)) or "No rule matched this conversation"

        conversations.append(ConversationAssessment(
            conversation_id=conversation_id(capture_sha, sid),
            session_id=sid,
            endpoints=score.endpoints,
            client_side=session.client_side,
            role_basis=session.role_basis,
            contributing_findings=score.finding_ids,
            components=[c.to_dict() for c in score.components],
            score=score.overall_score,
            severity=score.confidence,
            summary=score.summary,
        ))
        threat_scores.append(score)

    # ── Deterministic ordering ─────────────────────────────────────────────
    findings.sort(key=lambda f: (
        0 if f.kind == "dns" else 1,
        (f.observation_ids[0] if f.observation_ids else ""),
        f.rule_id,
        f.subject_value,
    ))
    # Observations: stable order, deduped by id.
    seen_obs: set[str] = set()
    ordered_obs: list[Observation] = []
    for o in sorted(observations, key=lambda x: (x.frame, x.field_name,
                                                 x.occurrence, x.observation_id)):
        if o.observation_id in seen_obs:
            continue
        seen_obs.add(o.observation_id)
        ordered_obs.append(o)

    conversations.sort(key=lambda c: (-c.score, c.session_id))
    threat_scores.sort(key=lambda s: (-s.overall_score, s.target))

    # ── Selection ──────────────────────────────────────────────────────────
    scored = len(threat_scores)
    eligible = [t for t in threat_scores if t.overall_score >= min_score]
    returned = eligible[:MAX_RETURNED_SESSIONS]
    returned_findings = findings[:MAX_RETURNED_FINDINGS]

    selection = Selection(
        counts={
            "packets_total": packets_total,
            "frames_decoded": report.frames_decoded,
            "frames_undecoded": report.frames_undecoded,
            "sessions_total": len(sessions),
            "sessions_scored": scored,
            "sessions_eligible": len(eligible),
            "sessions_returned": len(returned),
            "findings_total": len(findings),
            "findings_returned": len(returned_findings),
            "dns_findings": len([f for f in findings if f.kind == "dns"]),
            "conversation_findings": len([f for f in findings if f.kind != "dns"]),
            "unique_c2_indicators": len({
                (f.tool_inference.get("tool"), f.subject_value)
                for f in findings if f.tool_inference
            }),
        },
        filter={
            "min_score": settings["min_score"],
            "sessions_below_threshold": scored - len(eligible),
            "sessions_without_findings": len(sessions) - scored,
            "counting_unit": "session score (weighted composite 0-1)",
            "note": ("DNS findings are not session rows: one DNS query has no TCP "
                     "session and therefore no session score to filter."),
        },
        truncation={
            "sessions_limit": MAX_RETURNED_SESSIONS,
            "sessions_truncated": len(eligible) > MAX_RETURNED_SESSIONS,
            "findings_limit": MAX_RETURNED_FINDINGS,
            "findings_truncated": len(findings) > MAX_RETURNED_FINDINGS,
            "observations_per_finding_limit": MAX_OBSERVATIONS_PER_FINDING,
            "ordering": "conversations by score desc then session_id; findings by frame then rule",
        },
        explanation=_selection_explanation(
            coverage_status=None,  # filled after coverage is derived
            min_score=settings["min_score"], scored=scored,
            eligible=len(eligible), findings_total=len(findings),
            dns_findings=selection_dns_count(findings),
            sessions_total=len(sessions),
        ),
    )

    # ── Coverage ───────────────────────────────────────────────────────────
    stream_gaps = sum(
        len(s.src_reassembly.gaps) + len(s.dst_reassembly.gaps) for s in sessions
    )
    missing_bytes = sum(
        s.src_reassembly.missing_bytes + s.dst_reassembly.missing_bytes
        for s in sessions
    )
    payloads_capped = sum(
        int(s.src_reassembly.capped) + int(s.dst_reassembly.capped) for s in sessions
    )
    coverage = derive_coverage(
        report,
        sessions_total=len(sessions),
        sessions_dropped=accumulator.sessions_dropped,
        settings=settings,
        stream_gaps=stream_gaps,
        stream_missing_bytes=missing_bytes,
        payloads_capped=payloads_capped,
    )
    selection.explanation = _selection_explanation(
        coverage_status=coverage.status,
        min_score=settings["min_score"], scored=scored,
        eligible=len(eligible), findings_total=len(findings),
        dns_findings=len([f for f in findings if f.kind == "dns"]),
        sessions_total=len(sessions),
    )

    elapsed = time.perf_counter() - started
    generated_at = _utc_now()
    run = Run(
        run_id=make_run_id(capture_sha, __version__, settings, generated_at),
        engine_version=__version__,
        generated_at=generated_at,
        capture={
            "path": str(pcap_file),
            "sha256": capture_sha,
            "size_bytes": Path(pcap_file).stat().st_size,
            "format": report.capture_format or None,
            "link_type_declared": report.link_type_declared,
            "link_type_name": report.link_type_name or None,
            "parser_declared": report.declared_parser,
            "parser_used": report.parser_used or None,
            "parser_fallback": report.fallback_used,
            "framing_used": report.framing_used or None,
            "frames_read": report.frames_read,
            "frames_decoded": report.frames_decoded,
            "frames_undecoded": report.frames_undecoded,
            "decode_rate": (None if report.decode_rate() is None
                            else round(report.decode_rate() or 0.0, 4)),
            "decode_failures": report.decode_failures,
            "first_timestamp": time_min,
            "last_timestamp": time_max,
            "duration_seconds": (None if time_min is None or time_max is None
                                 else round(time_max - time_min, 6)),
            "ordering_anomalies": ordering_anomalies,
        },
        settings=settings,
        versions={
            "engine": __version__,
            "result_schema": run_schema(),
            "ja3_algorithm": JA3_ALGORITHM,
            "ja3_algorithm_notes": JA3_ALGORITHM_REVISIONS,
            "ja4_engine": ja4_engine_version(),
            "c2_rules": _feed_version(),
            "python": _python_version(),
        },
    )

    summary = coverage_summary(coverage, len(findings))

    analysis_result = AnalysisResult(
        run=run,
        coverage=coverage,
        observations=ordered_obs,
        findings=findings,
        conversations=conversations,
        threat_scores=returned,
        sessions=sessions,
        tls_fps=tls_fps,
        http_fps=list(http_fingerprint_by_key.values()),
        ssh_fps=list(ssh_fingerprint_by_key.values()),
        beacons=beacons,
        packets=packets,
        packets_total=packets_total,
        protocol_counts=protocol_counts,
        elapsed_seconds=elapsed,
        settings=settings,
        selection=selection,
        dns_threats=list(dns_threat_by_domain.values()),
        summary=summary,
    )
    # Only the selected rows go out as ``threats``; the full list of scored
    # conversations is available under ``conversations``.
    analysis_result.threat_scores = returned
    analysis_result.conversations = conversations
    return analysis_result


def selection_dns_count(findings: list[Finding]) -> int:
    return len([f for f in findings if f.kind == "dns"])


def run_schema() -> str:
    from engine.evidence import RESULT_SCHEMA_VERSION
    return RESULT_SCHEMA_VERSION


def _python_version() -> str:
    import platform
    return platform.python_version()


def _asdict(obj):
    from dataclasses import asdict
    return asdict(obj)


def _response_code_for(obs_bucket: list[Observation]) -> str:
    for o in obs_bucket:
        if "NXDOMAIN" in o.note or "SERVFAIL" in o.note or "REFUSED" in o.note:
            return o.note.split()[0]
    return "NOERROR"


def _selection_explanation(*, coverage_status: str | None, min_score: float,
                           scored: int, eligible: int, findings_total: int,
                           dns_findings: int, sessions_total: int) -> str:
    parts: list[str] = []
    parts.append(
        f"{findings_total} finding(s) recorded"
        + (f" ({dns_findings} standalone DNS finding(s))" if dns_findings else "")
        + "."
    )
    if sessions_total == 0:
        parts.append("No TCP conversations were reconstructed, so there is no session score to filter.")
    else:
        parts.append(
            f"{scored} of {sessions_total} conversation(s) had contributing findings; "
            f"{eligible} scored at or above the {min_score:g} session threshold."
        )
    if findings_total and eligible == 0 and sessions_total:
        parts.append(
            "An empty session table is a threshold result, not an empty capture: "
            "the findings above still apply."
        )
    if coverage_status in ("partial", "unsupported_decode"):
        parts.append("Coverage was not complete - see coverage.reasons.")
    return " ".join(parts)
