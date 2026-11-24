"""Evidence and coverage contract for GHOSTWIRE analysis results.

Everything an analyst sees has to answer four questions:

1. **Which capture and frames support this finding?**
   ``Run.capture`` carries the capture digest and decoder facts;
   ``Observation.frame``/``frames`` carry one-based frame numbers.
2. **Which field was observed?**
   ``Observation.field`` names it (``dns.query_name``,
   ``http.header.user-agent``, ``tls.client_hello.sni``, ...) and
   ``Observation.value`` holds the value exactly as it appeared on the wire,
   with ``normalized_value`` kept separate when a rule compared a normalised
   form.
3. **Which rule interpreted it?**
   ``Finding.rule`` (stable id + revision + source file) and
   ``Finding.reasons`` (each reason names the observation and the score it
   contributed on a named scale).
4. **What evidence was unavailable?**
   ``Run.coverage`` states whether analysis was complete, partial, an
   unsupported decode, or empty, and why. Stream-derived observations carry
   sequence ranges, gaps and a role basis instead of pretending the stream was
   continuous.

Identifiers are content hashes over the capture digest plus frame/field/value,
so the same evidence keeps the same id across repeat analyses. ``run_id`` is
deliberately *not* part of an observation or finding id: re-running the same
capture with the same settings must not silently rename the evidence.

This module is the contract only; :mod:`engine.analysis` builds the pipeline
and :mod:`engine.cli` renders it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from engine import __version__

# ─── Versions ───────────────────────────────────────────────────────────────

RESULT_SCHEMA_VERSION = "1.0"

#: Versions whose result shape this build can read. A stored result with a
#: schema version outside this set is reported as unsupported and its payload
#: is preserved rather than guessed at.
SUPPORTED_SCHEMA_VERSIONS = ("1.0",)

# ─── Coverage states ────────────────────────────────────────────────────────

COVERAGE_COMPLETE = "complete"
COVERAGE_PARTIAL = "partial"
COVERAGE_UNSUPPORTED_DECODE = "unsupported_decode"
COVERAGE_EMPTY = "empty"

COVERAGE_LABELS = {
    COVERAGE_COMPLETE: "Complete analysis of the decoded capture",
    COVERAGE_PARTIAL: "Partial coverage — some frames or bytes could not be decoded or were lost",
    COVERAGE_UNSUPPORTED_DECODE: "Unsupported decode — frames were read but no relevant traffic was decoded",
    COVERAGE_EMPTY: "Empty capture — no frames were read",
}

# ─── Rule registry ──────────────────────────────────────────────────────────
#
# A rule id names the interpretation, not the tool. Revisions change when the
# interpretation or its inputs change, so two runs of the same evidence can be
# compared without conflating a rule edit with a traffic difference.

RULE_REGISTRY: dict[str, dict[str, str]] = {
    "dns.tunneling_heuristic": {
        "revision": "1",
        "source": "engine/detection/dns_threats.py::detect_dns_tunneling",
        "match_method": "heuristic",
        "scale": "rule_score_0_1",
    },
    "dns.dga_heuristic": {
        "revision": "1",
        "source": "engine/detection/dns_threats.py::detect_dga",
        "match_method": "heuristic",
        "scale": "rule_score_0_1",
    },
    "c2.http_user_agent_exact": {
        "revision": "1",
        "source": "engine/fingerprint/c2_database.py::match_http",
        "match_method": "exact_normalized",
        "scale": "rule_weight_0_1",
    },
    "c2.ja4_prefix": {
        "revision": "1",
        "source": "engine/fingerprint/c2_database.py::match_ja4",
        "match_method": "prefix",
        "scale": "rule_weight_0_1",
    },
    "c2.ja3_exact": {
        "revision": "1",
        "source": "engine/fingerprint/c2_database.py::match_ja3",
        "match_method": "exact",
        "scale": "rule_weight_0_1",
    },
    "c2.ssh_software_heuristic": {
        "revision": "1",
        "source": "engine/fingerprint/c2_database.py::match_ssh",
        "match_method": "substring",
        "scale": "rule_weight_0_1",
    },
    "beacon.timing_heuristic": {
        "revision": "1",
        "source": "engine/detection/beacon.py::detect_beacon",
        "match_method": "statistical",
        "scale": "rule_score_0_1",
    },
    "hunt.cobalt_strike_user_agent": {
        "revision": "1",
        "source": "engine/detection/hunt.py::hunt_cobalt_strike",
        "match_method": "exact_normalized",
        "scale": "rule_weight_0_1",
    },
    "hunt.dns_tunneling_shape": {
        "revision": "1",
        "source": "engine/detection/hunt.py::hunt_dns_tunneling",
        "match_method": "heuristic",
        "scale": "rule_score_0_1",
    },
}

#: C2 match types map onto the rule that produced them.
C2_MATCH_RULES = {
    "http_pattern": "c2.http_user_agent_exact",
    "ja4": "c2.ja4_prefix",
    "ja3": "c2.ja3_exact",
    "ja4ssh": "c2.ssh_software_heuristic",
    "banner": "c2.ssh_software_heuristic",
}


def rule_info(rule_id: str) -> dict[str, str]:
    """Registry entry for ``rule_id`` (never raises: unknown rules are labelled)."""
    info = RULE_REGISTRY.get(rule_id)
    if info is None:
        return {
            "revision": "0",
            "source": "unregistered",
            "match_method": "unknown",
            "scale": "unknown",
        }
    return info


# ─── Stable ids ─────────────────────────────────────────────────────────────

def _digest(*parts: Any, length: int = 16) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(str(part).encode("utf-8", errors="replace"))
        h.update(b"\x1f")  # unit separator: no value can bleed into the next
    return h.hexdigest()[:length]


def observation_id(capture_sha256: str, frame: int, field_name: str,
                   value: str, occurrence: int = 1) -> str:
    return "obs-" + _digest("observation", capture_sha256, frame, field_name,
                            occurrence, value)


def finding_id(rule_id: str, rule_revision: str, subject_type: str,
               subject_value: str, observation_ids: list[str]) -> str:
    return "fnd-" + _digest("finding", rule_id, rule_revision, subject_type,
                            subject_value, *sorted(observation_ids))


def conversation_id(capture_sha256: str, session_id: str) -> str:
    return "cnv-" + _digest("conversation", capture_sha256, session_id)


def run_id(capture_sha256: str, engine_version: str, settings: dict,
           started_at: str) -> str:
    return "run-" + _digest("run", capture_sha256, engine_version,
                            sorted(settings.items()), started_at, length=20)


# ─── Record types ───────────────────────────────────────────────────────────

@dataclass
class Endpoint:
    """A typed address in the direction it was observed."""
    ip: str
    port: int = 0
    role: str = "unknown"        # "client" | "server" | "unknown"
    address_family: str = ""

    def __post_init__(self) -> None:
        if not self.address_family:
            self.address_family = "ipv6" if ":" in (self.ip or "") else "ipv4"

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port,
            "role": self.role,
            "address_family": self.address_family,
        }


@dataclass
class StreamEvidence:
    """Byte-level support for a stream-derived observation.

    ``seq_ranges`` are the sequence intervals that supplied the observed field;
    ``gaps`` are intervals inside the observed span with no captured bytes. A
    finding whose field needed bytes from a gap cannot be supported — the
    fingerprinter drops incomplete records instead of guessing.
    """
    session_id: str
    direction: str                      # "src_to_dst" | "dst_to_src"
    seq_ranges: list[dict] = field(default_factory=list)
    gaps: list[dict] = field(default_factory=list)
    captured_payload_bytes: int = 0
    distinct_stream_bytes: int = 0
    stored_bytes: int = 0
    capped: bool = False
    role_basis: str = ""

    @property
    def missing_bytes(self) -> int:
        return sum(int(g.get("missing_bytes", 0)) for g in self.gaps)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "direction": self.direction,
            "seq_ranges": self.seq_ranges,
            "gaps": self.gaps,
            "missing_bytes": self.missing_bytes,
            "captured_payload_bytes": self.captured_payload_bytes,
            "distinct_stream_bytes": self.distinct_stream_bytes,
            "stored_bytes": self.stored_bytes,
            "capped": self.capped,
            "role_basis": self.role_basis,
        }


@dataclass
class Observation:
    """One observed field value and where it was observed."""
    observation_id: str
    kind: str                 # "packet" | "stream" | "capture_timing"
    frame: int                # one-based frame number of the first frame
    frames: list[int]
    timestamp: float | None
    transport: str
    src: Endpoint
    dst: Endpoint
    direction: str            # "src_to_dst" | "dst_to_src" | "observed"
    field_name: str
    value: str
    normalized_value: str = ""
    occurrence: int = 1
    stream: StreamEvidence | None = None
    note: str = ""

    def to_dict(self) -> dict:
        d = {
            "observation_id": self.observation_id,
            "kind": self.kind,
            "frame": self.frame,
            "frames": list(self.frames),
            "timestamp": self.timestamp,
            "transport": self.transport,
            "src": self.src.to_dict(),
            "dst": self.dst.to_dict(),
            "direction": self.direction,
            "field": self.field_name,
            "value": self.value,
            "normalized_value": self.normalized_value or None,
            "occurrence": self.occurrence,
        }
        if self.stream is not None:
            d["stream"] = self.stream.to_dict()
        if self.note:
            d["note"] = self.note
        return d


@dataclass
class Reason:
    """One rule input and what it contributed, on a named scale."""
    code: str
    detail: str
    contribution: float | None = None
    scale: str = "rule_score_0_1"
    observation_id: str = ""

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "detail": self.detail,
            "contribution": (None if self.contribution is None
                             else round(self.contribution, 6)),
            "scale": self.scale,
            "observation_id": self.observation_id or None,
        }


@dataclass
class Finding:
    """One rule interpretation of one subject, with its supporting evidence."""
    finding_id: str
    kind: str                      # "dns" | "http_header" | "tls_fingerprint" | ...
    rule_id: str
    rule_revision: str
    subject_type: str
    subject_value: str
    scope: str                     # "packet" | "conversation" | "capture"
    match_method: str
    score: float
    score_scale: str
    reasons: list[Reason] = field(default_factory=list)
    observation_ids: list[str] = field(default_factory=list)
    conversation_id: str | None = None
    conversation_basis: str | None = None
    tool_inference: dict | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    provenance: dict = field(default_factory=dict)
    summary: str = ""

    def to_dict(self) -> dict:
        d = {
            "finding_id": self.finding_id,
            "kind": self.kind,
            "rule": {
                "id": self.rule_id,
                "revision": self.rule_revision,
                "source": rule_info(self.rule_id)["source"],
            },
            "subject": {
                "type": self.subject_type,
                "value": self.subject_value,
            },
            "scope": self.scope,
            "match_method": self.match_method,
            "score": round(self.score, 6),
            "score_scale": self.score_scale,
            "reasons": [r.to_dict() for r in self.reasons],
            "observation_ids": list(self.observation_ids),
            "conversation_id": self.conversation_id,
            "conversation_basis": self.conversation_basis,
            "mitre_techniques": list(self.mitre_techniques),
            "provenance": dict(self.provenance),
            "summary": self.summary,
        }
        if self.tool_inference is not None:
            d["tool_inference"] = self.tool_inference
        return d


@dataclass
class ConversationAssessment:
    """Score for one conversation, derived from named findings only."""
    conversation_id: str
    session_id: str
    endpoints: dict
    client_side: str
    role_basis: str
    contributing_findings: list[str] = field(default_factory=list)
    components: list[dict] = field(default_factory=list)
    score: float = 0.0
    severity: str = "NEGLIGIBLE"
    summary: str = ""
    score_scale: str = "weighted_composite_0_1"

    def to_dict(self) -> dict:
        return {
            "conversation_id": self.conversation_id,
            "session_id": self.session_id,
            "endpoints": self.endpoints,
            "client_side": self.client_side,
            "role_basis": self.role_basis,
            "contributing_findings": list(self.contributing_findings),
            "components": list(self.components),
            "score": round(self.score, 6),
            "score_scale": self.score_scale,
            "severity": self.severity,
            "summary": self.summary,
        }


@dataclass
class Coverage:
    """What the engine could and could not examine."""
    status: str = COVERAGE_COMPLETE
    reasons: list[str] = field(default_factory=list)
    limits: list[str] = field(default_factory=list)
    frames_read: int = 0
    frames_decoded: int = 0
    frames_undecoded: int = 0
    sessions_total: int = 0
    sessions_dropped: int = 0
    stream_gaps: int = 0
    stream_missing_bytes: int = 0
    payloads_capped: int = 0
    parser_used: str | None = None
    link_type_declared: int | None = None
    link_type_name: str = ""

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "label": COVERAGE_LABELS.get(self.status, self.status),
            "reasons": list(self.reasons),
            "limits": list(self.limits),
            "frames_read": self.frames_read,
            "frames_decoded": self.frames_decoded,
            "frames_undecoded": self.frames_undecoded,
            "sessions_total": self.sessions_total,
            "sessions_dropped": self.sessions_dropped,
            "stream_gaps": self.stream_gaps,
            "stream_missing_bytes": self.stream_missing_bytes,
            "payloads_capped": self.payloads_capped,
            "parser_used": self.parser_used,
            "link_type_declared": self.link_type_declared,
            "link_type_name": self.link_type_name or None,
        }


@dataclass
class Run:
    """Run-level metadata: identity, decoder facts, settings, versions."""
    schema_version: str = RESULT_SCHEMA_VERSION
    run_id: str = ""
    engine_version: str = __version__
    generated_at: str = ""
    capture: dict = field(default_factory=dict)
    settings: dict = field(default_factory=dict)
    versions: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "engine_version": self.engine_version,
            "generated_at": self.generated_at,
            "capture": dict(self.capture),
            "settings": dict(self.settings),
            "versions": dict(self.versions),
        }


@dataclass
class Selection:
    """Counting units, filter and truncation, so an empty page is explainable."""
    counts: dict = field(default_factory=dict)
    filter: dict = field(default_factory=dict)
    truncation: dict = field(default_factory=dict)
    explanation: str = ""

    def to_dict(self) -> dict:
        return {
            "counts": dict(self.counts),
            "filter": dict(self.filter),
            "truncation": dict(self.truncation),
            "explanation": self.explanation,
        }


# ─── Coverage derivation ────────────────────────────────────────────────────

def derive_coverage(report: Any, *, sessions_total: int, sessions_dropped: int,
                    settings: dict, stream_gaps: int = 0,
                    stream_missing_bytes: int = 0,
                    payloads_capped: int = 0) -> Coverage:
    """Turn decoder + stream facts into a single coverage verdict.

    The four states are deliberately distinct:

    * ``empty``              — no frames at all.
    * ``unsupported_decode`` — frames were read, none produced a usable decode.
      "No findings" here means "not examined", not "nothing there".
    * ``partial``            — some frames or stream bytes were lost.
    * ``complete``           — every read frame decoded and no bytes were lost.
    """
    frames_read = int(getattr(report, "frames_read", 0) or 0)
    frames_decoded = int(getattr(report, "frames_decoded", 0) or 0)
    frames_undecoded = int(getattr(report, "frames_undecoded", 0) or 0)

    coverage = Coverage(
        frames_read=frames_read,
        frames_decoded=frames_decoded,
        frames_undecoded=frames_undecoded,
        sessions_total=sessions_total,
        sessions_dropped=sessions_dropped,
        stream_gaps=stream_gaps,
        stream_missing_bytes=stream_missing_bytes,
        payloads_capped=payloads_capped,
        parser_used=getattr(report, "parser_used", None) or None,
        link_type_declared=getattr(report, "link_type_declared", None),
        link_type_name=getattr(report, "link_type_name", ""),
    )

    if frames_read == 0:
        coverage.status = COVERAGE_EMPTY
        coverage.reasons.append("the capture contains no frames")
    elif frames_decoded == 0:
        coverage.status = COVERAGE_UNSUPPORTED_DECODE
        coverage.reasons.append(
            "frames were read but none decoded to IPv4/IPv6 with TCP/UDP/ICMP; "
            "protocol findings cannot be interpreted as an absence of traffic"
        )
        declared = getattr(report, "link_type_name", "") or "unknown"
        coverage.reasons.append(
            f"declared link type: {declared}; parser used: {coverage.parser_used or 'none'}"
        )
    elif frames_undecoded:
        coverage.status = COVERAGE_PARTIAL
        coverage.reasons.append(
            f"{frames_undecoded} of {frames_read} frames produced no IP/TCP/UDP decode"
        )
    else:
        coverage.status = COVERAGE_COMPLETE

    if stream_gaps:
        coverage.status = (COVERAGE_PARTIAL if coverage.status != COVERAGE_UNSUPPORTED_DECODE
                           else coverage.status)
        coverage.reasons.append(
            f"{stream_gaps} stream gap(s) lost {stream_missing_bytes} byte(s); "
            "stream-derived findings are supported only by captured ranges"
        )
    if sessions_dropped:
        coverage.status = (COVERAGE_PARTIAL if coverage.status != COVERAGE_UNSUPPORTED_DECODE
                           else coverage.status)
        coverage.reasons.append(
            f"{sessions_dropped} conversation(s) were dropped at the session cap "
            f"({settings.get('max_sessions')})"
        )
    if payloads_capped:
        coverage.reasons.append(
            f"{payloads_capped} direction(s) were head-capped at "
            f"{settings.get('max_payload_bytes')} bytes; volume counters still "
            "count every transmitted byte"
        )

    if coverage.status == COVERAGE_COMPLETE:
        coverage.reasons.append(
            f"all {frames_read} frames decoded; no stream gaps were observed"
        )

    for note in getattr(report, "notes", []) or []:
        coverage.limits.append(note)

    if settings.get("retained_packets") is False:
        coverage.limits.append(
            "packets were streamed, not retained; per-packet inspection is unavailable "
            "in this result"
        )
    return coverage


def coverage_summary(coverage: Coverage, findings_total: int) -> str:
    """One sentence an analyst can act on — never an unconditional all-clear."""
    if coverage.status == COVERAGE_UNSUPPORTED_DECODE:
        return ("Analysis could not decode the relevant traffic "
                f"({coverage.reasons[0] if coverage.reasons else 'unsupported framing'}). "
                "Zero findings here does not mean the capture was clean.")
    if coverage.status == COVERAGE_EMPTY:
        return "The capture is empty; there is nothing to analyse."
    if coverage.status == COVERAGE_PARTIAL:
        base = ("Analysis was partial"
                + (f": {coverage.reasons[0]}" if coverage.reasons else "")
                + ".")
        return f"{base} {findings_total} finding(s) were recorded in the decoded traffic."
    if findings_total == 0:
        return (f"Complete analysis of {coverage.frames_read} frame(s): "
                "no configured rule matched this traffic.")
    return (f"Complete analysis of {coverage.frames_read} frame(s): "
            f"{findings_total} finding(s) recorded.")
