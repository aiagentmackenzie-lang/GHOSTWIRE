"""STIX 2.1 export — carry the observed subject, not a label.

The 0.2.x exporter turned every address in a threat target into an
``ipv4-addr`` indicator, labelled both peers "c2_communication", and dropped the
matched User-Agent entirely. An analyst importing that bundle got a claim
("these two addresses are C2") without the observation behind it.

Wave 1 changes the disposition:

* **Indicators are raised only for the subject a rule actually matched** — the
  DNS name in the query, or the HTTP request header value. Each indicator
  carries its provenance (capture digest, frames, rule id/revision, reasons) as
  a custom ``x_ghostwire_provenance`` property.
* **Addresses stay conversation context.** They are exported as SCOs inside an
  ``observed-data`` object, never as indicators, because sharing an address is
  not evidence that the address is malicious.
* **Every finding is exported** as an ``x-ghostwire-finding`` SDO with an
  explicit ``export_disposition`` and the reason for it. A TLS fingerprint, for
  example, has no standard STIX patterning target in 2.1, so it is exported as
  a finding with provenance rather than forced into a non-valid custom SCO
  pattern.

``validate_bundle`` checks format; ``import_bundle`` checks meaning. The two
are deliberately separate checks — a syntactically valid bundle full of the
wrong indicators still fails.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from engine.export.mitre_map import TECHNIQUE_MAP

logger = logging.getLogger(__name__)

_STIX_ID_RE = re.compile(
    r"^(?P<type>[a-z][a-z0-9-]*--)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

#: STIX 2.1 observable types we emit. Custom SCOs would be legal, but a custom
#: type inside an indicator *pattern* is not, so anything without a standard
#: patterning target is exported as a finding instead.
_STANDARD_SCO_TYPES = {
    "ipv4-addr", "ipv6-addr", "domain-name", "network-traffic", "url", "file",
}


def _stix_id(obj_type: str) -> str:
    """Generate a deterministic-per-content STIX 2.1 compliant ID."""
    return f"{obj_type}--{uuid.uuid4()}"


def _now(ts: float | None = None) -> str:
    """ISO 8601 timestamp (capture time when known, otherwise now)."""
    if ts is not None:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    else:
        dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _quote(value: str) -> str:
    """Escape a value for a STIX pattern string literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


# ─── Legacy helpers (kept: callers and tests use them) ──────────────────────

def build_stix_bundle(
    iocs: list[dict],
    description: str = "GHOSTWIRE automated analysis",
    source_file: str = "",
) -> dict:
    """Build a STIX 2.1 Bundle from a flat IOC list.

    This is the pre-Wave-1 entry point. It is kept because it is a public
    function, but the analysis pipeline uses
    :func:`build_bundle_from_analysis`, which carries provenance and export
    dispositions. Do not add new callers.
    """
    objects: list[dict] = []
    created = _now()

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

    for ioc in iocs:
        ioc_type = ioc.get("type", "")
        value = ioc.get("value", "")
        confidence = ioc.get("confidence", 0)
        threat_type = ioc.get("threat_type", "unknown")
        mitre_techniques = ioc.get("mitre_techniques", [])

        if not value:
            continue

        indicator_id = _stix_id("indicator")

        if ioc_type == "ipv4-addr" or _looks_like_ip(value):
            pattern = f"[ipv4-addr:value = '{_quote(value)}']"
        elif ioc_type == "domain-name" or _looks_like_domain(value):
            pattern = f"[domain-name:value = '{_quote(value)}']"
        elif ioc_type == "url":
            pattern = f"[url:value = '{_quote(value)}']"
        elif ioc_type == "file-hash":
            pattern = f"[file:hashes.'SHA-256' = '{_quote(value)}']"
        elif "ja4" in ioc_type.lower() or "ja3" in ioc_type.lower():
            pattern = f"[x-ghostwire-tls-fingerprint:value = '{_quote(value)}']"
        else:
            pattern = f"[x-ghostwire-ioc:value = '{_quote(value)}']"

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


# ─── Evidence-driven export ─────────────────────────────────────────────────

def _indicator_for_finding(finding: dict) -> tuple[str, str] | None:
    """Return (pattern, label) for a finding whose subject has a standard target.

    Returns None when STIX 2.1 has no standard patterning target for the
    subject — the finding is then exported as an ``x-ghostwire-finding``
    instead of being forced into an invalid custom-SCO pattern.
    """
    kind = finding.get("kind", "")
    subject = finding.get("subject", {}) or {}
    value = subject.get("value", "")
    if not value:
        return None
    if kind == "dns" and subject.get("type") == "domain":
        return (f"[domain-name:value = '{_quote(value)}']", "dns-query")
    if kind == "http_header" and subject.get("type") == "http_header":
        return (
            "[network-traffic:extensions.'http-request-ext'"
            f".request_header.'User-Agent' = '{_quote(value)}']",
            "http-request-header",
        )
    if kind == "ssh_banner":
        # No standard SSH banner patterning target in STIX 2.1.
        return None
    return None


def _endpoint_sco(endpoint: dict) -> dict:
    ip = endpoint.get("ip", "")
    if ":" in ip:
        return {"type": "ipv6-addr", "spec_version": "2.1",
                "id": _stix_id("ipv6-addr"), "value": ip}
    return {"type": "ipv4-addr", "spec_version": "2.1",
            "id": _stix_id("ipv4-addr"), "value": ip}


def build_bundle_from_analysis(analysis: dict) -> dict:
    """Build a STIX 2.1 bundle from a GHOSTWIRE versioned analysis result.

    Selection mirrors the analysis output: every finding is exported, and for
    each finding an explicit ``export_disposition`` records whether the
    observed subject became an indicator, remained conversation context, or was
    exported as a finding only — with the reason.
    """
    objects: list[dict] = []
    capture = (analysis.get("run") or {}).get("capture") or {}
    capture_sha = analysis.get("capture_sha256") or capture.get("sha256", "")
    created = _now(capture.get("first_timestamp"))
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

    observations = {o.get("observation_id"): o for o in analysis.get("observations", [])}
    findings = analysis.get("findings", [])
    context_sco_ids: list[str] = []
    exported_indicators: set[str] = set()

    for finding in findings:
        pattern_info = _indicator_for_finding(finding)
        obs_refs = [
            observations[i] for i in finding.get("observation_ids", []) if i in observations
        ]
        frames = sorted({o.get("frame") for o in obs_refs if o.get("frame")})
        timestamps = [o.get("timestamp") for o in obs_refs if o.get("timestamp") is not None]
        provenance = {
            "finding_id": finding.get("finding_id"),
            "capture_sha256": capture_sha,
            "frames": frames,
            "observation_ids": finding.get("observation_ids", []),
            "rule": finding.get("rule", {}),
            "match_method": finding.get("match_method"),
            "score": finding.get("score"),
            "score_scale": finding.get("score_scale"),
            "reasons": finding.get("reasons", []),
            "conversation_id": finding.get("conversation_id"),
            "engine_version": (analysis.get("run") or {}).get("engine_version"),
            "observed_values": [
                {"field": o.get("field"), "value": o.get("value")} for o in obs_refs
            ],
        }

        indicator_id = None
        if pattern_info is not None:
            pattern, label = pattern_info
            subject_value = finding["subject"]["value"]
            if subject_value in exported_indicators:
                # One indicator per distinct observed subject; the second
                # finding links to the same indicator instead of duplicating it.
                indicator_id = next(
                    (o["id"] for o in objects
                     if o.get("type") == "indicator" and o.get("x_ghostwire_subject") == subject_value),
                    None,
                )
            if indicator_id is None:
                indicator_id = _stix_id("indicator")
                exported_indicators.add(subject_value)
                indicator = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created_by_ref": author_id,
                    "created": created,
                    "modified": created,
                    "name": f"GHOSTWIRE observed: {subject_value}",
                    "description": (
                        f"{finding.get('summary', '')} Observed in {capture_sha or 'capture'} "
                        f"at frame(s) {', '.join(str(f) for f in frames) or 'unknown'}. "
                        "This is an observed value from the capture, not a confirmed compromise."
                    ),
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": _now(min(timestamps) if timestamps else None),
                    "confidence": min(int(round(float(finding.get("score", 0)) * 100)), 100),
                    "labels": [label, finding.get("kind", "finding")],
                    "x_ghostwire_subject": subject_value,
                    "x_ghostwire_provenance": provenance,
                }
                objects.append(indicator)
                disposition = {
                    "disposition": "indicator",
                    "reason": ("the rule's subject is the observed field value; "
                               "provenance records the frames and rule that matched"),
                }
            else:
                disposition = {
                    "disposition": "indicator",
                    "reason": "same observed subject as an earlier finding; indicator reused",
                }
        else:
            disposition = {
                "disposition": "finding-only",
                "reason": ("no standard STIX 2.1 patterning target exists for this "
                           "subject; the finding is exported with provenance instead "
                           "of being forced into a custom observable"),
            }

        finding_obj = {
            "type": "x-ghostwire-finding",
            "spec_version": "2.1",
            "id": _stix_id("x-ghostwire-finding"),
            "created_by_ref": author_id,
            "created": created,
            "modified": created,
            "name": finding.get("summary") or finding.get("kind", "finding"),
            "kind": finding.get("kind"),
            "rule_id": (finding.get("rule") or {}).get("id"),
            "rule_revision": (finding.get("rule") or {}).get("revision"),
            "subject_type": (finding.get("subject") or {}).get("type"),
            "subject_value": (finding.get("subject") or {}).get("value"),
            "export_disposition": disposition["disposition"],
            "export_reason": disposition["reason"],
            "x_ghostwire_provenance": provenance,
        }
        objects.append(finding_obj)

        if indicator_id:
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": _stix_id("relationship"),
                "created_by_ref": author_id,
                "created": created,
                "modified": created,
                "relationship_type": "based-on",
                "source_ref": indicator_id,
                "target_ref": finding_obj["id"],
                "description": "the indicator is derived from this observed finding",
            })

        # Addresses are conversation context, never indicators.
        for obs in obs_refs:
            for side in ("src", "dst"):
                ep = obs.get(side) or {}
                ip = ep.get("ip")
                if not ip:
                    continue
                existing = next(
                    (o["id"] for o in objects
                     if o.get("type") in ("ipv4-addr", "ipv6-addr") and o.get("value") == ip),
                    None,
                )
                if existing is None:
                    sco = _endpoint_sco(ep)
                    objects.append(sco)
                    existing = sco["id"]
                if existing not in context_sco_ids:
                    context_sco_ids.append(existing)

        for tech_id in finding.get("mitre_techniques", []):
            existing = next(
                (o["id"] for o in objects
                 if o.get("type") == "attack-pattern"
                 and any(r.get("external_id") == tech_id
                         for r in o.get("external_references", []))),
                None,
            )
            if existing is None:
                existing = _stix_id("attack-pattern")
                objects.append({
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": existing,
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
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": _stix_id("relationship"),
                "created_by_ref": author_id,
                "created": created,
                "modified": created,
                "relationship_type": "indicates",
                "source_ref": finding_obj["id"],
                "target_ref": existing,
                "description": "the rule that produced this finding maps to the technique",
            })

    if context_sco_ids:
        objects.append({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": _stix_id("observed-data"),
            "created_by_ref": author_id,
            "created": created,
            "modified": created,
            "first_observed": _now(capture.get("first_timestamp")),
            "last_observed": _now(capture.get("last_timestamp")),
            "number_observed": max(int(capture.get("frames_read") or 1), 1),
            "object_refs": context_sco_ids,
            "x_ghostwire_note": ("addresses are conversation context from the capture; "
                                 "they are not indicators"),
        })

    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": objects,
    }
    source_file = analysis.get("file")
    if source_file:
        bundle["description"] = (
            f"GHOSTWIRE analysis of {source_file}"
            + (f" (sha256 {capture_sha})" if capture_sha else "")
        )
    logger.info(f"Built STIX 2.1 bundle with {len(objects)} objects")
    return bundle


# ─── Validation (format) and import (meaning) ───────────────────────────────

def validate_bundle(bundle: dict) -> list[str]:
    """Structural checks for a STIX 2.1 bundle. Returns a list of problems.

    This is a local, dependency-free check of the properties this exporter
    relies on (identity, reference integrity, pattern shape, confidence range).
    It is not a substitute for the OASIS validator; a bundle that passes here
    can still be rejected by a stricter profile.
    """
    problems: list[str] = []
    if not isinstance(bundle, dict):
        return ["bundle is not an object"]
    if bundle.get("type") != "bundle":
        problems.append("bundle.type must be 'bundle'")
    if not _STIX_ID_RE.match(str(bundle.get("id", ""))):
        problems.append("bundle.id must be bundle--<uuid>")
    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        problems.append("bundle.objects must be a non-empty list")
        return problems

    ids: set[str] = set()
    for obj in objects:
        if not isinstance(obj, dict):
            problems.append("bundle.objects contains a non-object")
            continue
        oid = str(obj.get("id", ""))
        otype = str(obj.get("type", ""))
        if not _STIX_ID_RE.match(oid):
            problems.append(f"object id is not <type>--<uuid>: {oid!r}")
        if not oid.startswith(otype + "--"):
            problems.append(f"object id prefix does not match type {otype}: {oid!r}")
        if oid in ids:
            problems.append(f"duplicate object id {oid}")
        ids.add(oid)
        if not otype:
            problems.append("object without type")
        if otype.startswith("x-"):
            if "spec_version" not in obj:
                problems.append(f"custom object {oid} missing spec_version")
        elif otype in _STANDARD_SCO_TYPES:
            if "spec_version" not in obj:
                problems.append(f"SCO {oid} missing spec_version")
        elif otype not in ("bundle",):
            if obj.get("spec_version") != "2.1":
                problems.append(f"SDO {oid} missing spec_version 2.1")
        if otype == "indicator":
            pattern = obj.get("pattern", "")
            if obj.get("pattern_type") != "stix":
                problems.append(f"indicator {oid} pattern_type must be 'stix'")
            if not (isinstance(pattern, str) and pattern.startswith("[") and pattern.endswith("]")):
                problems.append(f"indicator {oid} pattern is not a STIX pattern")
            conf = obj.get("confidence")
            if conf is not None and not (0 <= conf <= 100):
                problems.append(f"indicator {oid} confidence out of 0..100")
            if "x_ghostwire_provenance" not in obj:
                problems.append(f"indicator {oid} lacks provenance")

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        for key in ("created_by_ref", "source_ref", "target_ref"):
            ref = obj.get(key)
            if ref is not None and ref not in ids:
                problems.append(f"{obj.get('id')} {key} points at missing object {ref}")
        for ref in obj.get("object_refs", []) or []:
            if ref not in ids:
                problems.append(f"{obj.get('id')} object_refs missing {ref}")

    return problems


def import_bundle(bundle: dict) -> dict:
    """Read a bundle back into subjects, findings and relationships.

    Used by tests and by anyone checking that the exported *meaning* is right,
    not just that the JSON is well formed.
    """
    exported: dict[str, list[Any]] = {
        "indicators": [],
        "observables": [],
        "findings": [],
        "relationships": [],
        "attack_patterns": [],
        "identities": [],
    }
    by_id: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if not isinstance(obj, dict):
            continue
        by_id[str(obj.get("id"))] = obj
        otype = obj.get("type")
        if otype == "indicator":
            exported["indicators"].append({
                "id": obj.get("id"),
                "pattern": obj.get("pattern"),
                "subject": obj.get("x_ghostwire_subject"),
                "confidence": obj.get("confidence"),
                "provenance": obj.get("x_ghostwire_provenance"),
            })
        elif otype in _STANDARD_SCO_TYPES:
            exported["observables"].append({
                "id": obj.get("id"),
                "type": otype,
                "value": obj.get("value"),
            })
        elif otype == "x-ghostwire-finding":
            exported["findings"].append({
                "id": obj.get("id"),
                "kind": obj.get("kind"),
                "rule_id": obj.get("rule_id"),
                "subject_value": obj.get("subject_value"),
                "export_disposition": obj.get("export_disposition"),
                "provenance": obj.get("x_ghostwire_provenance"),
            })
        elif otype == "relationship":
            exported["relationships"].append({
                "id": obj.get("id"),
                "type": obj.get("relationship_type"),
                "source": obj.get("source_ref"),
                "target": obj.get("target_ref"),
                "source_type": (by_id.get(str(obj.get("source_ref"))) or {}).get("type"),
                "target_type": (by_id.get(str(obj.get("target_ref"))) or {}).get("type"),
            })
        elif otype == "attack-pattern":
            exported["attack_patterns"].append(obj)
        elif otype == "identity":
            exported["identities"].append(obj)
    return exported


# ─── Compatibility helpers ──────────────────────────────────────────────────

def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _looks_like_domain(value: str) -> bool:
    return "." in value and not _looks_like_ip(value) and "/" not in value


def _mitre_name(tech_id: str) -> str:
    """Map MITRE technique IDs to human-readable names.

    Single source of truth: engine.export.mitre_map.TECHNIQUE_MAP (audit M-07 --
    a duplicate dict previously lived here and drifted from mitre_map).
    """
    info = TECHNIQUE_MAP.get(tech_id, {})
    return info.get("name", f"MITRE ATT&CK {tech_id}")


def export_stix(bundle: dict, filepath: str) -> None:
    """Write STIX bundle to JSON file."""
    with open(filepath, "w") as f:
        json.dump(bundle, f, indent=2)
    logger.info(f"STIX bundle exported to {filepath}")


def iocs_from_analysis(analysis: dict) -> list[dict]:
    """Convert an analysis result into IOC dicts (legacy flat list).

    Prefer :func:`build_bundle_from_analysis`, which records an export
    disposition per finding. This helper is kept for compatibility; note that
    it no longer invents IP indicators from a threat target when the analysis
    carries structured findings — in that case only real subjects are returned.
    """
    findings = analysis.get("findings")
    if findings:
        iocs: list[dict] = []
        for finding in findings:
            subject = finding.get("subject") or {}
            value = subject.get("value", "")
            if not value:
                continue
            if subject.get("type") == "domain":
                iocs.append({
                    "type": "domain-name",
                    "value": value,
                    "confidence": finding.get("score", 0),
                    "threat_type": finding.get("kind", "dns"),
                    "mitre_techniques": finding.get("mitre_techniques", []),
                    "description": finding.get("summary", ""),
                })
        return iocs

    iocs = []
    for threat in analysis.get("threats", []):
        target = threat.get("target", "")
        overall_score = threat.get("overall_score", 0)
        mitre_techniques = threat.get("mitre_techniques", [])
        summary = threat.get("summary", "")

        if target:
            for segment in target.split("-"):
                ip_part = segment.split(":")[0]
                if _looks_like_ip(ip_part):
                    iocs.append({
                        "type": "ipv4-addr",
                        "value": ip_part,
                        "confidence": overall_score,
                        "threat_type": "c2_communication",
                        "mitre_techniques": mitre_techniques,
                        "description": summary,
                    })

        for dns in threat.get("dns_threats", []):
            domain = dns.get("domain", "")
            if domain:
                iocs.append({
                    "type": "domain-name",
                    "value": domain,
                    "confidence": dns.get("score", 0),
                    "threat_type": dns.get("threat_type", "dns_threat"),
                    "mitre_techniques": mitre_techniques,
                    "description": f"DNS {dns.get('threat_type', 'threat')}: {domain}",
                })

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
