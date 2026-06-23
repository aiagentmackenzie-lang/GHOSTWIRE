"""C2 IOC feed loader (production-plan Phase 4.2).

Lets operators (and a shipped, cited snapshot) extend the runtime C2 database
with external IOC entries without editing code. Each entry carries a
`source` and `confidence` so matches stay attributable; no invented hashes
(see the audit's honesty policy — decision Q3: commit a cited snapshot,
license-check before adding CIRCL hashes).

Feed file format (JSON, one file = one list of entries):

    [
      {
        "tool": "cobalt_strike",
        "match_type": "ja4",
        "value": "t13d1516h2_",
        "confidence": 0.70,
        "source": "FoxIO JA4 research dataset",
        "license": "FoxIO JA4 datasets (public research)"
      }
    ]

`match_type` is one of: ja4, ja3, http_ua, ssh_banner, ssh_software.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

VALID_MATCH_TYPES = {"ja4", "ja3", "http_ua", "ssh_banner", "ssh_software"}


@dataclass(frozen=True)
class FeedEntry:
    tool: str
    match_type: str
    value: str
    confidence: float
    source: str
    license: str = ""

    def __post_init__(self) -> None:
        if self.match_type not in VALID_MATCH_TYPES:
            raise ValueError(f"invalid match_type {self.match_type!r}; expected one of {VALID_MATCH_TYPES}")
        if not self.tool or not self.value:
            raise ValueError("feed entry requires non-empty tool and value")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence {self.confidence} out of [0,1]")


def load_feed_file(path: str | Path) -> list[FeedEntry]:
    """Load and validate a single feed JSON file."""
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"feed {p} must be a JSON list of entries")
    entries: list[FeedEntry] = []
    for i, item in enumerate(data):
        try:
            entries.append(FeedEntry(
                tool=item["tool"],
                match_type=item["match_type"],
                value=item["value"],
                confidence=float(item["confidence"]),
                source=item.get("source", "unspecified"),
                license=item.get("license", ""),
            ))
        except (KeyError, ValueError, TypeError) as e:
            raise ValueError(f"feed {p} entry {i} invalid: {e}") from e
    return entries


def load_feeds_from_dir(dir_path: str | Path) -> list[FeedEntry]:
    """Load every *.json feed file in a directory (non-recursive)."""
    d = Path(dir_path)
    if not d.is_dir():
        return []
    entries: list[FeedEntry] = []
    for fp in sorted(d.glob("*.json")):
        try:
            entries.extend(load_feed_file(fp))
            logger.info(f"Loaded feed {fp.name}: {len(entries)} cumulative entries")
        except (ValueError, OSError) as e:
            logger.warning(f"Skipping feed {fp}: {e}")
    return entries


def apply_feeds(entries: list[FeedEntry], patterns: dict) -> int:
    """Merge feed entries into a KNOWN_C2_PATTERNS-shaped dict in place.

    Returns the number of entries applied. Idempotent-ish: duplicate (tool,
    match_type, value) entries are appended again (operators should keep feeds
    deduped); matching is unaffected by duplicates.
    """
    applied = 0
    for e in entries:
        tool_block = patterns.setdefault(e.tool, {
            "description": f"{e.tool} (feed-sourced)",
            "mitre": [],
            "ja3_hashes": [],
            "ja4_patterns": [],
            "http_patterns": {"user_agents": [], "uri_patterns": []},
            # SSH banners/software stored alongside http_patterns for now.
        })
        if e.match_type == "ja4":
            tool_block.setdefault("ja4_patterns", []).append(
                (e.value, "feed", e.source)
            )
        elif e.match_type == "ja3":
            tool_block.setdefault("ja3_hashes", []).append(e.value)
        elif e.match_type == "http_ua":
            tool_block.setdefault("http_patterns", {}).setdefault("user_agents", []).append(
                (e.value, e.confidence, e.source)
            )
        elif e.match_type in ("ssh_banner", "ssh_software"):
            tool_block.setdefault("ssh_patterns", {})[e.match_type] = e.value
        applied += 1
    return applied
