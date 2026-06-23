"""C2 feed loader tests (production-plan Phase 4.2)."""
import json

import pytest
from click.testing import CliRunner

from engine.cli import cli
from engine.feeds.loader import FeedEntry, apply_feeds, load_feed_file
from engine.fingerprint.c2_database import KNOWN_C2_PATTERNS, match_ja4


def _feed_file(tmp_path, entries):
    p = tmp_path / "feed.json"
    p.write_text(json.dumps(entries))
    return str(p)


class TestFeedLoader:
    def test_load_valid_feed(self, tmp_path):
        p = _feed_file(tmp_path, [
            {"tool": "acme_c2", "match_type": "ja4", "value": "t13d9999h2_",
             "confidence": 0.7, "source": "test", "license": "test"},
        ])
        entries = load_feed_file(p)
        assert len(entries) == 1
        assert entries[0].tool == "acme_c2"

    def test_invalid_match_type_rejected(self, tmp_path):
        p = _feed_file(tmp_path, [
            {"tool": "x", "match_type": "bogus", "value": "y", "confidence": 0.5},
        ])
        with pytest.raises(ValueError, match="invalid match_type"):
            load_feed_file(p)

    def test_confidence_out_of_range_rejected(self, tmp_path):
        p = _feed_file(tmp_path, [
            {"tool": "x", "match_type": "ja4", "value": "y", "confidence": 1.5},
        ])
        with pytest.raises(ValueError, match="out of"):

            load_feed_file(p)

    def test_apply_feeds_extends_runtime_db(self):
        patterns = {"existing_tool": {"ja4_patterns": []}}
        n = apply_feeds([FeedEntry("new_tool", "ja4", "t13d1111h2_", 0.7, "t")], patterns)
        assert n == 1
        assert "new_tool" in patterns
        assert patterns["new_tool"]["ja4_patterns"][0][0] == "t13d1111h2_"

    def test_bundled_sample_feed_loads(self):
        from pathlib import Path
        sample = Path(__file__).resolve().parent.parent / "engine" / "feeds" / "sample_feed.json"
        entries = load_feed_file(sample)
        assert len(entries) >= 4
        # Every bundled entry is attributed (no invented/anonymous hashes).
        for e in entries:
            assert e.source, f"entry {e} has no source"
            assert e.license, f"entry {e} has no license"

    def test_match_ja4_picks_up_feed_entry(self):
        """A feed-sourced JA4 prefix must produce a match via the runtime DB."""
        # acme_c2 is not in the curated DB; add it via apply_feeds + force a
        # fresh match. KNOWN_C2_PATTERNS is mutated in place by apply_feeds.
        apply_feeds([FeedEntry("acme_c2", "ja4", "t99d0101h2_", 0.7, "test-feed")],
                    KNOWN_C2_PATTERNS)
        matches = match_ja4("t99d0101h2_abcdef")
        tools = [m.tool_name for m in matches]
        assert "acme_c2" in tools, f"feed entry not matched: {tools}"


class TestRefreshFeedsCli:
    def test_refresh_feeds_lists_bundled_feed(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["refresh-feeds"])
        assert result.exit_code == 0, result.output
        assert "feed entries" in result.output
        # The bundled sample feed cites cobalt_strike / metasploit / sliver.
        assert "cobalt_strike" in result.output or "metasploit" in result.output
