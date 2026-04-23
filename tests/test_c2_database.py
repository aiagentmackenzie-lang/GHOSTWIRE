"""Tests for C2 database matching (engine/fingerprint/c2_database.py)."""

import pytest
from engine.fingerprint.c2_database import match_all, match_http, match_ja3, match_ja4, match_ssh


class TestMatchHTTP:
    """Tests for HTTP User-Agent C2 matching."""

    def test_known_ua_matches_cobalt_strike(self):
        """Exact Cobalt Strike UA should match with high confidence."""
        ua = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0)"
        matches = match_http(ua)
        cs_matches = [m for m in matches if m.tool_name == "cobalt_strike"]
        # Should have a high-confidence exact match
        exact = [m for m in cs_matches if m.confidence >= 0.85]
        assert len(exact) > 0, f"Known Cobalt Strike UA should match, got: {matches}"

    def test_partial_ua_lower_confidence(self):
        """Partial UA match should yield lower confidence than exact."""
        ua = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; extra)"
        matches = match_http(ua)
        cs_matches = [m for m in matches if m.tool_name == "cobalt_strike"]
        if cs_matches:
            # Partial match confidence should be < 0.90 (exact match threshold)
            assert cs_matches[0].confidence < 0.90

    def test_unknown_ua_no_match(self):
        """A normal browser UA should not match any C2 tool."""
        ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        matches = match_http(ua)
        assert len(matches) == 0, "Normal browser UA should not trigger C2 match"

    def test_go_http_client_matches_sliver(self):
        """Go HTTP client UA should match Sliver C2."""
        ua = "Go-http-client/1.1"
        matches = match_http(ua)
        sliver_matches = [m for m in matches if m.tool_name == "sliver"]
        assert len(sliver_matches) > 0, "Go-http-client should match Sliver"


class TestMatchSSH:
    """Tests for SSH banner C2 matching."""

    def test_paramiko_banner_flags(self):
        """Paramiko SSH client should flag as suspicious."""
        matches = match_ssh("SSH-2.0-Paramiko_2.12.0", "Paramiko")
        assert len(matches) > 0, "Paramiko should flag SSH-based C2 tunnel"
        assert matches[0].confidence >= 0.4


class TestMatchJA3:
    """Tests for JA3 hash matching."""

    def test_empty_ja3_no_match(self):
        """Empty JA3 should return no matches."""
        assert match_ja3("") == []

    def test_placeholder_hash_matches(self):
        """A known Cobalt Strike JA3 hash from the C2 database should match."""
        result = match_ja3("72a5876e4ce4f4a1a0b5e1a8e9c7f3d2")
        assert len(result) > 0, "Known CS JA3 hash should match cobalt_strike"


class TestMatchJA4:
    """Tests for JA4 pattern prefix matching."""

    def test_empty_ja4_no_match(self):
        """Empty JA4 should return no matches."""
        assert match_ja4("") == []

    def test_cobalt_strike_prefix_matches(self):
        """JA4 starting with a known CS prefix should match."""
        result = match_ja4("t13d1516h2_abcdef123456")
        cs = [m for m in result if m.tool_name == "cobalt_strike"]
        assert len(cs) > 0, "JA4 with CS prefix should match"


class TestMatchAll:
    """Tests for the combined match_all function."""

    def test_no_input_no_matches(self):
        """Empty inputs should return no matches."""
        assert match_all() == []

    def test_user_agent_triggers_match(self):
        """match_all with a known UA should return matches."""
        results = match_all(user_agent="Go-http-client/1.1")
        assert len(results) > 0

    def test_deduplication(self):
        """Same tool matched via multiple methods should be deduplicated."""
        # Provide both JA3 and UA for cobalt_strike
        results = match_all(
            ja3="72a5876e4ce4f4a1a0b5e1a8e9c7f3d2",
            user_agent="Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0)",
        )
        cs_matches = [m for m in results if m.tool_name == "cobalt_strike"]
        # Should be deduplicated to one entry (highest confidence)
        assert len(cs_matches) == 1