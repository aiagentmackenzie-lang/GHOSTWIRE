"""Tests for C2 database matching (engine/fingerprint/c2_database.py)."""

from engine.fingerprint.c2_database import (
    KNOWN_C2_PATTERNS,
    match_all,
    match_http,
    match_ja3,
    match_ja4,
    match_ssh,
)


class TestMatchHTTP:
    """Tests for HTTP User-Agent C2 matching (exact match only — audit M-10)."""

    def test_known_ua_matches_cobalt_strike(self):
        """Exact Cobalt Strike UA should match with high confidence."""
        ua = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0)"
        matches = match_http(ua)
        cs_matches = [m for m in matches if m.tool_name == "cobalt_strike"]
        exact = [m for m in cs_matches if m.confidence >= 0.85]
        assert len(exact) > 0, f"Known Cobalt Strike UA should match, got: {matches}"

    def test_non_exact_ua_no_match(self):
        """A UA that only differs by a suffix must NOT match (no substring matching)."""
        ua = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; extra)"
        matches = match_http(ua)
        cs_matches = [m for m in matches if m.tool_name == "cobalt_strike"]
        assert len(cs_matches) == 0, "Substring/partial UA matching was removed (audit M-10)"

    def test_unknown_browser_ua_no_match(self):
        """A normal browser UA should not match any C2 tool."""
        ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        matches = match_http(ua)
        assert len(matches) == 0, "Normal browser UA should not trigger C2 match"

    def test_brute_ratel_chrome_ua_not_matched(self):
        """Brute Ratel's documented UA is a generic Chrome string; we must not
        ship it as an indicator (audit M-10) or every Chrome client false-positives."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/108.0"
        matches = match_http(ua)
        br = [m for m in matches if m.tool_name == "brute_ratel"]
        assert len(br) == 0, "Generic Chrome UA must not match Brute Ratel"

    def test_go_http_client_matches_sliver(self):
        """Go HTTP client UA should match Sliver C2 (exact)."""
        ua = "Go-http-client/1.1"
        matches = match_http(ua)
        sliver_matches = [m for m in matches if m.tool_name == "sliver"]
        assert len(sliver_matches) > 0, "Go-http-client should match Sliver"
        assert sliver_matches[0].confidence >= 0.90


class TestMatchSSH:
    """Tests for SSH banner C2 matching."""

    def test_paramiko_banner_flags(self):
        """Paramiko SSH client should flag as suspicious (behavioral heuristic)."""
        matches = match_ssh("SSH-2.0-Paramiko_2.12.0", "Paramiko")
        assert len(matches) > 0, "Paramiko should flag SSH-based C2 tunnel"
        assert matches[0].confidence >= 0.4

    def test_clean_openssh_no_flag(self):
        """A normal OpenSSH banner should not flag."""
        matches = match_ssh("SSH-2.0-OpenSSH_8.9p1", "OpenSSH_8.9p1")
        assert len(matches) == 0


class TestMatchJA3:
    """Tests for JA3 hash matching.

    The database ships no fabricated JA3 hashes (audit H-03). These tests prove
    the matching mechanism works by injecting an attributed hash at test time,
    without shipping an invented IOC in production code.
    """

    def test_empty_ja3_no_match(self):
        assert match_ja3("") == []

    def test_unknown_ja3_no_match(self):
        """A hash not in the database returns no matches."""
        assert match_ja3("deadbeef" * 4) == []

    def test_attributed_hash_matches(self, monkeypatch):
        """Injecting an attributed hash into the DB makes match_ja3 fire."""
        cs = KNOWN_C2_PATTERNS["cobalt_strike"]
        monkeypatch.setitem(cs, "ja3_hashes", [("aabbccdd" * 4, 0.90)])
        result = match_ja3("aabbccdd" * 4)
        assert len(result) == 1
        assert result[0].tool_name == "cobalt_strike"
        assert result[0].confidence == 0.90


class TestMatchJA4:
    """Tests for JA4 pattern prefix matching (research_prefix → 0.70)."""

    def test_empty_ja4_no_match(self):
        assert match_ja4("") == []

    def test_cobalt_strike_prefix_matches(self):
        """JA4 starting with a known CS prefix should match at 0.70 (research tier)."""
        result = match_ja4("t13d1516h2_abcdef123456_789012345678")
        cs = [m for m in result if m.tool_name == "cobalt_strike"]
        assert len(cs) > 0, "JA4 with CS prefix should match"
        assert cs[0].confidence == 0.70, "JA4 prefix matches tier at 0.70 (research_prefix)"

    def test_unknown_prefix_no_match(self):
        assert match_ja4("t99d9999h9_unknown") == []


class TestMatchAll:
    """Tests for the combined match_all function."""

    def test_no_input_no_matches(self):
        assert match_all() == []

    def test_user_agent_triggers_match(self):
        results = match_all(user_agent="Go-http-client/1.1")
        assert len(results) > 0

    def test_deduplication(self):
        """Same tool matched via JA4 + UA should dedupe to one entry (highest confidence)."""
        results = match_all(
            ja4="t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb",
            user_agent="Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0)",
        )
        cs_matches = [m for m in results if m.tool_name == "cobalt_strike"]
        assert len(cs_matches) == 1, "Cobalt Strike should dedupe to one entry"
        # UA exact match (0.90) wins over JA4 prefix (0.70)
        assert cs_matches[0].confidence == 0.90


class TestUANormalization:
    """Phase 6.3: whitespace normalization must not break exact-match semantics."""

    def test_trailing_space_still_matches(self):
        ua = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0) "
        assert [m.tool_name for m in match_http(ua)] == ["cobalt_strike"]

    def test_doubled_internal_space_still_matches(self):
        ua = "Mozilla/5.0  (compatible; MSIE 9.0; Windows NT 6.0)"
        assert [m.tool_name for m in match_http(ua)] == ["cobalt_strike"]

    def test_substring_still_does_not_match(self):
        # Exact semantics preserved: an extra token must NOT match.
        ua = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; extra)"
        assert match_http(ua) == []
