"""JA3 conformance against an independent reference capture.

The repository's own ClientHello fixture has one cipher and one extension, so
it cannot reveal a delimiter bug in the JA3 serialisation. Wireshark's
``test/captures/tls13-rfc8446.pcap`` (pinned by commit and SHA-256 in
``tests/fixtures/wireshark_tls13_rfc8446.json``) can.

0.2.x joined every JA3 element with a comma, which produced
``9787a0eb94b2108989fb0c75cf0197e6`` for upstream frame 1 and
``8c5f06f9b7b345704eea0c0258089450`` for frame 7. The published JA3 algorithm
joins list elements with ``-``, giving the values below.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from engine.analysis import run_analysis
from engine.fingerprint.c2_database import _reset_feeds_for_tests
from engine.fingerprint.ja4_engine import (
    JA3_ALGORITHM,
    LEGACY_JA3_ALGORITHM,
    _walk_client_hello,
    legacy_comma_ja3,
)

FIXTURE = Path(__file__).parent / "fixtures" / "wireshark_tls13_rfc8446.json"

#: Published reference digests for the pinned upstream capture (Wireshark
#: 4.6.9 ``tls.handshake.ja3``). Frames are one-based upstream frame numbers.
REFERENCE = {
    1: {
        "ja3": "25bd5fc6fcc031c1c87f93613e0252ce",
        "ja4": "t00i180900_e8a523a41297_78e6aca7449b",
        "legacy_ja3": "9787a0eb94b2108989fb0c75cf0197e6",
    },
    7: {
        "ja3": "7ed44a80eb19c620609c3b5cbc2eafd0",
        "ja4": "t00i181200_e8a523a41297_9fc0c022da54",
        "legacy_ja3": "8c5f06f9b7b345704eea0c0258089450",
    },
}


def _payload(frame_no: int) -> bytes:
    frames = json.loads(FIXTURE.read_text())["frames"]
    return bytes.fromhex(frames[str(frame_no)]["payload"])


class TestReferenceCapture:
    def test_fixture_is_attributed_and_pinned(self):
        meta = json.loads(FIXTURE.read_text())["upstream"]
        assert meta["commit"] == "62874e37789272afdcf97d25339428b60b2c84b0"
        assert meta["sha256"] == (
            "e24aaedb2912f9ea371f8a1fbd360ccccc0154737aa5e422e206cd8bc0b783aa"
        )
        assert meta["path"] == "test/captures/tls13-rfc8446.pcap"

    def test_both_reference_ja3_digests_match_through_the_analysis_entry_point(
            self, wireshark_tls13_client_hellos_pcap):
        result = run_analysis(wireshark_tls13_client_hellos_pcap)
        assert len(result.tls_fps) == 2, [f.to_dict() for f in result.tls_fps]

        client_hellos = [f for f in result.tls_fps if f.is_client_hello]
        assert len(client_hellos) == 2

        by_frame = {}
        for fp in client_hellos:
            assert fp.ja3_algorithm == JA3_ALGORITHM
            by_frame[fp.session_id] = fp

        digests = sorted(fp.ja3_hash for fp in client_hellos)
        assert digests == sorted([REFERENCE[1]["ja3"], REFERENCE[7]["ja3"]])

    def test_reference_ja4_values_still_match(self, wireshark_tls13_client_hellos_pcap):
        result = run_analysis(wireshark_tls13_client_hellos_pcap)
        ja4s = sorted(fp.ja4 for fp in result.tls_fps if fp.is_client_hello)
        assert ja4s == sorted([REFERENCE[1]["ja4"], REFERENCE[7]["ja4"]])

    def test_legacy_comma_algorithm_is_reproducible_and_labelled(self):
        """Historical values stay identifiable by their producing revision."""
        for frame_no, expected in REFERENCE.items():
            parsed = _walk_client_hello(_payload(frame_no))
            assert parsed is not None
            assert legacy_comma_ja3(parsed) == expected["legacy_ja3"]
            assert legacy_comma_ja3(parsed) != expected["ja3"]

        from engine.fingerprint.ja4_engine import JA3_ALGORITHM_REVISIONS
        assert LEGACY_JA3_ALGORITHM in JA3_ALGORITHM_REVISIONS
        assert JA3_ALGORITHM in JA3_ALGORITHM_REVISIONS
        assert "0.2.x" in JA3_ALGORITHM_REVISIONS[LEGACY_JA3_ALGORITHM]

    def test_saved_result_records_the_producing_algorithm(self, wireshark_tls13_client_hellos_pcap):
        out = run_analysis(wireshark_tls13_client_hellos_pcap).to_output()
        assert out["run"]["versions"]["ja3_algorithm"] == JA3_ALGORITHM
        assert out["run"]["versions"]["ja3_algorithm_notes"][LEGACY_JA3_ALGORITHM]


class TestFeedLookupUsesTheCorrectedValue:
    def test_reference_ja3_matches_a_feed_entry(self, wireshark_tls13_client_hellos_pcap,
                                                tmp_path, monkeypatch):
        """A feed keyed on the *corrected* digest must hit; the old one must miss."""
        feed_dir = tmp_path / "feeds"
        feed_dir.mkdir()
        (feed_dir / "reference.json").write_text(json.dumps([
            {
                "tool": "reference_tls_rule",
                "match_type": "ja3",
                "value": REFERENCE[1]["ja3"],
                "confidence": 0.88,
                "source": "test/reference fixture",
                "license": "test",
            }
        ]))
        monkeypatch.setenv("GHOSTWIRE_FEEDS_DIR", str(feed_dir))
        _reset_feeds_for_tests()
        try:
            result = run_analysis(wireshark_tls13_client_hellos_pcap)
            matches = [f for f in result.findings if f.rule_id == "c2.ja3_exact"]
            assert len(matches) == 1, [f.to_dict() for f in result.findings]
            finding = matches[0]
            assert finding.subject_value == REFERENCE[1]["ja3"]
            # The feed's stated confidence survives loading (0.2.x replaced it).
            assert finding.score == pytest.approx(0.88)
            assert "test/reference fixture" in finding.provenance["rule_source"]
        finally:
            _reset_feeds_for_tests()
            os.environ.pop("GHOSTWIRE_FEEDS_DIR", None)

    def test_legacy_digest_does_not_match_the_corrected_feed(self, tmp_path, monkeypatch):
        feed_dir = tmp_path / "feeds2"
        feed_dir.mkdir()
        (feed_dir / "reference.json").write_text(json.dumps([
            {
                "tool": "reference_tls_rule",
                "match_type": "ja3",
                "value": REFERENCE[1]["ja3"],
                "confidence": 0.88,
                "source": "test/reference fixture",
                "license": "test",
            }
        ]))
        from engine.fingerprint.c2_database import match_ja3

        monkeypatch.setenv("GHOSTWIRE_FEEDS_DIR", str(feed_dir))
        _reset_feeds_for_tests()
        try:
            assert match_ja3(REFERENCE[1]["legacy_ja3"]) == []
            assert match_ja3(REFERENCE[1]["ja3"])
        finally:
            _reset_feeds_for_tests()
            os.environ.pop("GHOSTWIRE_FEEDS_DIR", None)
