"""Detection-accuracy harness (production-plan Phase 4.1).

Three corpora, each with a documented expected outcome:

  (a) benign_browsing.pcap — normal traffic — MUST be zero detections.
      This is the single most important "real tool" signal: we do not cry
      wolf. If this fails, tune detection BEFORE weakening the fixture.
  (b) beacon_pcap          — synthetic steady-interval C2 beacon — MUST be HIGH.
  (c) dns_pcap             — DNS tunneling (long-label TXT) — MUST flag.

Expected FP/FN per fixture are documented in tests/corpus/README.md.
"""
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Use sys.executable so tests work in CI (no .venv) and locally (.venv).
PYTHON_BIN = sys.executable


def _run_cli(*args, timeout=30):
    cmd = [PYTHON_BIN, "-m", "engine.cli"] + list(args)
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, cwd=str(PROJECT_ROOT),
    )
    return result.returncode, result.stdout, result.stderr


class TestBenignCorpus:
    """Normal browsing traffic must produce ZERO detections (no false positives)."""

    def test_benign_browsing_zero_beacons(self, benign_pcap):
        code, stdout, stderr = _run_cli("analyze", benign_pcap, "--output", "json")
        assert code == 0, f"stderr: {stderr}"
        data = json.loads(stdout)
        assert data["beacons_detected"] == 0, (
            f"FALSE POSITIVE: benign corpus flagged {data['beacons_detected']} beacons "
            f"(sessions={data['sessions_total']}, packets={data['packets_total']})"
        )

    def test_benign_browsing_zero_c2_matches(self, benign_pcap):
        code, stdout, stderr = _run_cli("analyze", benign_pcap, "--output", "json")
        assert code == 0, f"stderr: {stderr}"
        data = json.loads(stdout)
        assert data["c2_matches"] == 0, (
            f"FALSE POSITIVE: benign corpus produced {data['c2_matches']} C2 matches "
            f"(tls_fingerprints={data['tls_fingerprints']}, http_fingerprints={data['http_fingerprints']})"
        )

    def test_benign_browsing_zero_dns_threats(self, benign_pcap):
        code, stdout, stderr = _run_cli("analyze", benign_pcap, "--output", "json")
        assert code == 0, f"stderr: {stderr}"
        data = json.loads(stdout)
        assert data["dns_threats"] == 0, (
            f"FALSE POSITIVE: benign corpus flagged {data['dns_threats']} DNS threats"
        )

    def test_benign_browsing_parses_real_sessions(self, benign_pcap):
        """Sanity: the benign corpus is non-trivial — it must actually parse
        into a realistic number of sessions and packets, so a zero-detection
        result is meaningful and not an artifact of a broken fixture."""
        code, stdout, stderr = _run_cli("analyze", benign_pcap, "--output", "json")
        assert code == 0, f"stderr: {stderr}"
        data = json.loads(stdout)
        assert data["packets_total"] >= 80, f"Fixture too small: {data['packets_total']} packets"
        assert data["sessions_total"] >= 25, f"Too few sessions: {data['sessions_total']}"


class TestKnownPositiveCorpus:
    """Known-malicious traffic MUST be detected (no false negatives)."""

    def test_beacon_corpus_detected_high(self, beacon_pcap):
        code, stdout, stderr = _run_cli("analyze", beacon_pcap, "--output", "json")
        assert code == 0, f"stderr: {stderr}"
        data = json.loads(stdout)
        assert data["beacons_detected"] >= 1, "FALSE NEGATIVE: beacon corpus not detected"
        threats = data["threats"]
        assert threats, "Beacon should produce a threat score above min-score"
        top = max(threats, key=lambda t: t["overall_score"])
        assert top["confidence"] == "HIGH", (
            f"Textbook beacon should reach HIGH, got {top['confidence']} ({top['overall_score']})"
        )

    def test_dns_tunnel_corpus_detected(self, dns_pcap):
        code, stdout, stderr = _run_cli("analyze", dns_pcap, "--output", "json")
        assert code == 0, f"stderr: {stderr}"
        data = json.loads(stdout)
        assert data["dns_threats"] >= 1, "FALSE NEGATIVE: DNS tunneling not detected"

    def test_c2_ua_corpus_detected(self, c2_http_pcap):
        code, stdout, stderr = _run_cli("analyze", c2_http_pcap, "--output", "json")
        assert code == 0, f"stderr: {stderr}"
        data = json.loads(stdout)
        assert data["c2_matches"] >= 1, "FALSE NEGATIVE: Cobalt Strike UA not matched"


class TestIPv6Corpus:
    """IPv6 traffic must parse and detect (production-plan Phase 2.1)."""

    def test_ipv6_beacon_detected(self, ipv6_beacon_pcap):
        """An IPv6 steady-interval beacon must be flagged — exercises IPv6 parse
        + IPv6 external classification in hunt._is_private_ip."""
        code, stdout, stderr = _run_cli("analyze", ipv6_beacon_pcap, "--output", "json")
        assert code == 0, f"stderr: {stderr}"
        data = json.loads(stdout)
        assert data["beacons_detected"] >= 1, (
            f"IPv6 beacon not detected (sessions={data['sessions_total']}, "
            f"packets={data['packets_total']})"
        )

    def test_ipv6_dns_threat_detected(self, ipv6_dns_pcap):
        """An IPv6-transported long-label TXT DNS query must flag a threat."""
        code, stdout, stderr = _run_cli("analyze", ipv6_dns_pcap, "--output", "json")
        assert code == 0, f"stderr: {stderr}"
        data = json.loads(stdout)
        assert data["dns_threats"] >= 1, "IPv6 DNS tunneling not detected"


class TestSplitTLSReassembly:
    """A ClientHello split across TCP segments must still fingerprint (Phase 2.2)."""

    def test_split_client_hello_fingerprints(self, split_tls_pcap):
        code, stdout, stderr = _run_cli("analyze", split_tls_pcap, "--output", "json")
        assert code == 0, f"stderr: {stderr}"
        data = json.loads(stdout)
        assert data["tls_fingerprints"] >= 1, (
            "Split ClientHello produced no TLS fingerprint - reassembly broken"
        )

    def test_split_client_hello_extracts_sni_and_ja4(self, split_tls_pcap):
        """The reassembled handshake must populate ja4 and sni (the headline
        Phase 2 fix: real captures split the ClientHello across segments)."""
        from engine.cli import _full_analysis
        results = _full_analysis(split_tls_pcap)
        assert results["tls_fps"], "No TLS fingerprint extracted from split ClientHello"
        fp = results["tls_fps"][0]
        assert fp.sni == "evil.example.com", f"SNI not extracted: {fp.sni!r}"
        assert fp.ja4, "JA4 empty - ja4plus did not fingerprint the reassembled hello"
        assert fp.is_client_hello
