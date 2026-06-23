"""Tests for CLI commands (integration tests).

Uses scapy-generated PCAP fixtures (see conftest.py) so the suite runs on a
fresh clone with no binary samples committed.
"""

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Use sys.executable so tests work in CI (no .venv) and locally (.venv).
PYTHON_BIN = sys.executable


def _run_cli(*args, timeout=30):
    """Run the GHOSTWIRE CLI and return (returncode, stdout, stderr)."""
    cmd = [PYTHON_BIN, "-m", "engine.cli"] + list(args)
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(PROJECT_ROOT),
    )
    return result.returncode, result.stdout, result.stderr


class TestAnalyzeCommand:
    """Integration tests for the 'analyze' command."""

    def test_valid_pcap_returns_json(self, mixed_pcap):
        """Analyze on a valid PCAP should return JSON with expected keys."""
        code, stdout, stderr = _run_cli("analyze", mixed_pcap, "--output", "json")
        assert code == 0, f"CLI exited with {code}. stderr: {stderr}"
        data = json.loads(stdout)
        expected_keys = [
            "ghostwire_version", "file", "packets_total",
            "sessions_total", "beacons_detected",
        ]
        for key in expected_keys:
            assert key in data, f"Missing key: {key}"

    def test_beacon_pcap_detects_beacon(self, beacon_pcap):
        """The synthetic beacon PCAP should detect at least one beacon."""
        code, stdout, stderr = _run_cli("analyze", beacon_pcap, "--output", "json")
        assert code == 0, f"stderr: {stderr}"
        data = json.loads(stdout)
        assert data["beacons_detected"] >= 1, "Should detect the steady-interval beacon"
        # Audit H-04 gate: a textbook beacon (jitter ≈ 0) must reach HIGH, not LOW.
        threats = data["threats"]
        assert threats, "Beacon should produce a threat score above min-score"
        top = max(threats, key=lambda t: t["overall_score"])
        assert top["confidence"] == "HIGH", (
            f"Textbook beacon should reach HIGH, got {top['confidence']} ({top['overall_score']})"
        )

    def test_tls_pcap_produces_fingerprint(self, tls_pcap):
        """The ClientHello PCAP should produce at least one TLS fingerprint."""
        code, stdout, stderr = _run_cli("analyze", tls_pcap, "--output", "json")
        assert code == 0, f"stderr: {stderr}"
        data = json.loads(stdout)
        assert data["tls_fingerprints"] >= 1, "Should extract a TLS fingerprint from the ClientHello"

    def test_dns_pcap_detects_threat(self, dns_pcap):
        """The DNS tunneling PCAP should flag at least one DNS threat."""
        code, stdout, stderr = _run_cli("analyze", dns_pcap, "--output", "json")
        assert code == 0, f"stderr: {stderr}"
        data = json.loads(stdout)
        assert data["dns_threats"] >= 1, "Should flag the long-subdomain TXT query"

    def test_c2_http_pcap_fires_match(self, c2_http_pcap):
        """The CS-UA HTTP PCAP should produce a cobalt_strike C2 match end-to-end (Phase 2 gate)."""
        code, stdout, stderr = _run_cli("analyze", c2_http_pcap, "--output", "json")
        assert code == 0, f"stderr: {stderr}"
        data = json.loads(stdout)
        assert data["c2_matches"] >= 1, "Should match the Cobalt Strike default User-Agent"

    def test_missing_file_returns_error(self):
        """Analyze on a missing file should return a non-zero exit code."""
        code, stdout, stderr = _run_cli("analyze", "/nonexistent/file.pcap")
        assert code != 0, "Should exit with error for missing file"
        assert "Traceback" not in stdout, "Should not show raw traceback in stdout"
        assert "Traceback" not in stderr or "Invalid value" in stderr, "Should not show raw traceback in stderr"

    def test_corrupt_file_returns_clean_error(self):
        """Corrupt/invalid file should give clean error, no raw traceback."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(b"This is not a pcap file at all")
            corrupt_path = f.name
        try:
            code, stdout, stderr = _run_cli("analyze", corrupt_path)
            assert code != 0, "Should exit with error for corrupt file"
            combined = stdout + stderr
            assert "Traceback (most recent call" not in combined, "Should not show raw traceback"
        finally:
            Path(corrupt_path).unlink(missing_ok=True)


class TestHuntCommand:
    """Integration tests for the 'hunt' command."""

    def test_hunt_all_runs_without_crash(self, mixed_pcap):
        """Hunt --all on valid PCAP should run without crashing."""
        code, stdout, stderr = _run_cli("hunt", mixed_pcap, "--all", "--output", "json")
        assert code == 0, f"Hunt crashed: {stderr}"
        data = json.loads(stdout)
        assert isinstance(data, dict)

    def test_hunt_dns_tunneling_fires(self, dns_pcap):
        """Hunt --query dns_tunneling should find the TXT query (CLI path, not just unit test)."""
        code, stdout, stderr = _run_cli("hunt", dns_pcap, "--query", "dns_tunneling", "--output", "json")
        assert code == 0, f"stderr: {stderr}"
        data = json.loads(stdout)
        findings = data.get("dns_tunneling", [])
        assert len(findings) >= 1, "Hunt should detect DNS tunneling via the CLI path"
        assert any("TXT" in f.get("reason", "") for f in findings)

    def test_hunt_no_query_shows_list(self, beacon_pcap):
        """Hunt with no query should show available hunt queries."""
        code, stdout, stderr = _run_cli("hunt", beacon_pcap)
        assert code == 0


class TestReportCommand:
    """Integration tests for the 'report' command."""

    def test_markdown_report_generated(self, beacon_pcap):
        """Report should generate a markdown file."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            output_path = f.name
        try:
            code, stdout, stderr = _run_cli(
                "report", beacon_pcap, "--format", "markdown", "--output-file", output_path
            )
            assert code == 0, f"Report failed: {stderr}"
            content = Path(output_path).read_text()
            assert "GHOSTWIRE" in content or "Analysis" in content
        finally:
            Path(output_path).unlink(missing_ok=True)
