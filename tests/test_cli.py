"""Tests for CLI commands (integration tests)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_PCAP = PROJECT_ROOT / "samples" / "c2_beacon_test.pcap"
MIXED_PCAP = PROJECT_ROOT / "samples" / "test_mixed.pcap"
VENV_PYTHON = PROJECT_ROOT / ".venv" / "bin" / "python3"


def _run_cli(*args, timeout=30):
    """Run the GHOSTWIRE CLI and return (returncode, stdout, stderr)."""
    cmd = [str(VENV_PYTHON), "-m", "engine.cli"] + list(args)
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

    def test_valid_pcap_returns_json(self):
        """Analyze on a valid PCAP should return JSON with expected keys."""
        code, stdout, stderr = _run_cli("analyze", str(SAMPLE_PCAP), "--output", "json")
        assert code == 0, f"CLI exited with {code}. stderr: {stderr}"
        data = json.loads(stdout)
        expected_keys = [
            "ghostwire_version", "file", "packets_total",
            "sessions_total", "beacons_detected",
        ]
        for key in expected_keys:
            assert key in data, f"Missing key: {key}"

    def test_valid_pcap_detects_beacon(self):
        """C2 beacon test PCAP should detect at least one beacon."""
        code, stdout, stderr = _run_cli("analyze", str(SAMPLE_PCAP), "--output", "json")
        assert code == 0
        data = json.loads(stdout)
        assert data["beacons_detected"] >= 1, "Should detect at least one beacon in C2 test PCAP"

    def test_missing_file_returns_error(self):
        """Analyze on a missing file should return a non-zero exit code."""
        code, stdout, stderr = _run_cli("analyze", "/nonexistent/file.pcap")
        assert code != 0, "Should exit with error for missing file"
        # Should be a clean error message, not a raw traceback
        assert "Traceback" not in stdout, "Should not show raw traceback in stdout"
        assert "Traceback" not in stderr or "Invalid value" in stderr, "Should not show raw traceback in stderr"

    def test_corrupt_file_returns_clean_error(self):
        """Corrupt/invalid file should give clean error, no raw traceback."""
        # Create a temp corrupt file
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(b"This is not a pcap file at all")
            corrupt_path = f.name
        try:
            code, stdout, stderr = _run_cli("analyze", corrupt_path)
            assert code != 0, "Should exit with error for corrupt file"
            # No raw Python traceback in the output
            combined = stdout + stderr
            assert "Traceback (most recent call" not in combined, "Should not show raw traceback"
        finally:
            Path(corrupt_path).unlink(missing_ok=True)


class TestHuntCommand:
    """Integration tests for the 'hunt' command."""

    def test_hunt_all_runs_without_crash(self):
        """Hunt --all on valid PCAP should run without crashing."""
        code, stdout, stderr = _run_cli("hunt", str(SAMPLE_PCAP), "--all", "--output", "json")
        assert code == 0, f"Hunt crashed: {stderr}"
        data = json.loads(stdout)
        assert isinstance(data, dict)

    def test_hunt_no_query_shows_list(self):
        """Hunt with no query should show available hunt queries."""
        code, stdout, stderr = _run_cli("hunt", str(SAMPLE_PCAP))
        assert code == 0


class TestReportCommand:
    """Integration tests for the 'report' command."""

    def test_markdown_report_generated(self):
        """Report should generate a markdown file."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            output_path = f.name
        try:
            code, stdout, stderr = _run_cli(
                "report", str(SAMPLE_PCAP), "--format", "markdown", "--output-file", output_path
            )
            assert code == 0, f"Report failed: {stderr}"
            content = Path(output_path).read_text()
            assert "GHOSTWIRE" in content or "Analysis" in content
        finally:
            Path(output_path).unlink(missing_ok=True)