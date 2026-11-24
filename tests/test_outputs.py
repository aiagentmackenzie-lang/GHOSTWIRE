"""Wave 1 slice 4: every analyst-facing output tells the same story.

Exercises the CLI (analyze + hunt), both human report formats, the STIX export
and its re-import. Views group information differently, so the tests assert the
*evidence* survives and that each view explains its counting unit, threshold
and limits.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from engine.analysis import run_analysis
from engine.export.stix import (
    build_bundle_from_analysis,
    import_bundle,
    validate_bundle,
)

ROOT = Path(__file__).resolve().parent.parent
DNS_DOMAIN = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4.evil.com"
CS_UA = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0)"


def _cli(*args: str, timeout: int = 90):
    proc = subprocess.run(
        [sys.executable, "-m", "engine.cli", *args],
        capture_output=True, text=True, cwd=str(ROOT), timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


# ─── Counting units and denominators ────────────────────────────────────────

class TestCountingUnits:
    def test_one_packet_dns_capture_uses_one_packet_as_denominator(self, dns_pcap):
        code, stdout, stderr = _cli("analyze", dns_pcap, "--output", "json")
        assert code == 0, stderr
        data = json.loads(stdout)
        assert data["packets_total"] == 1
        assert data["protocol_counts"] == {"DNS": 1}
        assert sum(data["protocol_counts"].values()) == data["packets_total"]
        # Findings have their own unit and are not folded into the packet total.
        assert data["selection"]["counts"]["findings_total"] == 1

    def test_complete_zero_findings_is_reported_as_such(self, benign_pcap):
        out = run_analysis(benign_pcap).to_output()
        assert out["selection"]["counts"]["findings_total"] == 0
        assert out["coverage"]["status"] == "complete"
        assert "no configured rule matched" in out["summary"]

    def test_report_distinguishes_filtered_from_empty(self, http_pcap, tmp_path):
        target = tmp_path / "filtered.md"
        code, _, stderr = _cli(
            "report", http_pcap, "--format", "markdown",
            "--min-score", "0.32", "--output-file", str(target),
        )
        assert code == 0, stderr
        text = target.read_text()
        assert CS_UA in text
        assert "Finding 1" in text
        assert "frame" in text.lower()
        assert "sessions_below_threshold" in text or "threshold" in text
        assert "threshold result, not an empty capture" in text
        assert "No significant threats detected in this capture" not in text

    def test_report_marks_partial_coverage(self, truncated_hello_pcap, tmp_path):
        target = tmp_path / "partial.md"
        code, _, stderr = _cli(
            "report", truncated_hello_pcap, "--format", "markdown",
            "--output-file", str(target),
        )
        assert code == 0, stderr
        text = target.read_text()
        assert "Partial" in text
        assert "19" in text and "missing" in text.lower()
        assert "not equivalent to a complete clean result" in text
        assert "No significant threats detected in this capture" not in text


# ─── Human reports carry the observation ────────────────────────────────────

class TestReports:
    def test_markdown_dns_report_exposes_domain_frame_and_reasons(self, dns_pcap, tmp_path):
        target = tmp_path / "dns.md"
        code, _, stderr = _cli("report", dns_pcap, "--format", "markdown",
                               "--output-file", str(target))
        assert code == 0, stderr
        text = target.read_text()
        assert DNS_DOMAIN in text
        assert "**Frame(s):** 1" in text
        assert "dns.tunneling_heuristic" in text
        assert "dns.unusual_qtype" in text
        assert "dns.long_label" in text
        assert "not a probability of compromise" in text
        assert "### Selection" in text
        # The 0.2.x report printed an all-clear next to a DNS count of 1.
        assert "No significant threats detected in this capture" not in text

    def test_text_report_lists_the_observation(self, http_pcap, tmp_path):
        target = tmp_path / "http.txt"
        code, _, stderr = _cli("report", http_pcap, "--format", "text",
                               "--output-file", str(target))
        assert code == 0, stderr
        text = target.read_text()
        assert CS_UA in text
        assert "frame 1" in text
        assert "c2.http_user_agent_exact" in text
        assert "Coverage: complete" in text

    def test_report_records_a_measured_elapsed_time(self, http_pcap, tmp_path):
        target = tmp_path / "timed.md"
        code, _, stderr = _cli("report", http_pcap, "--format", "markdown",
                               "--output-file", str(target))
        assert code == 0, stderr
        text = target.read_text()
        match = re.search(r"\*\*Analysis Time:\*\* ([0-9.]+)s", text)
        assert match, "report must state the measured elapsed time"
        assert float(match.group(1)) >= 0.0
        assert "unavailable" not in text.split("**Analysis Time:**")[1].splitlines()[0]

    def test_markdown_report_matches_the_json_findings(self, http_pcap, tmp_path):
        code, stdout, _ = _cli("analyze", http_pcap, "--output", "json")
        assert code == 0
        data = json.loads(stdout)
        target = tmp_path / "http.md"
        _cli("report", http_pcap, "--format", "markdown", "--output-file", str(target))
        text = target.read_text()
        for finding in data["findings"]:
            assert finding["finding_id"] in text
            assert finding["subject"]["value"] in text
            assert finding["rule"]["id"] in text


# ─── Hunt ───────────────────────────────────────────────────────────────────

class TestHunt:
    def test_hunt_rows_carry_frame_and_endpoints(self, dns_pcap):
        code, stdout, stderr = _cli("hunt", dns_pcap, "--query", "dns_tunneling",
                                    "--output", "json")
        assert code == 0, stderr
        data = json.loads(stdout)
        rows = data["dns_tunneling"]
        assert len(rows) >= 1
        assert all(row["frame"] == 1 for row in rows)
        assert all(row["domain"] == DNS_DOMAIN for row in rows)
        assert rows[0]["endpoints"]["src"]["ip"] == "192.168.1.50"
        assert rows[0]["endpoints"]["dst"]["ip"] == "8.8.8.8"
        assert data["_meta"]["coverage"]["status"] == "complete"
        assert data["_meta"]["counting"]["unit"]

    def test_hunt_cobalt_strike_uses_the_shared_exact_matcher(self, http_pcap):
        code, stdout, stderr = _cli("hunt", http_pcap, "--query", "cobalt_strike",
                                    "--output", "json")
        assert code == 0, stderr
        data = json.loads(stdout)
        rows = data["cobalt_strike"]
        assert len(rows) == 1
        row = rows[0]
        assert row["user_agent"] == CS_UA
        assert row["frame"] == 1
        assert row["rule_id"] == "c2.http_user_agent_exact"
        assert "inference" in row["reason"]

    def test_hunt_does_not_use_substring_matching(self, tmp_path):
        """A UA that merely *contains* a CS default must not match."""
        from scapy.all import IP, TCP, Ether, Raw, wrpcap

        ua = CS_UA + " extra"
        req = f"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: {ua}\r\n\r\n".encode()
        pkt = (Ether() / IP(src="192.168.1.50", dst="185.220.101.34")
               / TCP(sport=49152, dport=80, flags="PA", seq=1, ack=1) / Raw(load=req))
        pkt.time = 1.0
        p = tmp_path / "almost.pcap"
        wrpcap(str(p), [pkt])
        code, stdout, _ = _cli("hunt", str(p), "--query", "cobalt_strike", "--output", "json")
        assert code == 0
        assert json.loads(stdout)["cobalt_strike"] == []


# ─── STIX: format and meaning are checked separately ────────────────────────

class TestStix:
    def _bundle(self, pcap, tmp_path):
        out = tmp_path / "bundle.json"
        code, _, stderr = _cli("report", pcap, "--format", "stix",
                               "--output-file", str(out))
        assert code == 0, stderr
        return json.loads(out.read_text())

    def test_bundle_is_structurally_valid(self, dns_pcap, tmp_path):
        bundle = self._bundle(dns_pcap, tmp_path)
        assert validate_bundle(bundle) == []
        assert bundle["type"] == "bundle"

    def test_dns_subject_survives_import_with_provenance(self, dns_pcap, tmp_path):
        bundle = self._bundle(dns_pcap, tmp_path)
        imported = import_bundle(bundle)

        assert len(imported["indicators"]) == 1
        indicator = imported["indicators"][0]
        assert indicator["subject"] == DNS_DOMAIN
        assert f"[domain-name:value = '{DNS_DOMAIN}']" == indicator["pattern"]
        provenance = indicator["provenance"]
        assert provenance["capture_sha256"] == (
            "a2f6299ae1ab35675896658119ce0bf6f4265adcf8076a875463730de5ad9ff8"
        )
        assert provenance["frames"] == [1]
        assert provenance["rule"]["id"] == "dns.tunneling_heuristic"
        assert provenance["reasons"]

        # Addresses are conversation context, not indicators.
        observable_types = {o["type"] for o in imported["observables"]}
        assert observable_types == {"ipv4-addr"}
        assert all(o["type"] != "indicator" for o in imported["observables"])

    def test_http_header_survives_import_and_addresses_are_context(self, http_pcap, tmp_path):
        bundle = self._bundle(http_pcap, tmp_path)
        assert validate_bundle(bundle) == []
        imported = import_bundle(bundle)

        assert len(imported["indicators"]) == 1
        indicator = imported["indicators"][0]
        assert indicator["subject"] == CS_UA
        assert "http-request-ext" in indicator["pattern"]
        assert indicator["provenance"]["frames"] == [1]
        assert indicator["provenance"]["rule"]["id"] == "c2.http_user_agent_exact"

        # No IPv4 indicator: 0.2.x exported both peers as "c2_communication".
        assert [o for o in imported["observables"] if o["type"].startswith("ipv")] != []
        indicator_patterns = " ".join(i["pattern"] for i in imported["indicators"])
        assert "185.220.101.34" not in indicator_patterns
        assert "192.168.1.50" not in indicator_patterns

        # The finding is explicitly dispositioned and linked to its indicator.
        finding = imported["findings"][0]
        assert finding["export_disposition"] == "indicator"
        assert finding["kind"] == "http_header"
        assert any(r["type"] == "based-on" and r["source_type"] == "indicator"
                   for r in imported["relationships"])

    def test_combined_bundle_keeps_both_subjects(self, dns_plus_http_pcap, tmp_path):
        bundle = self._bundle(dns_plus_http_pcap, tmp_path)
        imported = import_bundle(bundle)
        subjects = sorted(i["subject"] for i in imported["indicators"])
        assert subjects == sorted([DNS_DOMAIN, CS_UA])
        assert validate_bundle(bundle) == []

    def test_syntactically_valid_wrong_indicators_would_fail_the_meaning_check(
            self, http_pcap, tmp_path):
        """Format and meaning are separate: a valid bundle can still be wrong."""
        bundle = self._bundle(http_pcap, tmp_path)
        assert validate_bundle(bundle) == []

        # Rewrite the indicator to name a peer address, as 0.2.x did.
        for obj in bundle["objects"]:
            if obj["type"] == "indicator":
                obj["pattern"] = "[ipv4-addr:value = '185.220.101.34']"
                obj["x_ghostwire_subject"] = "185.220.101.34"
        assert validate_bundle(bundle) == [], "format alone cannot catch this"
        imported = import_bundle(bundle)
        assert imported["indicators"][0]["subject"] != CS_UA
        assert "http-request-ext" not in imported["indicators"][0]["pattern"]


# ─── Version and default alignment ──────────────────────────────────────────

class TestVersionAlignment:
    def test_engine_and_package_versions_match(self):
        from engine import __version__

        pyproject = (ROOT / "pyproject.toml").read_text()
        declared = re.search(r'^version = "([^"]+)"', pyproject, re.MULTILINE)
        assert declared is not None
        assert declared.group(1) == __version__

    def test_server_declares_the_same_version_and_defaults(self):
        index = (ROOT / "server" / "index.ts").read_text()
        from engine import __version__

        assert f"const SERVER_VERSION = '{__version__}'" in index
        # The API and CLI must not disagree about effective defaults.
        assert "DEFAULT_MIN_SCORE = 0.25" in index
        assert "DEFAULT_MIN_PACKETS = 10" in index

    def test_analysis_reports_the_running_version(self, dns_pcap):
        from engine import __version__

        data = run_analysis(dns_pcap).to_output()
        assert data["ghostwire_version"] == __version__
        assert data["run"]["engine_version"] == __version__
        assert data["run"]["versions"]["engine"] == __version__

    def test_advertised_defaults_match_the_entry_point(self, dns_pcap):
        out = run_analysis(dns_pcap).to_output()
        settings = out["run"]["settings"]
        assert settings["min_score"] == 0.25
        assert settings["min_packets"] == 10
        assert settings["max_payload_bytes"] == 16 * 1024
        assert settings["max_sessions"] == 20_000
        assert settings["max_returned_sessions"] == 50


def test_build_bundle_from_analysis_is_pure(monkeypatch):
    """The exporter must not mutate the analysis it is given."""
    analysis = {
        "file": "/tmp/x.pcap",
        "capture_sha256": "abc",
        "run": {"capture": {"sha256": "abc", "frames_read": 1,
                            "first_timestamp": 1.0, "last_timestamp": 1.0},
                "engine_version": "0.3.0"},
        "findings": [], "observations": [],
    }
    before = json.dumps(analysis, sort_keys=True)
    build_bundle_from_analysis(analysis)
    assert json.dumps(analysis, sort_keys=True) == before
